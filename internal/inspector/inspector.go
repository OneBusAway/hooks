// Package inspector serves the admin-only web UI at /inspector.
//
// All assets (HTML templates and CSS) are embedded so the deployment is one
// statically-linked binary. Authentication uses a cookie scoped to /inspector
// containing the same plaintext bearer token the API uses; the server-side
// lookup is identical (Argon2id constant-time compare).
package inspector

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/push"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

//go:embed templates/*.tmpl.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

const cookieName = "hooks_inspector_token"

// Inspector is the http handler set for /inspector.
type Inspector struct {
	Events     store.EventStore
	Tokens     store.TokenStore
	Subs       store.PushSubscriptionStore
	Notifier   *pubsub.Notifier
	Push       *push.Manager
	Auth       *tokens.Authenticator
	Logger     *slog.Logger
	Sources    []string
	tpls       *template.Template
	staticSub  fs.FS
}

// New constructs an Inspector. Templates are parsed at construction.
func New(
	events store.EventStore,
	ts store.TokenStore,
	subs store.PushSubscriptionStore,
	notifier *pubsub.Notifier,
	pushMgr *push.Manager,
	auth *tokens.Authenticator,
	configuredSources []string,
	logger *slog.Logger,
) (*Inspector, error) {
	if logger == nil {
		logger = slog.Default()
	}
	tpls, err := template.New("").ParseFS(templatesFS, "templates/*.tmpl.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	return &Inspector{
		Events: events, Tokens: ts, Subs: subs,
		Notifier: notifier, Push: pushMgr,
		Auth: auth, Logger: logger,
		Sources: configuredSources,
		tpls:    tpls, staticSub: sub,
	}, nil
}

// Register mounts inspector routes onto mux.
func (in *Inspector) Register(mux *http.ServeMux) {
	mux.Handle("GET /inspector/static/", http.StripPrefix("/inspector/static/", http.FileServer(http.FS(in.staticSub))))
	mux.HandleFunc("GET /inspector/login", in.loginGET)
	mux.HandleFunc("POST /inspector/login", in.loginPOST)
	mux.HandleFunc("GET /inspector/logout", in.logout)
	mux.HandleFunc("GET /inspector", in.index)
	mux.HandleFunc("GET /inspector/events/{source}/{sequence}", in.detail)
	mux.HandleFunc("POST /inspector/events/{source}/{sequence}/replay", in.replay)
	mux.HandleFunc("GET /inspector/tokens", in.tokensList)
	mux.HandleFunc("POST /inspector/tokens/create", in.tokensCreate)
	mux.HandleFunc("POST /inspector/tokens/{id}/revoke", in.tokensRevoke)
	mux.HandleFunc("GET /inspector/push", in.pushList)
	mux.HandleFunc("POST /inspector/push/create", in.pushCreate)
	mux.HandleFunc("POST /inspector/push/{id}/pause", in.pushPause)
	mux.HandleFunc("POST /inspector/push/{id}/resume", in.pushResume)
	mux.HandleFunc("POST /inspector/push/{id}/test", in.pushTest)
	mux.HandleFunc("POST /inspector/push/{id}/rotate", in.pushRotate)
	mux.HandleFunc("POST /inspector/push/{id}/delete", in.pushDelete)
}

// requireAdmin enforces admin scope via the cookie token.
//
// Outcomes:
//   - missing/invalid cookie → GET redirects to /inspector/login, others 401.
//   - lookup error from a non-auth source (DB unreachable, etc.) → 503 so
//     operators don't mistake an outage for a bad token.
//   - valid token without admin scope → 403 for all methods.
func (in *Inspector) requireAdmin(w http.ResponseWriter, r *http.Request) (store.Token, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		in.denyUnauthorized(w, r)
		return store.Token{}, false
	}
	tok, err := in.Auth.ResolvePlaintext(r.Context(), c.Value)
	if err != nil {
		if tokens.IsAuthError(err) {
			clearCookie(w)
			in.denyUnauthorized(w, r)
			return store.Token{}, false
		}
		in.Logger.Error("inspector: auth lookup failed", slog.String("error", err.Error()))
		http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
		return store.Token{}, false
	}
	if !store.HasScope(tok.Scopes, store.ScopeAdmin) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return store.Token{}, false
	}
	return tok, true
}

func (in *Inspector) denyUnauthorized(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/inspector/login", http.StatusFound)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (in *Inspector) loginGET(w http.ResponseWriter, r *http.Request) {
	in.render(w, "login", map[string]any{"Error": ""})
}

func (in *Inspector) loginPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	plaintext := strings.TrimSpace(r.Form.Get("token"))
	tok, err := in.Auth.ResolvePlaintext(r.Context(), plaintext)
	if err != nil && !tokens.IsAuthError(err) {
		in.Logger.Error("inspector: login lookup failed", slog.String("error", err.Error()))
		http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if err != nil || !store.HasScope(tok.Scopes, store.ScopeAdmin) {
		in.render(w, "login", map[string]any{"Error": "invalid or non-admin token"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    plaintext,
		Path:     "/inspector",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})
	http.Redirect(w, r, "/inspector", http.StatusFound)
}

func (in *Inspector) logout(w http.ResponseWriter, r *http.Request) {
	clearCookie(w)
	http.Redirect(w, r, "/inspector/login", http.StatusFound)
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/inspector", MaxAge: -1})
}

// index renders the recent-events list.
func (in *Inspector) index(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	selected := r.URL.Query().Get("source")
	storedSources, err := in.Events.Sources(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	known := map[string]bool{}
	dropdown := append([]string{}, in.Sources...)
	for _, s := range dropdown {
		known[s] = true
	}
	for _, s := range storedSources {
		if !known[s] {
			dropdown = append(dropdown, s)
			known[s] = true
		}
	}

	scanSources := storedSources
	if selected != "" {
		scanSources = []string{selected}
	}
	const limit = 50
	rows, err := in.recentEvents(r.Context(), scanSources, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	in.render(w, "index", map[string]any{
		"Title":          "Events",
		"Sources":        dropdown,
		"SelectedSource": selected,
		"Events":         rows,
	})
}

type indexRow struct {
	Source     string
	Sequence   int64
	ReceivedAt time.Time
	DeliveryID string
	Preview    string
}

func (in *Inspector) recentEvents(ctx context.Context, sources []string, limit int) ([]indexRow, error) {
	out := []indexRow{}
	for _, source := range sources {
		latest, err := in.Events.LatestSequence(ctx, source)
		if err != nil {
			return nil, err
		}
		from := latest - int64(limit)
		if from < 0 {
			from = 0
		}
		evs, err := in.Events.ReadSince(ctx, source, from, limit)
		if err != nil {
			return nil, err
		}
		// Most recent first.
		for i := len(evs) - 1; i >= 0; i-- {
			ev := evs[i]
			out = append(out, indexRow{
				Source:     ev.Source,
				Sequence:   ev.Sequence,
				ReceivedAt: ev.ReceivedAt,
				DeliveryID: ev.DeliveryID,
				Preview:    preview(ev.Body, 60),
			})
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func preview(body []byte, n int) string {
	s := string(body)
	if len(s) > n {
		s = s[:n] + "…"
	}
	// Replace newlines for table sanity.
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func (in *Inspector) detail(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	source := r.PathValue("source")
	seq, err := strconv.ParseInt(r.PathValue("sequence"), 10, 64)
	if err != nil {
		http.Error(w, "bad sequence", http.StatusBadRequest)
		return
	}
	ev, err := in.Events.Get(r.Context(), source, seq)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pretty, isJSON := tryPretty(ev.Headers, ev.Body)
	in.render(w, "detail", map[string]any{
		"Title":      fmt.Sprintf("%s #%d", ev.Source, ev.Sequence),
		"Event":      ev,
		"IsJSON":     isJSON,
		"PrettyBody": pretty,
		"HexBody":    hexDump(ev.Body),
	})
}

func tryPretty(headers map[string]string, body []byte) (string, bool) {
	ct := strings.ToLower(headerValue(headers, "Content-Type"))
	if !strings.Contains(ct, "json") {
		return "", false
	}
	var out bytes.Buffer
	if err := json.Indent(&out, body, "", "  "); err != nil {
		return "", false
	}
	return out.String(), true
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func hexDump(body []byte) string {
	const max = 256
	if len(body) > max {
		body = body[:max]
	}
	var sb strings.Builder
	for i := 0; i < len(body); i += 16 {
		end := i + 16
		if end > len(body) {
			end = len(body)
		}
		fmt.Fprintf(&sb, "%04x  ", i)
		for j := i; j < end; j++ {
			fmt.Fprintf(&sb, "%02x ", body[j])
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func (in *Inspector) replay(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	source := r.PathValue("source")
	seq, err := strconv.ParseInt(r.PathValue("sequence"), 10, 64)
	if err != nil {
		http.Error(w, "bad sequence", http.StatusBadRequest)
		return
	}
	ev, err := in.Events.Get(r.Context(), source, seq)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Wake SSE subscribers by re-publishing the existing sequence.
	in.Notifier.Publish(source, seq)
	// Push subscribers get a one-shot replay (no cursor advance).
	in.Push.ReplayOne(r.Context(), ev)
	http.Redirect(w, r, fmt.Sprintf("/inspector/events/%s/%d", source, seq), http.StatusSeeOther)
}

func (in *Inspector) tokensList(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	includeRevoked := r.URL.Query().Get("include-revoked") == "1"
	list, err := in.Tokens.List(r.Context(), includeRevoked)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.render(w, "tokens", map[string]any{
		"Title":     "Tokens",
		"Tokens":    list,
		"Plaintext": "",
	})
}

func (in *Inspector) tokensCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.Form.Get("name"))
	scopes := tokens.ParseScopes(r.Form.Get("scopes"))
	if name == "" || len(scopes) == 0 {
		http.Error(w, "name and scopes are required", http.StatusBadRequest)
		return
	}
	res, err := tokens.Issue(r.Context(), in.Tokens, name, scopes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	list, _ := in.Tokens.List(r.Context(), false)
	in.render(w, "tokens", map[string]any{
		"Title":     "Tokens",
		"Tokens":    list,
		"Plaintext": res.Plaintext,
	})
}

func (in *Inspector) tokensRevoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if err := in.Tokens.Revoke(r.Context(), id, time.Now().UTC()); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/inspector/tokens", http.StatusSeeOther)
}

func (in *Inspector) pushList(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	subs, err := in.Subs.List(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rendered, err := in.renderSubs(r.Context(), subs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.render(w, "push", map[string]any{
		"Title": "Push",
		"Subs":  rendered,
	})
}

func (in *Inspector) renderSubs(ctx context.Context, subs []store.PushSubscription) ([]subRow, error) {
	latest := store.NewLatestByCursor(in.Events)
	out := make([]subRow, 0, len(subs))
	for _, s := range subs {
		out = append(out, subRow{
			ID: s.ID, Source: s.Source, TargetURL: s.TargetURL, Name: s.Name,
			Cursor:              s.Cursor,
			QueueDepth:          store.QueueDepth(latest.Get(ctx, s.Source), s.Cursor),
			ConsecutiveFailures: s.ConsecutiveFailures,
			LastError:           truncate(s.LastError, 200),
			LastAttemptAt:       s.LastAttemptAt,
			LastSuccessAt:       s.LastSuccessAt,
			PausedAt:            s.PausedAt,
		})
	}
	return out, latest.Err()
}

type subRow struct {
	ID                  string
	Source              string
	TargetURL           string
	Name                string
	Cursor              int64
	QueueDepth          int64
	ConsecutiveFailures int
	LastError           string
	LastAttemptAt       *time.Time
	LastSuccessAt       *time.Time
	PausedAt            *time.Time
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (in *Inspector) pushCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	source := strings.TrimSpace(r.Form.Get("source"))
	target := strings.TrimSpace(r.Form.Get("target_url"))
	name := strings.TrimSpace(r.Form.Get("name"))

	if u, err := url.Parse(target); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "target_url must be http or https", http.StatusBadRequest)
		return
	}

	plaintext, err := secret.NewRandom()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash, err := tokens.Hash(plaintext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cursor, err := in.Events.LatestSequence(r.Context(), source)
	if err != nil {
		http.Error(w, "cold-start cursor unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sub := store.PushSubscription{
		ID: uuid.NewString(), Source: source, TargetURL: target, Name: name,
		SigningSecretHash: hash,
		Cursor:            cursor,
		CreatedAt:         time.Now().UTC(),
	}
	if err := in.Subs.Insert(r.Context(), sub); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.Push.Add(sub, plaintext)

	subs, err := in.Subs.List(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rendered, err := in.renderSubs(r.Context(), subs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.render(w, "push", map[string]any{
		"Title":     "Push",
		"Subs":      rendered,
		"Plaintext": plaintext,
	})
}

func (in *Inspector) pushPause(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if err := in.Subs.Pause(r.Context(), id, time.Now().UTC()); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.Push.Pause(id)
	http.Redirect(w, r, "/inspector/push", http.StatusSeeOther)
}

func (in *Inspector) pushResume(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if err := in.Subs.Resume(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = in.Push.Resume(r.Context(), id)
	http.Redirect(w, r, "/inspector/push", http.StatusSeeOther)
}

func (in *Inspector) pushTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if err := in.Push.Test(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/inspector/push", http.StatusSeeOther)
}

func (in *Inspector) pushRotate(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	plaintext, err := secret.NewRandom()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash, err := tokens.Hash(plaintext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := in.Subs.RotateSecret(r.Context(), id, hash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.Push.Rotate(id, plaintext)

	subs, err := in.Subs.List(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rendered, err := in.renderSubs(r.Context(), subs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.render(w, "push", map[string]any{
		"Title":     "Push",
		"Subs":      rendered,
		"Plaintext": plaintext,
	})
}

func (in *Inspector) pushDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := in.requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if err := in.Subs.Delete(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.Push.Remove(id)
	http.Redirect(w, r, "/inspector/push", http.StatusSeeOther)
}

func (in *Inspector) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := in.tpls.ExecuteTemplate(w, name, data); err != nil {
		in.Logger.Error("inspector: render", slog.String("name", name), slog.String("error", err.Error()))
	}
}

