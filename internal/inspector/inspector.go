// Package inspector serves the admin web UI mounted at the root of the
// hooks server (/, /me, /tokens, /push, /users, /audit, ...).
//
// All assets (HTML templates and CSS) are embedded so the deployment is one
// statically-linked binary. Authentication is the hooks_session cookie
// issued by /login.
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
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/push"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
	"github.com/onebusaway/hooks/internal/web"
)

//go:embed templates/*.tmpl.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Cascader runs the deactivate-and-cascade transaction. Implemented by
// store.SQLite.DeactivateUserCascade. The same shape is in admin.API.
type Cascader interface {
	DeactivateUserCascade(ctx context.Context, id string, when time.Time) (store.CascadeRevokeResult, error)
}

// Inspector is the http handler set for the inspector web UI.
type Inspector struct {
	Events   store.EventStore
	Tokens   store.TokenStore
	Subs     store.PushSubscriptionStore
	Notifier *pubsub.Notifier
	Push     *push.Manager
	// Sessions enables session-cookie authentication; nil means the
	// inspector refuses every request as anonymous (no other auth path
	// remains).
	Sessions *auth.Manager
	// Audit, when set, receives a token.create / token.revoke entry on
	// every PAT mint or revoke through /me/tokens.
	Audit audit.Recorder
	// Users, when set, lets /tokens, /push, and /audit render an owner /
	// actor column with the user's email instead of a bare id.
	Users store.UserStore
	// AuditReader, when set, powers /audit. Reads audit_events ordered by
	// `at DESC` with optional time-range filters from the query string.
	AuditReader store.AuditStore
	// Invites, Cascader, HashPassword, and ValidatePolicy power the /users
	// admin page; mirror the wiring on invites.API and admin.API. When
	// unset the page degrades to a read-only view (writes return 503).
	Invites        store.InviteStore
	Cascader       Cascader
	HashPassword   func(plaintext string) (string, error)
	ValidatePolicy func(email, plaintext string) error
	Logger         *slog.Logger
	Sources        []string
	tpls           *template.Template
	staticSub      fs.FS
}

// New constructs an Inspector. Templates are parsed at construction. The
// caller MUST set Sessions on the returned value before calling Register
// — without it, every request resolves as anonymous and redirects to
// /login.
func New(
	events store.EventStore,
	ts store.TokenStore,
	subs store.PushSubscriptionStore,
	notifier *pubsub.Notifier,
	pushMgr *push.Manager,
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
		Logger:  logger,
		Sources: configuredSources,
		tpls:    tpls, staticSub: sub,
	}, nil
}

// Register mounts inspector routes onto mux. Each handler is wrapped in
// in.Sessions.Middleware (when set) so requireAdmin can read the session
// from request context.
func (in *Inspector) Register(mux *http.ServeMux) {
	wrap := func(h http.HandlerFunc) http.Handler {
		if in.Sessions == nil {
			return h
		}
		return in.Sessions.Middleware(h)
	}
	// wrapH is the same as wrap but accepts an already-composed Handler
	// (e.g. one already wrapped in CSRF middleware).
	wrapH := func(h http.Handler) http.Handler {
		if in.Sessions == nil {
			return h
		}
		return in.Sessions.Middleware(h)
	}

	mux.Handle("GET /assets/stylesheets/", http.StripPrefix("/assets/stylesheets/", http.FileServer(http.FS(in.staticSub))))
	mux.Handle("GET /logout", wrap(in.logout))
	mux.Handle("GET /{$}", wrap(in.index))
	mux.Handle("GET /events/{source}/{sequence}", wrap(in.detail))
	mux.Handle("POST /events/{source}/{sequence}/replay", wrap(in.replay))
	mux.Handle("GET /tokens", wrap(in.tokensList))
	mux.Handle("POST /tokens/create", wrap(in.tokensCreate))
	mux.Handle("POST /tokens/{id}/revoke", wrap(in.tokensRevoke))
	mux.Handle("GET /push", wrap(in.pushList))
	mux.Handle("POST /push/create", wrap(in.pushCreate))
	mux.Handle("POST /push/{id}/pause", wrap(in.pushPause))
	mux.Handle("POST /push/{id}/resume", wrap(in.pushResume))
	mux.Handle("POST /push/{id}/test", wrap(in.pushTest))
	mux.Handle("POST /push/{id}/rotate", wrap(in.pushRotate))
	mux.Handle("POST /push/{id}/delete", wrap(in.pushDelete))

	// /me is the user self-service page. Mutations run through the shared
	// CSRF middleware so the inspector and /api/me/* enforce the same
	// double-submit + Origin contract.
	csrf := func(h http.Handler) http.Handler {
		return web.Middleware(web.CSRFConfig{}, h)
	}
	mux.Handle("GET /me", wrap(in.meIndex))
	mux.Handle("POST /me/tokens", wrapH(csrf(http.HandlerFunc(in.meCreateToken))))
	mux.Handle("POST /me/tokens/{id}/revoke", wrapH(csrf(http.HandlerFunc(in.meRevokeToken))))

	// /me/push — user-owned push-subscription view mirroring /push without
	// the owner column.
	mux.Handle("GET /me/push", wrap(in.mePushIndex))
	mux.Handle("POST /me/push/{id}/pause", wrapH(csrf(http.HandlerFunc(in.mePushPause))))
	mux.Handle("POST /me/push/{id}/resume", wrapH(csrf(http.HandlerFunc(in.mePushResume))))
	mux.Handle("POST /me/push/{id}/test", wrapH(csrf(http.HandlerFunc(in.mePushTest))))
	mux.Handle("POST /me/push/{id}/rotate", wrapH(csrf(http.HandlerFunc(in.mePushRotate))))
	mux.Handle("POST /me/push/{id}/delete", wrapH(csrf(http.HandlerFunc(in.mePushDelete))))

	// /audit: admin-only HTML view of the audit log.
	mux.Handle("GET /audit", wrap(in.auditList))

	// /users: admin-only user table + invite form + per-row
	// deactivate/reactivate/reset-password/edit. Mutations run through
	// the same CSRF middleware as /me.
	mux.Handle("GET /users", wrap(in.usersList))
	mux.Handle("POST /users/invite", wrapH(csrf(http.HandlerFunc(in.usersInvite))))
	mux.Handle("POST /users/{id}/deactivate", wrapH(csrf(http.HandlerFunc(in.usersDeactivate))))
	mux.Handle("POST /users/{id}/reactivate", wrapH(csrf(http.HandlerFunc(in.usersReactivate))))
	mux.Handle("POST /users/{id}/reset-password", wrapH(csrf(http.HandlerFunc(in.usersResetPassword))))
	mux.Handle("POST /users/{id}/update", wrapH(csrf(http.HandlerFunc(in.usersUpdate))))
}

// requireAdmin enforces admin access via the hooks_session cookie. Admin
// callers proceed; non-admin GETs redirect to /me; non-admin mutations 403.
// Anonymous GETs redirect to /login?next=<path>; anonymous mutations 401.
func (in *Inspector) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if in.Sessions != nil {
		if user, _, ok := in.Sessions.FromContext(r.Context()); ok {
			if user.Role == store.RoleAdmin {
				return true
			}
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/me", http.StatusFound)
				return false
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return false
		}
	}
	in.denyUnauthorized(w, r)
	return false
}

// denyUnauthorized redirects anonymous GETs to /login?next=<path> and
// returns 401 for mutations.
func (in *Inspector) denyUnauthorized(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// logout invalidates the session row and clears the browser cookies, then
// redirects to /login. Idempotent — visiting /logout while already
// anonymous still 302s to /login.
func (in *Inspector) logout(w http.ResponseWriter, r *http.Request) {
	if in.Sessions != nil {
		if c, err := r.Cookie(auth.SessionCookie); err == nil && c.Value != "" {
			if _, delErr := in.Sessions.DeleteSession(r.Context(), c.Value); delErr != nil && !errors.Is(delErr, auth.ErrInvalid) {
				in.Logger.Warn("inspector: logout delete session failed", slog.Any("err", delErr))
			}
		}
		in.Sessions.ClearCookies(w, r)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// index renders the recent-events list.
func (in *Inspector) index(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
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
	if !in.requireAdmin(w, r) {
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
	if !in.requireAdmin(w, r) {
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
	http.Redirect(w, r, fmt.Sprintf("/events/%s/%d", source, seq), http.StatusSeeOther)
}

func (in *Inspector) tokensList(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
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
		"Tokens":    in.decorateTokens(r.Context(), list),
		"Plaintext": "",
	})
}

// tokenRow decorates a store.Token with a human-readable owner label
// resolved via the UserStore (when available). OwnerLabel is "system" for
// rows whose OwnerUserID is nil, the user's email when the lookup
// succeeds, or the raw user id as a last-resort fallback.
type tokenRow struct {
	store.Token
	OwnerLabel string
	KindLabel  string
}

func (in *Inspector) decorateTokens(ctx context.Context, rows []store.Token) []tokenRow {
	cache := map[string]string{}
	out := make([]tokenRow, 0, len(rows))
	for _, t := range rows {
		out = append(out, tokenRow{
			Token:      t,
			OwnerLabel: in.ownerLabel(ctx, t.OwnerUserID, cache),
			KindLabel:  kindLabel(t.Kind),
		})
	}
	return out
}

// ownerLabel resolves a nullable owner_user_id to an email (via UserStore)
// or "system" for NULL. The cache short-circuits repeated lookups within
// a single render — n tokens by the same user becomes one DB call.
func (in *Inspector) ownerLabel(ctx context.Context, ownerUserID *string, cache map[string]string) string {
	if ownerUserID == nil {
		return "system"
	}
	id := *ownerUserID
	if cached, ok := cache[id]; ok {
		return cached
	}
	if in.Users == nil {
		cache[id] = id
		return id
	}
	u, err := in.Users.GetByID(ctx, id)
	if err != nil {
		// Fall back to the raw id rather than failing the whole render.
		// A deactivated user still has a row, so this is genuinely the
		// "user was hard-deleted" path.
		cache[id] = id
		return id
	}
	cache[id] = u.Email
	return u.Email
}

func kindLabel(k store.TokenKind) string {
	if k == "" {
		return string(store.TokenKindListener)
	}
	return string(k)
}

func (in *Inspector) tokensCreate(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
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
	kind := store.TokenKind(strings.TrimSpace(r.Form.Get("kind")))
	switch kind {
	case "", store.TokenKindListener, store.TokenKindPAT:
		// ok; "" is treated as listener below.
	default:
		http.Error(w, "kind must be 'pat' or 'listener'", http.StatusBadRequest)
		return
	}
	if kind == "" {
		kind = store.TokenKindListener
	}
	ownerID := strings.TrimSpace(r.Form.Get("owner_user_id"))
	var ownerPtr *string
	if ownerID != "" {
		// Confirm the user exists before issuing; surfacing 404 here is
		// friendlier than a foreign-key error after generating a token.
		if in.Users == nil {
			http.Error(w, "owner lookup unavailable", http.StatusServiceUnavailable)
			return
		}
		if _, err := in.Users.GetByID(r.Context(), ownerID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				http.Error(w, "owner user not found", http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		owner := ownerID
		ownerPtr = &owner
	}
	gen, err := tokens.Generate(name, scopes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tok := store.Token{
		ID:          gen.ID,
		Name:        name,
		Scopes:      scopes,
		SecretHash:  gen.Hash,
		CreatedAt:   time.Now().UTC(),
		OwnerUserID: ownerPtr,
		Kind:        kind,
	}
	if err := in.Tokens.Insert(r.Context(), tok); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	list, _ := in.Tokens.List(r.Context(), false)
	in.render(w, "tokens", map[string]any{
		"Title":     "Tokens",
		"Tokens":    in.decorateTokens(r.Context(), list),
		"Plaintext": gen.Plaintext,
	})
}

func (in *Inspector) tokensRevoke(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := in.Tokens.Revoke(r.Context(), id, time.Now().UTC()); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (in *Inspector) pushList(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	owner := r.URL.Query().Get("owner")
	subs, err := in.fetchPushSubs(r.Context(), owner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The owner-filter dropdown lists every distinct user owner across
	// the full fleet, not just rows visible under the current filter, so
	// switching from `?owner=system` to a user choice is always possible.
	allSubs := subs
	if owner != "" {
		allSubs, err = in.Subs.List(r.Context(), true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	cache := map[string]string{}
	rendered, err := in.renderSubs(r.Context(), subs, cache)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.render(w, "push", map[string]any{
		"Title":        "Push",
		"Subs":         rendered,
		"OwnerFilter":  owner,
		"OwnerOptions": in.ownerOptions(r.Context(), allSubs, cache),
	})
}

// fetchPushSubs applies the optional ?owner= filter. The contract mirrors
// the JSON list endpoint (internal/push/api.go): "" returns everything,
// "system" returns owner-NULL rows, anything else is treated as a user id.
func (in *Inspector) fetchPushSubs(ctx context.Context, owner string) ([]store.PushSubscription, error) {
	switch owner {
	case "":
		return in.Subs.List(ctx, true)
	case "system":
		return in.Subs.ListSystem(ctx, true)
	default:
		return in.Subs.ListByOwner(ctx, owner, true)
	}
}

// ownerOption is one entry in the /push owner-filter dropdown.
type ownerOption struct {
	Value string // "" / "system" / user_id
	Label string // "all" / "system" / email-or-id
}

func (in *Inspector) ownerOptions(ctx context.Context, subs []store.PushSubscription, cache map[string]string) []ownerOption {
	seen := map[string]bool{}
	out := []ownerOption{
		{Value: "", Label: "all"},
		{Value: "system", Label: "system"},
	}
	for _, s := range subs {
		if s.OwnerUserID == nil || seen[*s.OwnerUserID] {
			continue
		}
		seen[*s.OwnerUserID] = true
		out = append(out, ownerOption{
			Value: *s.OwnerUserID,
			Label: in.ownerLabel(ctx, s.OwnerUserID, cache),
		})
	}
	return out
}

func (in *Inspector) renderSubs(ctx context.Context, subs []store.PushSubscription, cache map[string]string) ([]subRow, error) {
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
			OwnerLabel:          in.ownerLabel(ctx, s.OwnerUserID, cache),
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
	OwnerLabel          string
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (in *Inspector) pushCreate(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
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
	cache := map[string]string{}
	rendered, err := in.renderSubs(r.Context(), subs, cache)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.render(w, "push", map[string]any{
		"Title":        "Push",
		"Subs":         rendered,
		"Plaintext":    plaintext,
		"OwnerOptions": in.ownerOptions(r.Context(), subs, cache),
	})
}

func (in *Inspector) pushPause(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := in.Subs.Pause(r.Context(), id, time.Now().UTC()); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.Push.Pause(id)
	http.Redirect(w, r, "/push", http.StatusSeeOther)
}

func (in *Inspector) pushResume(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := in.Subs.Resume(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = in.Push.Resume(r.Context(), id)
	http.Redirect(w, r, "/push", http.StatusSeeOther)
}

func (in *Inspector) pushTest(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := in.Push.Test(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/push", http.StatusSeeOther)
}

func (in *Inspector) pushRotate(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
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
	cache := map[string]string{}
	rendered, err := in.renderSubs(r.Context(), subs, cache)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.render(w, "push", map[string]any{
		"Title":        "Push",
		"Subs":         rendered,
		"Plaintext":    plaintext,
		"OwnerOptions": in.ownerOptions(r.Context(), subs, cache),
	})
}

func (in *Inspector) pushDelete(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := in.Subs.Delete(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.Push.Remove(id)
	http.Redirect(w, r, "/push", http.StatusSeeOther)
}

func (in *Inspector) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := in.tpls.ExecuteTemplate(w, name, data); err != nil {
		in.Logger.Error("inspector: render", slog.String("name", name), slog.String("error", err.Error()))
	}
}
