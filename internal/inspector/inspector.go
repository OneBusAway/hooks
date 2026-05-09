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

const cookieName = "hooks_inspector_token"

// Cascader runs the deactivate-and-cascade transaction. Implemented by
// store.SQLite.DeactivateUserCascade. The same shape is in admin.API.
type Cascader interface {
	DeactivateUserCascade(ctx context.Context, id string, when time.Time) (store.CascadeRevokeResult, error)
}

// Inspector is the http handler set for /inspector.
type Inspector struct {
	Events   store.EventStore
	Tokens   store.TokenStore
	Subs     store.PushSubscriptionStore
	Notifier *pubsub.Notifier
	Push     *push.Manager
	Auth     *tokens.Authenticator
	// Sessions, when non-nil, enables session-cookie authentication on the
	// inspector router (task 11.12). The middleware runs before each
	// handler so requireAdmin can read (*User, *Session) from context. A
	// nil Sessions falls back to the legacy hooks_inspector_token bearer
	// cookie path only.
	Sessions *auth.Manager
	// Audit, when set, receives a token.create / token.revoke entry every
	// time /inspector/me/tokens (task 11.4) issues or revokes a PAT. The
	// session-attached User on each request comes from auth.Manager's
	// per-request lookup, so a separate UserStore reference would be a
	// stale read; omit it here.
	Audit audit.Recorder
	// Users, when set, lets /inspector/tokens, /inspector/push, and
	// /inspector/audit render an "owner" / "actor" column with the user's
	// email instead of a bare id (tasks 11.8, 11.9, 11.6). When nil, those
	// views fall back to printing the raw user id (or "system" for NULL).
	Users store.UserStore
	// AuditReader, when set, powers /inspector/audit (task 11.6). Reads
	// audit_events ordered by `at DESC` with optional time-range filters
	// pulled from the request query string.
	AuditReader store.AuditStore
	// Invites, Cascader, HashPassword, and ValidatePolicy power the
	// /inspector/users admin page (task 11.5). They mirror the wiring on
	// invites.API and admin.API so the inspector and JSON surfaces share
	// the same business logic. When unset the admin page degrades to a
	// read-only view (writes return 503).
	Invites        store.InviteStore
	Cascader       Cascader
	HashPassword   func(plaintext string) (string, error)
	ValidatePolicy func(email, plaintext string) error
	Logger         *slog.Logger
	Sources     []string
	tpls        *template.Template
	staticSub   fs.FS
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

// Register mounts inspector routes onto mux. If in.Sessions is non-nil
// (task 11.12), each handler is wrapped in the session middleware so the
// inspector can authenticate via the hooks_session cookie alongside the
// legacy hooks_inspector_token bearer cookie.
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

	mux.Handle("GET /inspector/static/", http.StripPrefix("/inspector/static/", http.FileServer(http.FS(in.staticSub))))
	mux.Handle("GET /inspector/login", wrap(in.loginGET))
	mux.Handle("POST /inspector/login", wrap(in.loginPOST))
	mux.Handle("GET /inspector/logout", wrap(in.logout))
	mux.Handle("GET /inspector", wrap(in.index))
	mux.Handle("GET /inspector/events/{source}/{sequence}", wrap(in.detail))
	mux.Handle("POST /inspector/events/{source}/{sequence}/replay", wrap(in.replay))
	mux.Handle("GET /inspector/tokens", wrap(in.tokensList))
	mux.Handle("POST /inspector/tokens/create", wrap(in.tokensCreate))
	mux.Handle("POST /inspector/tokens/{id}/revoke", wrap(in.tokensRevoke))
	mux.Handle("GET /inspector/push", wrap(in.pushList))
	mux.Handle("POST /inspector/push/create", wrap(in.pushCreate))
	mux.Handle("POST /inspector/push/{id}/pause", wrap(in.pushPause))
	mux.Handle("POST /inspector/push/{id}/resume", wrap(in.pushResume))
	mux.Handle("POST /inspector/push/{id}/test", wrap(in.pushTest))
	mux.Handle("POST /inspector/push/{id}/rotate", wrap(in.pushRotate))
	mux.Handle("POST /inspector/push/{id}/delete", wrap(in.pushDelete))

	// /inspector/me is the user self-service page (task 11.4). It is
	// session-only (the legacy raw-bearer cookie path is admin-scoped and
	// does not surface a "current user"). Mutations run through the
	// shared CSRF middleware so the inspector and /api/me/* enforce the
	// same double-submit + Origin contract.
	csrf := func(h http.Handler) http.Handler {
		return web.Middleware(web.CSRFConfig{}, h)
	}
	mux.Handle("GET /inspector/me", wrap(in.meIndex))
	mux.Handle("POST /inspector/me/tokens", wrapH(csrf(http.HandlerFunc(in.meCreateToken))))
	mux.Handle("POST /inspector/me/tokens/{id}/revoke", wrapH(csrf(http.HandlerFunc(in.meRevokeToken))))

	// /inspector/me/push (task 11.7) — user-owned push-subscription view
	// mirroring /inspector/push without the owner column. Mutations share
	// the CSRF middleware so the same double-submit + Origin contract
	// applies as elsewhere on /inspector/me.
	mux.Handle("GET /inspector/me/push", wrap(in.mePushIndex))
	mux.Handle("POST /inspector/me/push/{id}/pause", wrapH(csrf(http.HandlerFunc(in.mePushPause))))
	mux.Handle("POST /inspector/me/push/{id}/resume", wrapH(csrf(http.HandlerFunc(in.mePushResume))))
	mux.Handle("POST /inspector/me/push/{id}/test", wrapH(csrf(http.HandlerFunc(in.mePushTest))))
	mux.Handle("POST /inspector/me/push/{id}/rotate", wrapH(csrf(http.HandlerFunc(in.mePushRotate))))
	mux.Handle("POST /inspector/me/push/{id}/delete", wrapH(csrf(http.HandlerFunc(in.mePushDelete))))

	// /inspector/audit (task 11.6): admin-only HTML view of the audit log.
	mux.Handle("GET /inspector/audit", wrap(in.auditList))

	// /inspector/users (task 11.5): admin-only user table + invite form
	// + per-row deactivate/reactivate/reset-password/edit. Mutations run
	// through the same CSRF middleware as /inspector/me.
	mux.Handle("GET /inspector/users", wrap(in.usersList))
	mux.Handle("POST /inspector/users/invite", wrapH(csrf(http.HandlerFunc(in.usersInvite))))
	mux.Handle("POST /inspector/users/{id}/deactivate", wrapH(csrf(http.HandlerFunc(in.usersDeactivate))))
	mux.Handle("POST /inspector/users/{id}/reactivate", wrapH(csrf(http.HandlerFunc(in.usersReactivate))))
	mux.Handle("POST /inspector/users/{id}/reset-password", wrapH(csrf(http.HandlerFunc(in.usersResetPassword))))
	mux.Handle("POST /inspector/users/{id}/update", wrapH(csrf(http.HandlerFunc(in.usersUpdate))))
}

// requireAdmin enforces admin access for an inspector request.
//
// Authentication sources, in order:
//  1. hooks_session cookie (task 11.12): if present and the user is admin,
//     allow. If the user is non-admin, GET redirects to /inspector/me;
//     non-GET returns 403.
//  2. legacy hooks_inspector_token cookie (task 11.11): plaintext bearer
//     token in a cookie; admin scope required.
//
// Outcomes when no auth is present:
//   - GET → 302 to /login?next=<path> (task 11.10).
//   - non-GET → 401.
//
// Lookup failures from a non-auth source (DB unreachable, etc.) → 503 so
// operators don't mistake an outage for a bad token.
func (in *Inspector) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	// 1. Session cookie path.
	if in.Sessions != nil {
		if user, _, ok := in.Sessions.FromContext(r.Context()); ok {
			if user.Role == store.RoleAdmin {
				return true
			}
			// Logged in as non-admin: GET redirects to /inspector/me;
			// mutations 403.
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/inspector/me", http.StatusFound)
				return false
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return false
		}
	}
	// 2. Legacy bearer cookie path.
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		in.denyUnauthorized(w, r)
		return false
	}
	tok, err := in.Auth.ResolvePlaintext(r.Context(), c.Value)
	if err != nil {
		if tokens.IsAuthError(err) {
			clearCookie(w)
			in.denyUnauthorized(w, r)
			return false
		}
		in.Logger.Error("inspector: auth lookup failed", slog.String("error", err.Error()))
		http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
		return false
	}
	if !store.HasScope(tok.Scopes, store.ScopeAdmin) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// denyUnauthorized handles the no-auth-at-all case. GETs redirect to the
// new /login page with a ?next= so the user lands back on the inspector
// after logging in (task 11.10). Mutations get a flat 401.
func (in *Inspector) denyUnauthorized(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (in *Inspector) loginGET(w http.ResponseWriter, r *http.Request) {
	in.render(w, "login", map[string]any{"Error": ""})
}

// loginPOST is the legacy v1 inspector login form. It still issues the
// raw-bearer cookie for backwards compatibility with operators who haven't
// yet migrated to /login (the session-based flow). The Deprecation
// response header (RFC 8594) marks this path as slated for v2 removal;
// the cookie format itself continues to authenticate every request,
// including mutations, until then (task 11.11).
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
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Link", `</login>; rel="successor-version"`)
	in.Logger.Warn("inspector: legacy /inspector/login used; migrate to /login (deprecated for v2)",
		slog.String("token_id", tok.ID))
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
	http.Redirect(w, r, fmt.Sprintf("/inspector/events/%s/%d", source, seq), http.StatusSeeOther)
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
	http.Redirect(w, r, "/inspector/tokens", http.StatusSeeOther)
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

// ownerOption is one entry in the /inspector/push owner-filter dropdown.
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
	http.Redirect(w, r, "/inspector/push", http.StatusSeeOther)
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
	http.Redirect(w, r, "/inspector/push", http.StatusSeeOther)
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
	http.Redirect(w, r, "/inspector/push", http.StatusSeeOther)
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
	http.Redirect(w, r, "/inspector/push", http.StatusSeeOther)
}

func (in *Inspector) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := in.tpls.ExecuteTemplate(w, name, data); err != nil {
		in.Logger.Error("inspector: render", slog.String("name", name), slog.String("error", err.Error()))
	}
}
