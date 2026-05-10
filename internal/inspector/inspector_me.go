package inspector

// /me — user self-service: profile, own tokens (filtered by kind), own
// subscriptions, and a CSRF-protected form for minting an ephemeral PAT.
// Admins additionally see links to /users and /audit. Anonymous callers
// redirect to /login.

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

// meTokenRow is one row in the /me tokens table.
type meTokenRow struct {
	ID         string
	Name       string
	Scopes     []string
	Kind       string
	Ephemeral  bool
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
}

// meSubRow is one row in the /me subscriptions table.
type meSubRow struct {
	ID                  string
	Source              string
	TargetURL           string
	Name                string
	Cursor              int64
	ConsecutiveFailures int
	LastError           string
	LastSuccessAt       *time.Time
	PausedAt            *time.Time
}

// requireSessionUser resolves the calling user via the session cookie. On
// no-session, GET requests redirect to /login?next=<path> and non-GETs
// return 401 (mirroring requireAdmin's behavior). Returns the user and
// true on success; on failure the response is already written.
func (in *Inspector) requireSessionUser(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	if in.Sessions == nil {
		// Without a session manager wired in, /me cannot
		// authenticate. Redirect anonymous-style.
		in.denyUnauthorized(w, r)
		return store.User{}, false
	}
	user, _, ok := in.Sessions.FromContext(r.Context())
	if !ok {
		in.denyUnauthorized(w, r)
		return store.User{}, false
	}
	return user, true
}

// meIndex renders /me. Optional ?kind=pat|listener narrows the
// tokens table to just one kind; missing/empty leaves it un-filtered.
func (in *Inspector) meIndex(w http.ResponseWriter, r *http.Request) {
	user, ok := in.requireSessionUser(w, r)
	if !ok {
		return
	}
	in.renderMe(w, r, user, "")
}

// renderMe is the shared render path — meCreateToken calls it after a
// successful mint to surface the plaintext exactly once.
func (in *Inspector) renderMe(w http.ResponseWriter, r *http.Request, user store.User, plaintext string) {
	kindFilter := store.TokenKind(r.URL.Query().Get("kind"))
	tokRows, err := in.loadOwnTokens(r, user.ID, kindFilter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	subRows, err := in.loadOwnSubs(r, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	csrfToken := ""
	if c, err := r.Cookie(auth.CSRFCookie); err == nil {
		csrfToken = c.Value
	}
	in.render(w, "me", map[string]any{
		"Title":      "Me",
		"User":       user,
		"IsAdmin":    user.Role == store.RoleAdmin,
		"Tokens":     tokRows,
		"KindFilter": string(kindFilter),
		"Subs":       subRows,
		"Plaintext":  plaintext,
		"CSRFToken":  csrfToken,
	})
}

func (in *Inspector) loadOwnTokens(r *http.Request, userID string, kindFilter store.TokenKind) ([]meTokenRow, error) {
	rows, err := in.Tokens.ListByOwner(r.Context(), userID, false)
	if err != nil {
		return nil, err
	}
	out := make([]meTokenRow, 0, len(rows))
	for _, t := range rows {
		if kindFilter != "" && t.Kind != kindFilter {
			continue
		}
		out = append(out, meTokenRow{
			ID: t.ID, Name: t.Name, Scopes: t.Scopes,
			Kind: string(t.Kind), Ephemeral: t.Ephemeral,
			CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt, ExpiresAt: t.ExpiresAt,
		})
	}
	return out, nil
}

func (in *Inspector) loadOwnSubs(r *http.Request, userID string) ([]meSubRow, error) {
	rows, err := in.Subs.ListByOwner(r.Context(), userID, true)
	if err != nil {
		return nil, err
	}
	out := make([]meSubRow, 0, len(rows))
	for _, s := range rows {
		out = append(out, meSubRow{
			ID: s.ID, Source: s.Source, TargetURL: s.TargetURL, Name: s.Name,
			Cursor:              s.Cursor,
			ConsecutiveFailures: s.ConsecutiveFailures,
			LastError:           truncate(s.LastError, 200),
			LastSuccessAt:       s.LastSuccessAt,
			PausedAt:            s.PausedAt,
		})
	}
	return out, nil
}

// meCreateToken handles the "mint ephemeral PAT" form. Scopes requested
// must be a subset of HeldByUser(caller); the implicit account scope is
// added automatically. CSRF is enforced by the middleware mounted in
// Register; reaching this handler implies the cookie/form-token pair
// matched and Origin checked out.
func (in *Inspector) meCreateToken(w http.ResponseWriter, r *http.Request) {
	user, ok := in.requireSessionUser(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.Form.Get("name"))
	scopes := tokens.ParseScopes(r.Form.Get("scopes"))
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	held := store.HeldByUser(user)
	if !store.Scopes(scopes).SubsetOf(held) {
		http.Error(w, "scopes exceed your authority", http.StatusForbidden)
		return
	}
	// PATs always carry the implicit account scope so /api/me/* works.
	scopes = []string(store.Scopes(scopes).With(store.ScopeAccount))

	res, err := tokens.Generate(name, scopes)
	if err != nil {
		in.Logger.Error("inspector: me token generate failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	owner := user.ID
	tok := store.Token{
		ID:          res.ID,
		Name:        name,
		Scopes:      scopes,
		SecretHash:  res.Hash,
		CreatedAt:   time.Now().UTC(),
		OwnerUserID: &owner,
		Kind:        store.TokenKindPAT,
		Ephemeral:   true,
	}
	if err := in.Tokens.Insert(r.Context(), tok); err != nil {
		in.Logger.Error("inspector: me token insert failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if in.Audit != nil {
		uid := user.ID
		in.Audit.Record(r.Context(), store.AuditEvent{
			ActorUserID: &uid,
			Action:      audit.ActionTokenCreate,
			TargetType:  audit.TargetTypeToken,
			TargetID:    tok.ID,
			Metadata: map[string]any{
				"kind":      string(store.TokenKindPAT),
				"ephemeral": true,
				"scopes":    scopes,
				"via":       "inspector/me",
			},
		})
	}
	in.renderMe(w, r, user, res.Plaintext)
}

// meRevokeToken revokes a token owned by the caller. Cross-user attempts
// return 404 (probe-resistant) without disturbing the row. CSRF is
// enforced by the middleware mounted in Register.
func (in *Inspector) meRevokeToken(w http.ResponseWriter, r *http.Request) {
	user, ok := in.requireSessionUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	tok, err := in.Tokens.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tok.OwnerUserID == nil || *tok.OwnerUserID != user.ID {
		http.NotFound(w, r)
		return
	}
	if err := in.Tokens.Revoke(r.Context(), id, time.Now().UTC()); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if in.Audit != nil {
		uid := user.ID
		in.Audit.Record(r.Context(), store.AuditEvent{
			ActorUserID: &uid,
			Action:      audit.ActionTokenRevoke,
			TargetType:  audit.TargetTypeToken,
			TargetID:    id,
			Metadata:    map[string]any{"via": "inspector/me"},
		})
	}
	http.Redirect(w, r, "/me", http.StatusSeeOther)
}
