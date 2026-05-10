package inspector

// /users: admin-only user table, "Issue invite"
// form, per-row deactivate (with email confirmation field; refuses
// last-admin), reactivate, reset-password, and edit-default-scopes.
// Every mutation is CSRF-protected by the same web.Middleware that
// guards /me/*.
//
// The page intentionally re-uses the existing /api/users/* business
// logic rather than reaching into store directly: it calls the same
// store interfaces (UserStore, InviteStore, Cascader) so behaviour
// stays consistent with the JSON surface.

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/invites"
	"github.com/onebusaway/hooks/internal/store"
)

// userRow is one row in the /users table.
type userRow struct {
	ID            string
	Email         string
	Name          string
	Role          string
	DefaultScopes []string
	CreatedAt     time.Time
	DeactivatedAt *time.Time
}

// inviteBanner carries the invite-creation result back to the rendered
// page so the signup URL is visible exactly once.
type inviteBanner struct {
	Code      string
	SignupURL string
	Role      string
	ExpiresAt *time.Time
}

func (in *Inspector) usersList(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	in.renderUsers(w, r, inviteBanner{})
}

// renderUsers is the shared render path. banner carries the just-issued
// invite, if any.
func (in *Inspector) renderUsers(w http.ResponseWriter, r *http.Request, banner inviteBanner) {
	rows, err := in.Users.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]userRow, 0, len(rows))
	for _, u := range rows {
		out = append(out, userRow{
			ID: u.ID, Email: u.Email, Name: u.Name, Role: string(u.Role),
			DefaultScopes: u.DefaultScopes,
			CreatedAt:     u.CreatedAt, DeactivatedAt: u.DeactivatedAt,
		})
	}
	csrfToken := ""
	if c, err := r.Cookie(auth.CSRFCookie); err == nil {
		csrfToken = c.Value
	}
	in.render(w, "users", map[string]any{
		"Title":     "Users",
		"Users":     out,
		"Banner":    banner,
		"CSRFToken": csrfToken,
	})
}

// usersInvite handles the "Issue invite" form. Admin-only; CSRF and
// Origin checks come from the surrounding middleware.
func (in *Inspector) usersInvite(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	if in.Invites == nil {
		http.Error(w, "invites store not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	role := store.Role(strings.TrimSpace(r.Form.Get("role")))
	if role != store.RoleAdmin && role != store.RoleUser {
		http.Error(w, "role must be admin or user", http.StatusBadRequest)
		return
	}
	scopes := parseScopesField(r.Form.Get("scopes"))
	code, err := invites.NewCode()
	if err != nil {
		in.Logger.Error("inspector: invite code generation failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	exp := now.Add(invites.DefaultInviteTTL)
	caller, _, _ := in.Sessions.FromContext(r.Context())
	createdBy := caller.ID
	inv := store.Invite{
		Code:            code,
		Role:            role,
		DefaultScopes:   scopes,
		CreatedByUserID: &createdBy,
		Bootstrap:       false,
		CreatedAt:       now,
		ExpiresAt:       &exp,
	}
	if err := in.Invites.Insert(r.Context(), inv); err != nil {
		in.Logger.Error("inspector: invite insert failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	in.recordUsersAudit(r, audit.ActionInviteCreate, audit.TargetTypeInvite, code, map[string]any{
		"role": string(role),
	})
	banner := inviteBanner{
		Code:      code,
		SignupURL: signupURL(r, code),
		Role:      string(role),
		ExpiresAt: &exp,
	}
	in.renderUsers(w, r, banner)
}

// recordUsersAudit emits an audit event for a /users mutation, attributed
// to the caller and tagged via=inspector/users so audit consumers can tell
// inspector clicks from JSON API calls.
func (in *Inspector) recordUsersAudit(r *http.Request, action audit.Action, targetType audit.TargetType, targetID string, extra map[string]any) {
	if in.Audit == nil {
		return
	}
	caller, _, _ := in.Sessions.FromContext(r.Context())
	actor := caller.ID
	meta := make(map[string]any, len(extra)+1)
	for k, v := range extra {
		meta[k] = v
	}
	meta["via"] = "inspector/users"
	in.Audit.Record(r.Context(), store.AuditEvent{
		ActorUserID: &actor,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Metadata:    meta,
	})
}

// signupURL builds an absolute /signup?code=… URL using the request's
// Origin/host so the operator can copy-paste it. We don't have access to
// HOOKS_PUBLIC_URL in this layer, but the inspector is itself only
// reachable through whichever hostname the operator is browsing.
func signupURL(r *http.Request, code string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if x := r.Header.Get("X-Forwarded-Proto"); x != "" {
		scheme = x
	}
	host := r.Host
	if x := r.Header.Get("X-Forwarded-Host"); x != "" {
		host = x
	}
	u := url.URL{Scheme: scheme, Host: host, Path: "/signup", RawQuery: "code=" + url.QueryEscape(code)}
	return u.String()
}

// usersDeactivate POSTs through the cascading-revoke transaction. Rejects
// last-admin (409) and confirm mismatch (400) up front.
func (in *Inspector) usersDeactivate(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	if in.Cascader == nil {
		http.Error(w, "cascader not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	target, err := in.Users.GetByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	confirm := strings.TrimSpace(r.Form.Get("confirm"))
	if !strings.EqualFold(confirm, target.Email) {
		http.Error(w, "confirm must equal the target user's email", http.StatusBadRequest)
		return
	}
	res, err := in.Cascader.DeactivateUserCascade(r.Context(), id, time.Now().UTC())
	if errors.Is(err, store.ErrLastAdmin) {
		http.Error(w, "would leave zero active admins", http.StatusConflict)
		return
	}
	if errors.Is(err, store.ErrAlreadyDeactivated) {
		http.Error(w, "already deactivated", http.StatusConflict)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		in.Logger.Error("inspector: deactivate cascade failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	in.recordUsersAudit(r, audit.ActionUserDeactivate, audit.TargetTypeUser, id, map[string]any{
		"tokens_revoked":       res.TokensRevoked,
		"subscriptions_paused": res.SubscriptionsPaused,
	})
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// usersReactivate clears deactivated_at on the target user. Tokens and
// subscriptions are NOT restored (matches the API behaviour from §9.5).
func (in *Inspector) usersReactivate(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := in.Users.Reactivate(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		in.Logger.Error("inspector: reactivate failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	in.recordUsersAudit(r, audit.ActionUserReactivate, audit.TargetTypeUser, id, nil)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// usersResetPassword sets a new password hash for the target user and
// invalidates all live sessions. Policy violations return 400.
func (in *Inspector) usersResetPassword(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	if in.HashPassword == nil || in.ValidatePolicy == nil {
		http.Error(w, "password hasher not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	target, err := in.Users.GetByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	plain := r.Form.Get("new_password")
	if plain == "" {
		http.Error(w, "new_password required", http.StatusBadRequest)
		return
	}
	if err := in.ValidatePolicy(target.Email, plain); err != nil {
		http.Error(w, "password does not meet policy", http.StatusBadRequest)
		return
	}
	hash, err := in.HashPassword(plain)
	if err != nil {
		in.Logger.Error("inspector: reset-password hash failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if err := in.Users.SetPasswordHash(r.Context(), id, hash); err != nil {
		in.Logger.Error("inspector: reset-password set hash failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if in.Sessions != nil {
		// Match admin.API.ResetPassword: invalidate live sessions for the
		// target. Failure here is security-relevant — the hash was rotated
		// but live cookies still authorize. Surface as 500 so the operator
		// retries.
		if err := in.Sessions.DeleteSessionsByUser(r.Context(), id); err != nil {
			in.Logger.Error("inspector: reset-password session-delete failed",
				slog.String("error", err.Error()), slog.String("user_id", id))
			http.Error(w, "password updated but session invalidation failed; retry to invalidate live sessions",
				http.StatusInternalServerError)
			return
		}
	}
	in.recordUsersAudit(r, audit.ActionUserPasswordReset, audit.TargetTypeUser, id, nil)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// usersUpdate edits the target's name and/or default_scopes. The form
// fields are optional; missing fields leave the prior value alone.
func (in *Inspector) usersUpdate(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	target, err := in.Users.GetByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := target.Name
	if r.Form.Has("name") {
		nm := strings.TrimSpace(r.Form.Get("name"))
		if nm == "" {
			http.Error(w, "name must be non-empty", http.StatusBadRequest)
			return
		}
		name = nm
	}
	scopes := target.DefaultScopes
	if r.Form.Has("default_scopes") {
		scopes = parseScopesField(r.Form.Get("default_scopes"))
	}
	if err := in.Users.UpdateProfile(r.Context(), id, name, scopes); err != nil {
		in.Logger.Error("inspector: update profile failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	in.recordUsersAudit(r, audit.ActionUserUpdate, audit.TargetTypeUser, id, map[string]any{
		"name":           name,
		"default_scopes": scopes,
	})
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// parseScopesField splits "render,stripe ,  foo" into ["render","stripe","foo"].
// Empty input yields a nil slice, which the user store stores as `[]`.
func parseScopesField(in string) []string {
	parts := strings.Split(in, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
