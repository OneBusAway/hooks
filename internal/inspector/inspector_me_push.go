package inspector

// /me/push — user-owned push-subscription view that mirrors /push but
// without the owner column. Anonymous callers redirect to /login.
//
// Mutations (pause / resume / rotate / delete / test) run through the
// shared CSRF middleware mounted in Register and operate strictly on rows
// whose owner_user_id matches the calling user; cross-user attempts
// return 404 (probe-resistant) without disturbing the row.

import (
	"errors"
	"net/http"
	"time"

	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

// requireOwnedSub looks up a push subscription by id and confirms it
// belongs to user. Returns the subscription on success; on any failure
// (not found, foreign owner, store error) the response is already written
// and the caller should return.
func (in *Inspector) requireOwnedSub(w http.ResponseWriter, r *http.Request, user store.User, id string) (store.PushSubscription, bool) {
	sub, err := in.Subs.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return store.PushSubscription{}, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return store.PushSubscription{}, false
	}
	if sub.OwnerUserID == nil || *sub.OwnerUserID != user.ID {
		// Foreign or system-owned: 404 to keep ids un-probeable.
		http.NotFound(w, r)
		return store.PushSubscription{}, false
	}
	return sub, true
}

// mePushIndex renders /me/push for the calling user.
func (in *Inspector) mePushIndex(w http.ResponseWriter, r *http.Request) {
	user, ok := in.requireSessionUser(w, r)
	if !ok {
		return
	}
	in.renderMePush(w, r, user, "")
}

// renderMePush is the shared render path; rotate-secret calls it after a
// successful rotation to surface the new plaintext exactly once.
func (in *Inspector) renderMePush(w http.ResponseWriter, r *http.Request, user store.User, plaintext string) {
	subs, err := in.Subs.ListByOwner(r.Context(), user.ID, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rendered, err := in.renderSubs(r.Context(), subs, map[string]string{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	csrfToken := ""
	if c, err := r.Cookie(auth.CSRFCookie); err == nil {
		csrfToken = c.Value
	}
	in.render(w, "me_push", map[string]any{
		"Title":     "My push",
		"User":      user,
		"IsAdmin":   user.Role == store.RoleAdmin,
		"Subs":      rendered,
		"Plaintext": plaintext,
		"CSRFToken": csrfToken,
	})
}

// mePushPause pauses a subscription owned by the caller.
func (in *Inspector) mePushPause(w http.ResponseWriter, r *http.Request) {
	user, ok := in.requireSessionUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, ok := in.requireOwnedSub(w, r, user, id); !ok {
		return
	}
	if err := in.Subs.Pause(r.Context(), id, time.Now().UTC()); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.Push.Pause(id)
	http.Redirect(w, r, "/me/push", http.StatusSeeOther)
}

// mePushResume resumes a subscription owned by the caller.
func (in *Inspector) mePushResume(w http.ResponseWriter, r *http.Request) {
	user, ok := in.requireSessionUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, ok := in.requireOwnedSub(w, r, user, id); !ok {
		return
	}
	if err := in.Subs.Resume(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = in.Push.Resume(r.Context(), id)
	http.Redirect(w, r, "/me/push", http.StatusSeeOther)
}

// mePushTest sends a synthetic ping event to the subscription's target URL
// without advancing the cursor. Returns 502 on delivery failure so the
// operator sees a real status, not a redirect-to-empty-page.
func (in *Inspector) mePushTest(w http.ResponseWriter, r *http.Request) {
	user, ok := in.requireSessionUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, ok := in.requireOwnedSub(w, r, user, id); !ok {
		return
	}
	if err := in.Push.Test(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/me/push", http.StatusSeeOther)
}

// mePushRotate rotates the signing secret. The new plaintext is rendered
// exactly once on the resulting page (matches /push behavior).
func (in *Inspector) mePushRotate(w http.ResponseWriter, r *http.Request) {
	user, ok := in.requireSessionUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, ok := in.requireOwnedSub(w, r, user, id); !ok {
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
	if err := in.Subs.RotateSecret(r.Context(), id, hash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.Push.Rotate(id, plaintext)
	in.renderMePush(w, r, user, plaintext)
}

// mePushDelete removes a subscription owned by the caller.
func (in *Inspector) mePushDelete(w http.ResponseWriter, r *http.Request) {
	user, ok := in.requireSessionUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, ok := in.requireOwnedSub(w, r, user, id); !ok {
		return
	}
	if err := in.Subs.Delete(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in.Push.Remove(id)
	http.Redirect(w, r, "/me/push", http.StatusSeeOther)
}
