package webpages

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/devicepair"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
)

// DeviceApprover is implemented by *devicepair.API. The webpages package
// only needs the lookup + approve + deny operations the user sees on
// /device; declaring a narrow interface keeps the dependency surface
// inverted (and makes test substitution straightforward).
type DeviceApprover interface {
	ApproveCore(ctx context.Context, caller store.User, userCode string, password secret.String, grantedScopes []string) error
	DenyCore(ctx context.Context, caller store.User, userCode string) error
	LookupPairing(ctx context.Context, userCode string) (store.DevicePairing, error)
}

// DevicePageRoute is the path where the device-pairing approval page is
// mounted; exported so server.Build can use it when attaching the
// session middleware around the page handler.
const DevicePageRoute = "/device"

// MountDevice attaches the DeviceApprover to the Pages handler so the
// /device GET and POST routes can be served. Wiring is separate from
// New() so that webpages tests covering /login and /signup do not need
// to construct a devicepair.API stub.
func (p *Pages) MountDevice(approver DeviceApprover) {
	p.device = approver
}

// DeviceGET renders /device. When the caller is not logged in the page
// redirects to /login?next=/device. When ?user_code= is absent the
// page prompts the user to type their code. When ?user_code= is present
// the page looks up the pairing and renders the approval form (or an
// error if the code is unknown / expired / already-handled).
func (p *Pages) DeviceGET(w http.ResponseWriter, r *http.Request) {
	if p.device == nil {
		http.Error(w, "device pairing not configured", http.StatusNotFound)
		return
	}
	caller, _, ok := p.Auth.FromContext(r.Context())
	if !ok {
		redirectToLogin(w, r)
		return
	}

	csrf := p.deviceCSRFToken(r)
	if csrf == "" {
		// No post-session CSRF cookie present (shouldn't happen if the
		// user just logged in, but guard against operator misconfig).
		http.Error(w, "missing csrf cookie; log in again", http.StatusForbidden)
		return
	}

	userCode := devicepair.NormalizeUserCode(r.URL.Query().Get("user_code"))
	if userCode == "" {
		p.render(w, "device_lookup", map[string]any{
			"CSRFToken": csrf,
			"UserCode":  "",
			"Error":     "",
		})
		return
	}

	dp, err := p.device.LookupPairing(r.Context(), userCode)
	if errors.Is(err, store.ErrNotFound) {
		p.render(w, "device_lookup", map[string]any{
			"CSRFToken": csrf,
			"UserCode":  userCode,
			"Error":     "Code not found.",
		})
		return
	}
	if err != nil {
		p.warn(r.Context(), "webpages: device lookup failed", slog.Any("err", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if dp.Status != store.DevicePairingStatusPending {
		p.render(w, "device_lookup", map[string]any{
			"CSRFToken": csrf,
			"UserCode":  userCode,
			"Error":     "This pairing is no longer pending.",
		})
		return
	}

	p.render(w, "device_approve", deviceApproveData(csrf, userCode, dp, "", caller))
}

// DevicePOST dispatches to either approve or deny based on the
// `action` form field. Both branches require a valid CSRF token (the
// page-rendered form embeds the post-session hooks_csrf cookie value).
// Approval requires the user's password to be re-entered.
func (p *Pages) DevicePOST(w http.ResponseWriter, r *http.Request) {
	if p.device == nil {
		http.Error(w, "device pairing not configured", http.StatusNotFound)
		return
	}
	caller, _, ok := p.Auth.FromContext(r.Context())
	if !ok {
		redirectToLogin(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !p.checkSessionCSRF(r) {
		http.Error(w, "csrf token mismatch", http.StatusForbidden)
		return
	}

	userCode := devicepair.NormalizeUserCode(r.Form.Get("user_code"))
	switch r.Form.Get("action") {
	case "deny":
		p.deviceDeny(w, r, caller, userCode)
	case "approve", "":
		p.deviceApprove(w, r, caller, userCode)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

func (p *Pages) deviceApprove(w http.ResponseWriter, r *http.Request, caller store.User, userCode string) {
	password := r.Form.Get("password")
	grantedScopes := r.Form["granted_scopes"]
	csrf := p.deviceCSRFToken(r)

	rerender := func(msg string) {
		dp, lookupErr := p.device.LookupPairing(r.Context(), userCode)
		if errors.Is(lookupErr, store.ErrNotFound) {
			p.render(w, "device_lookup", map[string]any{
				"CSRFToken": csrf, "UserCode": userCode, "Error": msg,
			})
			return
		}
		if lookupErr != nil {
			p.warn(r.Context(), "webpages: device approve rerender lookup failed", slog.Any("err", lookupErr))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		p.render(w, "device_approve", deviceApproveData(csrf, userCode, dp, msg, caller))
	}

	err := p.device.ApproveCore(r.Context(), caller, userCode, secret.String(password), grantedScopes)
	switch {
	case err == nil:
		p.render(w, "device_done", map[string]any{
			"Action":   "approved",
			"UserCode": userCode,
		})
	case errors.Is(err, devicepair.ErrApproveBadInput):
		rerender("User code and password are required.")
	case errors.Is(err, devicepair.ErrApprovePasswordVerify):
		rerender("Password verification failed.")
	case errors.Is(err, devicepair.ErrApproveUserCodeNotFound):
		p.render(w, "device_lookup", map[string]any{
			"CSRFToken": csrf, "UserCode": userCode, "Error": "Code not found.",
		})
	case errors.Is(err, devicepair.ErrApprovePairingNotPending):
		p.render(w, "device_lookup", map[string]any{
			"CSRFToken": csrf, "UserCode": userCode, "Error": "This pairing is no longer pending.",
		})
	case errors.Is(err, devicepair.ErrApprovePairingExpired):
		p.render(w, "device_lookup", map[string]any{
			"CSRFToken": csrf, "UserCode": userCode, "Error": "This pairing has expired. Ask the CLI to start a new one.",
		})
	case errors.Is(err, devicepair.ErrApproveScopesExceedRequested):
		rerender("You cannot grant more than the CLI requested.")
	case errors.Is(err, devicepair.ErrApproveScopesExceedAuthority):
		rerender("You do not hold all of the requested scopes.")
	default:
		p.warn(r.Context(), "webpages: device approve failed", slog.Any("err", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (p *Pages) deviceDeny(w http.ResponseWriter, r *http.Request, caller store.User, userCode string) {
	err := p.device.DenyCore(r.Context(), caller, userCode)
	switch {
	case err == nil:
		p.render(w, "device_done", map[string]any{
			"Action":   "denied",
			"UserCode": userCode,
		})
	case errors.Is(err, devicepair.ErrDenyUserCodeNotFound):
		csrf := p.deviceCSRFToken(r)
		p.render(w, "device_lookup", map[string]any{
			"CSRFToken": csrf, "UserCode": userCode, "Error": "Code not found.",
		})
	default:
		p.warn(r.Context(), "webpages: device deny failed", slog.Any("err", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// deviceCSRFToken returns the post-session CSRF token. The caller is
// expected to be logged in; the cookie is set by auth.Manager.SetCookies
// at login time. If the cookie is missing, the empty string is returned
// and DeviceGET surfaces a 403 so the user re-logs in (and the CSRF
// middleware on POST would refuse anyway).
func (p *Pages) deviceCSRFToken(r *http.Request) string {
	c, err := r.Cookie(auth.CSRFCookie)
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

// checkSessionCSRF is the post-session double-submit check used by the
// /device form. It mirrors the same compare web.Middleware performs for
// API mutations; we duplicate the inline check here because the form
// posts to /device (a webpages route) rather than /api/auth/device/*.
func (p *Pages) checkSessionCSRF(r *http.Request) bool {
	cookie := p.deviceCSRFToken(r)
	tok := r.Form.Get("csrf_token")
	if cookie == "" || tok == "" {
		return false
	}
	return secret.EqualString(tok, cookie)
}

// deviceApproveData builds the template data for the approval form.
// `caller` is the authenticated user; their email is shown for context
// but no other PII leaks.
func deviceApproveData(csrf, userCode string, dp store.DevicePairing, errMsg string, caller store.User) map[string]any {
	return map[string]any{
		"CSRFToken":           csrf,
		"UserCode":            userCode,
		"RequestingIP":        dp.RequestingIP,
		"RequestingUserAgent": dp.RequestingUserAgent,
		"RequestedScopes":     dp.RequestedScopes,
		"CallerEmail":         caller.Email,
		"Error":               errMsg,
	}
}

// redirectToLogin redirects to /login?next=<current path+query> so the
// post-login flow returns the user to /device (with the same query
// string they arrived with, which preserves a pasted ?user_code=).
func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Path
	if r.URL.RawQuery != "" {
		next += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
}
