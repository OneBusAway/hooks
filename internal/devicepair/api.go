package devicepair

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/ratelimit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
	"github.com/onebusaway/hooks/internal/users"
)

// Typed errors returned by ApproveCore and DenyCore. HTTP handlers and
// the server-rendered /device page both translate these into the
// appropriate response (status code or rendered error message). Keeping
// the typed-error vocabulary stable lets the web layer reuse the same
// validation logic that the JSON API exercises.
var (
	// ErrApproveBadInput indicates an empty user_code or password.
	ErrApproveBadInput = errors.New("device-pairing: user_code and password required")
	// ErrApprovePasswordVerify indicates the supplied password did not
	// match the caller's stored hash.
	ErrApprovePasswordVerify = errors.New("device-pairing: password verification failed")
	// ErrApproveUserCodeNotFound indicates no pairing exists for the
	// supplied user_code.
	ErrApproveUserCodeNotFound = errors.New("device-pairing: user_code not found")
	// ErrApprovePairingNotPending indicates the pairing is no longer in
	// 'pending' state (denied, approved, expired, or done).
	ErrApprovePairingNotPending = errors.New("device-pairing: pairing not pending")
	// ErrApprovePairingExpired indicates the pairing has outlived its TTL.
	ErrApprovePairingExpired = errors.New("device-pairing: pairing expired")
	// ErrApproveScopesExceedRequested indicates granted_scopes contains a
	// scope the CLI did not request.
	ErrApproveScopesExceedRequested = errors.New("device-pairing: granted_scopes exceeds requested_scopes")
	// ErrApproveScopesExceedAuthority indicates granted_scopes contains a
	// scope the calling user does not hold.
	ErrApproveScopesExceedAuthority = errors.New("device-pairing: granted_scopes exceeds caller's authority")
	// ErrDenyUserCodeNotFound indicates no pairing exists for the supplied
	// user_code on a deny attempt.
	ErrDenyUserCodeNotFound = errors.New("device-pairing: user_code not found")
)

// PollInterval is the recommended client-side poll cadence (seconds);
// returned to the CLI on /device/start.
const PollInterval = 5

// PairingTTL is how long a pairing row sits in 'pending' before the
// sweeper transitions it to 'expired'.
const PairingTTL = 15 * time.Minute

// AuthProvider is implemented by internal/auth.Manager — extracts the
// (User, Session) attached by session middleware.
type AuthProvider interface {
	FromContext(ctx context.Context) (store.User, store.Session, bool)
}

// API exposes /api/auth/device/{start,poll,approve,deny} and the GET
// /device HTML render is mounted by the inspector.
type API struct {
	Pairings store.DevicePairingStore
	Tokens   store.TokenStore
	Users    store.UserStore
	Audit    audit.Recorder
	Auth     AuthProvider
	Now      func() time.Time

	// Server is the SQLite store; needed for ApproveDevicePairing's tx.
	Server *store.SQLite

	// VerificationURL is the absolute URL of the /device page printed
	// to the CLI.
	VerificationURL string

	// Logger receives WarnContext entries for failure paths (response
	// write errors, deferred MarkFetched failures, internal-error sites).
	// nil-safe: a missing logger silently swallows messages, matching the
	// existing pattern in audit.SQLRecorder. Tests inject a buffer-backed
	// logger to assert observable behavior.
	Logger *slog.Logger

	// OnMarkFetched, when non-nil, is invoked from the deferred goroutine
	// after the post-poll MarkFetched call completes (with whatever error
	// the call returned). Tests use this to synchronize on the
	// approved_unfetched → done transition without sleep-and-pray; in
	// production it is nil and the goroutine returns silently.
	OnMarkFetched func(deviceCode string, err error)
}

// NewAPI constructs an API.
func NewAPI(s *store.SQLite, auth AuthProvider, recorder audit.Recorder, verificationURL string) *API {
	return &API{
		Pairings:        s.DevicePairings(),
		Tokens:          s.Tokens(),
		Users:           s.Users(),
		Audit:           recorder,
		Auth:            auth,
		Now:             time.Now,
		Server:          s,
		VerificationURL: verificationURL,
	}
}

// Register mounts the routes onto mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/device/start", a.Start)
	mux.HandleFunc("POST /api/auth/device/poll", a.Poll)
	mux.HandleFunc("POST /api/auth/device/approve", a.Approve)
	mux.HandleFunc("POST /api/auth/device/deny", a.Deny)
}

type startRequest struct {
	Scopes []string `json:"scopes,omitempty"`
	Admin  bool     `json:"admin,omitempty"`
}

type startResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_uri"`
	Interval        int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}

func (a *API) Start(w http.ResponseWriter, r *http.Request) {
	var req startRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{store.ScopeAccount}
	}
	// admin: true is recorded as a requested scope; the actual admin-vs-
	// user check happens at /approve when the calling user is known.
	if req.Admin {
		hasAdmin := false
		for _, s := range req.Scopes {
			if s == store.ScopeAdmin {
				hasAdmin = true
				break
			}
		}
		if !hasAdmin {
			req.Scopes = append(req.Scopes, store.ScopeAdmin)
		}
	}

	deviceCode, err := NewDeviceCode()
	if err != nil {
		a.warn(r.Context(), "device-pairing start: NewDeviceCode failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	userCode, err := NewUserCode()
	if err != nil {
		a.warn(r.Context(), "device-pairing start: NewUserCode failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	now := a.Now().UTC()
	dp := store.DevicePairing{
		DeviceCode:          deviceCode,
		UserCode:            userCode,
		Status:              store.DevicePairingStatusPending,
		CreatedAt:           now,
		ExpiresAt:           now.Add(PairingTTL),
		RequestingIP:        clientIP(r),
		RequestingUserAgent: r.UserAgent(),
		RequestedScopes:     req.Scopes,
	}
	if err := a.Pairings.Insert(r.Context(), dp); err != nil {
		a.warn(r.Context(), "device-pairing start: insert failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), nil, audit.ActionDevicePairingStart, "device_pairing", deviceCode, map[string]any{
		"user_code": userCode,
		"scopes":    req.Scopes,
	})
	writeJSON(w, http.StatusOK, startResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURL: a.VerificationURL,
		Interval:        PollInterval,
		ExpiresIn:       int(PairingTTL.Seconds()),
	})
}

type pollRequest struct {
	DeviceCode string `json:"device_code"`
}

type pollResponse struct {
	Token   string   `json:"token,omitempty"`
	UserID  string   `json:"user_id,omitempty"`
	Name    string   `json:"name,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
}

func (a *API) Poll(w http.ResponseWriter, r *http.Request) {
	var req pollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	dp, err := a.Pairings.GetByDeviceCode(r.Context(), req.DeviceCode)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		a.warn(r.Context(), "device-pairing poll: lookup failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	switch dp.Status {
	case store.DevicePairingStatusPending:
		// Has the row outlived its TTL? Surface 410 instead of pending so
		// the CLI stops polling.
		if a.Now().UTC().After(dp.ExpiresAt) {
			writeJSON(w, http.StatusGone, map[string]string{"error": "expired"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	case store.DevicePairingStatusDenied:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "denied"})
		return
	case store.DevicePairingStatusExpired, store.DevicePairingStatusDone:
		writeJSON(w, http.StatusGone, map[string]string{"error": "no longer fetchable"})
		return
	case store.DevicePairingStatusApprovedUnfetched:
		if dp.PlaintextToken == nil || dp.TokenID == nil {
			a.warn(r.Context(), "device-pairing poll: approved row missing token",
				slog.String("device_code_prefix", devicePrefix(dp.DeviceCode)))
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "approved row missing token"})
			return
		}
		tok, err := a.Server.GetToken(r.Context(), *dp.TokenID)
		if err != nil {
			a.warn(r.Context(), "device-pairing poll: token lookup failed",
				slog.String("device_code_prefix", devicePrefix(dp.DeviceCode)),
				slog.Any("err", err))
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup"})
			return
		}
		// Encode into a buffer first, write to the wire explicitly, and
		// only schedule the deferred MarkFetched if the write returned no
		// error. design.md is explicit: "do not bind the `done` transition
		// to TCP-write success." If the response write fails partway, the
		// row stays approved_unfetched and the next poll succeeds — the
		// deferred goroutine MUST NOT run, otherwise a client whose TCP
		// read failed mid-response would lose the only chance to fetch
		// the plaintext.
		buf, err := json.Marshal(pollResponse{
			Token:  *dp.PlaintextToken,
			UserID: derefString(dp.UserID),
			Name:   tok.Name,
			Scopes: tok.Scopes,
		})
		if err != nil {
			a.warn(r.Context(), "device-pairing poll: marshal response failed",
				slog.String("device_code_prefix", devicePrefix(dp.DeviceCode)),
				slog.Any("err", err))
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(buf); err != nil {
			a.warn(r.Context(), "device-pairing poll write failed",
				slog.String("device_code_prefix", devicePrefix(dp.DeviceCode)),
				slog.Any("err", err),
			)
			return
		}
		// Write succeeded — kick off the mark-fetched in a fresh goroutine.
		// This runs concurrently with the in-flight HTTP write of the body
		// (Write may still be flushing kernel buffers when this fires); the
		// design only requires that we have observed Write returning nil
		// before scheduling. Failure here is logged so the security-
		// sensitive narrow window (plaintext_token sitting in
		// approved_unfetched indefinitely) is observable, not silent.
		go func(deviceCode string, logger *slog.Logger, hook func(string, error)) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := a.Pairings.MarkFetched(ctx, deviceCode)
			if err != nil && logger != nil {
				logger.WarnContext(ctx, "device-pairing mark-fetched failed",
					slog.String("device_code_prefix", devicePrefix(deviceCode)),
					slog.Any("err", err),
				)
			}
			if hook != nil {
				hook(deviceCode, err)
			}
		}(dp.DeviceCode, a.Logger, a.OnMarkFetched)
		return
	}
	a.warn(r.Context(), "device-pairing poll: unexpected status",
		slog.String("status", string(dp.Status)))
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unexpected status"})
}

type approveRequest struct {
	UserCode      string   `json:"user_code"`
	Password      string   `json:"password"`
	GrantedScopes []string `json:"granted_scopes"`
}

func (a *API) Approve(w http.ResponseWriter, r *http.Request) {
	caller, _, ok := a.Auth.FromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	var req approveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	req.UserCode = NormalizeUserCode(req.UserCode)
	if err := a.ApproveCore(r.Context(), caller, req.UserCode, secret.String(req.Password), req.GrantedScopes); err != nil {
		writeApproveError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

// ApproveCore performs the device-pairing approval logic shared between
// the JSON HTTP handler and the server-rendered /device page. It
// re-verifies the caller's password (session alone is insufficient),
// validates that grantedScopes is a subset of both requested_scopes and
// the caller's held scopes, then mints a kind='pat' token bound to the
// caller. An empty grantedScopes argument means "grant exactly the
// requested set" (the CLI's default UX). Returns one of the typed
// Err* sentinels above on validation failure; an unwrapped non-sentinel
// error indicates an unexpected internal failure (logged at warn level).
func (a *API) ApproveCore(ctx context.Context, caller store.User, userCode string, password secret.String, grantedScopes []string) error {
	if userCode == "" || password.Reveal() == "" {
		return ErrApproveBadInput
	}
	pwOK, err := users.VerifyPassword(password, caller.PasswordHash)
	if err != nil {
		a.warn(ctx, "device-pairing approve: password verify error", slog.Any("err", err))
		return err
	}
	if !pwOK {
		return ErrApprovePasswordVerify
	}

	dp, err := a.Pairings.GetByUserCode(ctx, userCode)
	if errors.Is(err, store.ErrNotFound) {
		return ErrApproveUserCodeNotFound
	}
	if err != nil {
		a.warn(ctx, "device-pairing approve: lookup failed", slog.Any("err", err))
		return err
	}
	if dp.Status != store.DevicePairingStatusPending {
		return ErrApprovePairingNotPending
	}
	if a.Now().UTC().After(dp.ExpiresAt) {
		return ErrApprovePairingExpired
	}

	// granted_scopes ⊆ requested_scopes ∩ caller's held scopes.
	if len(grantedScopes) == 0 {
		grantedScopes = append([]string{}, dp.RequestedScopes...)
	}
	if !subset(grantedScopes, dp.RequestedScopes) {
		return ErrApproveScopesExceedRequested
	}
	heldScopes := userHeldScopes(caller)
	if !subset(grantedScopes, heldScopes) {
		return ErrApproveScopesExceedAuthority
	}

	// Mint a kind='pat' token. Plaintext is shown to the CLI exactly once
	// when it polls (and the row is purged on fetch).
	res, err := tokens.Generate("device-pairing", grantedScopes)
	if err != nil {
		a.warn(ctx, "device-pairing approve: token generate failed", slog.Any("err", err))
		return err
	}
	tok := store.Token{
		ID: res.ID, Name: "device-pairing", Scopes: grantedScopes,
		SecretHash: res.Hash, CreatedAt: a.Now().UTC(),
		Kind: store.TokenKindPAT,
	}
	if err := a.Server.ApproveDevicePairing(ctx, userCode, tok, res.Plaintext, caller.ID, a.Now().UTC()); err != nil {
		// Do NOT echo err.Error() to the client: the underlying error
		// can carry SQL fragments or, worse, parameter values from a
		// future Errorf-wrapping change (which could include the
		// plaintext token). Operators get the detail via Logger.
		a.warn(ctx, "device-pairing approve failed",
			slog.String("user_code", userCode),
			slog.String("token_id", tok.ID),
			slog.Any("err", err),
		)
		return err
	}
	a.recordAudit(ctx, &caller.ID, audit.ActionDevicePairingApprove, "device_pairing", dp.DeviceCode, map[string]any{
		"granted_scopes": grantedScopes,
		"token_id":       tok.ID,
	})
	return nil
}

// writeApproveError translates an ApproveCore error into the HTTP
// response the JSON API contract expects. Unknown errors fall through
// to a generic 500.
func writeApproveError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrApproveBadInput):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_code and password required"})
	case errors.Is(err, ErrApprovePasswordVerify):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password verification failed"})
	case errors.Is(err, ErrApproveUserCodeNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_code not found"})
	case errors.Is(err, ErrApprovePairingNotPending):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "pairing not pending"})
	case errors.Is(err, ErrApprovePairingExpired):
		writeJSON(w, http.StatusGone, map[string]string{"error": "pairing expired"})
	case errors.Is(err, ErrApproveScopesExceedRequested):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "granted_scopes exceeds requested_scopes"})
	case errors.Is(err, ErrApproveScopesExceedAuthority):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "granted_scopes exceeds caller's authority"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
	}
}

type denyRequest struct {
	UserCode string `json:"user_code"`
}

func (a *API) Deny(w http.ResponseWriter, r *http.Request) {
	caller, _, ok := a.Auth.FromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	var req denyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	req.UserCode = NormalizeUserCode(req.UserCode)
	if err := a.DenyCore(r.Context(), caller, req.UserCode); err != nil {
		switch {
		case errors.Is(err, ErrDenyUserCodeNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// LookupPairing returns the device-pairing row for the supplied
// user_code, used by the server-rendered /device page to display the
// requesting client's IP, user-agent, and requested scopes before the
// user types a password. Returns store.ErrNotFound if no row matches.
func (a *API) LookupPairing(ctx context.Context, userCode string) (store.DevicePairing, error) {
	return a.Pairings.GetByUserCode(ctx, userCode)
}

// DenyCore performs the device-pairing deny logic shared between the
// JSON HTTP handler and the server-rendered /device page. It transitions
// the pairing identified by userCode to status='denied' and records an
// audit event. Returns ErrDenyUserCodeNotFound when no row matches; any
// other returned error indicates an unexpected internal failure.
func (a *API) DenyCore(ctx context.Context, caller store.User, userCode string) error {
	if err := a.Pairings.Deny(ctx, userCode, caller.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrDenyUserCodeNotFound
		}
		a.warn(ctx, "device-pairing deny: failed", slog.Any("err", err))
		return err
	}
	a.recordAudit(ctx, &caller.ID, audit.ActionDevicePairingDeny, "device_pairing", userCode, nil)
	return nil
}

// RunSweeper transitions stale pending pairings to expired and deletes
// terminal-state rows older than 24h. Intended to be run as a background
// goroutine alongside the session sweeper.
func (a *API) RunSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := a.Now().UTC()
			if _, err := a.Pairings.ExpirePending(ctx, now); err != nil {
				a.warn(ctx, "device-pairing sweeper: ExpirePending failed", slog.Any("err", err))
			}
			if _, err := a.Pairings.DeleteOld(ctx, now.Add(-24*time.Hour)); err != nil {
				a.warn(ctx, "device-pairing sweeper: DeleteOld failed", slog.Any("err", err))
			}
		}
	}
}

// userHeldScopes returns the scope set the caller may request on a PAT.
// Admins implicitly hold every source scope plus admin; non-admin users
// hold default_scopes plus implicit account.
func userHeldScopes(u store.User) []string {
	if u.Role == store.RoleAdmin {
		return []string{"*"} // sentinel: admin-implicit-everything
	}
	out := append([]string{}, u.DefaultScopes...)
	hasAccount := false
	for _, s := range out {
		if s == store.ScopeAccount {
			hasAccount = true
			break
		}
	}
	if !hasAccount {
		out = append(out, store.ScopeAccount)
	}
	return out
}

// subset reports whether each element of need is present in have. The
// "*" sentinel in have grants everything.
func subset(need, have []string) bool {
	for _, h := range have {
		if h == "*" {
			return true
		}
	}
	hs := map[string]bool{}
	for _, h := range have {
		hs[h] = true
	}
	for _, n := range need {
		if !hs[n] {
			return false
		}
	}
	return true
}

func clientIP(r *http.Request) string { return ratelimit.KeyByIP(r) }

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (a *API) recordAudit(ctx context.Context, actor *string, action, targetType, targetID string, meta map[string]any) {
	if a.Audit == nil {
		return
	}
	a.Audit.Record(ctx, store.AuditEvent{
		ActorUserID: actor,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Metadata:    meta,
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// warn logs at WarnContext if a logger is configured; nil-safe so callers
// don't have to nil-check at every site.
func (a *API) warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	if a.Logger == nil {
		return
	}
	a.Logger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}

// devicePrefix returns the first 8 hex chars of the device_code so log
// lines remain correlatable without persisting the full secret-adjacent
// identifier.
func devicePrefix(code string) string {
	if len(code) <= 8 {
		return code
	}
	return code[:8]
}

