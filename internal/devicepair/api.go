package devicepair

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
	"github.com/onebusaway/hooks/internal/users"
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
	mux.HandleFunc("POST /api/auth/device/start", a.start)
	mux.HandleFunc("POST /api/auth/device/poll", a.poll)
	mux.HandleFunc("POST /api/auth/device/approve", a.approve)
	mux.HandleFunc("POST /api/auth/device/deny", a.deny)
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

func (a *API) start(w http.ResponseWriter, r *http.Request) {
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	userCode, err := NewUserCode()
	if err != nil {
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

func (a *API) poll(w http.ResponseWriter, r *http.Request) {
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
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "approved row missing token"})
			return
		}
		tok, err := a.Server.GetToken(r.Context(), *dp.TokenID)
		if err != nil {
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
		// Write succeeded; schedule the deferred mark-fetched. A failure
		// here is logged so the security-sensitive narrow window (where
		// plaintext_token sits in approved_unfetched indefinitely) is
		// observable instead of silent.
		go func(deviceCode string, logger *slog.Logger) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := a.Pairings.MarkFetched(ctx, deviceCode); err != nil && logger != nil {
				logger.WarnContext(ctx, "device-pairing mark-fetched failed",
					slog.String("device_code_prefix", devicePrefix(deviceCode)),
					slog.Any("err", err),
				)
			}
		}(dp.DeviceCode, a.Logger)
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unexpected status"})
}

type approveRequest struct {
	UserCode      string   `json:"user_code"`
	Password      string   `json:"password"`
	GrantedScopes []string `json:"granted_scopes"`
}

func (a *API) approve(w http.ResponseWriter, r *http.Request) {
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
	if req.UserCode == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_code and password required"})
		return
	}

	// Re-verify the password (session alone is insufficient).
	pwOK, err := users.VerifyPassword(secret.String(req.Password), caller.PasswordHash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if !pwOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password verification failed"})
		return
	}

	dp, err := a.Pairings.GetByUserCode(r.Context(), req.UserCode)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_code not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if dp.Status != store.DevicePairingStatusPending {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "pairing not pending"})
		return
	}
	if a.Now().UTC().After(dp.ExpiresAt) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "pairing expired"})
		return
	}

	// granted_scopes ⊆ requested_scopes ∩ caller's held scopes.
	if len(req.GrantedScopes) == 0 {
		req.GrantedScopes = append([]string{}, dp.RequestedScopes...)
	}
	if !subset(req.GrantedScopes, dp.RequestedScopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "granted_scopes exceeds requested_scopes"})
		return
	}
	heldScopes := userHeldScopes(caller)
	if !subset(req.GrantedScopes, heldScopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "granted_scopes exceeds caller's authority"})
		return
	}

	// Mint a kind='pat' token. Plaintext is shown to the CLI exactly once
	// when it polls (and the row is purged on fetch).
	res, err := tokens.Generate("device-pairing", req.GrantedScopes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	tok := store.Token{
		ID: res.ID, Name: "device-pairing", Scopes: req.GrantedScopes,
		SecretHash: res.Hash, CreatedAt: a.Now().UTC(),
		Kind: store.TokenKindPAT,
	}
	if err := a.Server.ApproveDevicePairing(r.Context(), req.UserCode, tok, res.Plaintext, caller.ID, a.Now().UTC()); err != nil {
		// Do NOT echo err.Error() to the client: the underlying error
		// can carry SQL fragments or, worse, parameter values from a
		// future Errorf-wrapping change (which could include the
		// plaintext token). Operators get the detail via Logger.
		a.warn(r.Context(), "device-pairing approve failed",
			slog.String("user_code", req.UserCode),
			slog.String("token_id", tok.ID),
			slog.Any("err", err),
		)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), &caller.ID, audit.ActionDevicePairingApprove, "device_pairing", dp.DeviceCode, map[string]any{
		"granted_scopes": req.GrantedScopes,
		"token_id":       tok.ID,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

type denyRequest struct {
	UserCode string `json:"user_code"`
}

func (a *API) deny(w http.ResponseWriter, r *http.Request) {
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
	if err := a.Pairings.Deny(r.Context(), req.UserCode, caller.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), &caller.ID, audit.ActionDevicePairingDeny, "device_pairing", req.UserCode, nil)
	w.WriteHeader(http.StatusNoContent)
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
			_, _ = a.Pairings.ExpirePending(ctx, now)
			_, _ = a.Pairings.DeleteOld(ctx, now.Add(-24*time.Hour))
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

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

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

// strings.TrimSpace is used by NormalizeUserCode in codes.go.
var _ = strings.TrimSpace
