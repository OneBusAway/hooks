// Package server wires the storage layer, ingestion handler, SSE handler,
// push manager, pruner, inspector, and HTTP routes together. It is consumed
// by cmd/hooks for both the long-running server and `hooks --dev` mode.
package server

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/onebusaway/hooks/internal/admin"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/config"
	"github.com/onebusaway/hooks/internal/devicepair"
	"github.com/onebusaway/hooks/internal/ingest"
	"github.com/onebusaway/hooks/internal/inspector"
	"github.com/onebusaway/hooks/internal/invites"
	"github.com/onebusaway/hooks/internal/me"
	"github.com/onebusaway/hooks/internal/prune"
	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/push"
	"github.com/onebusaway/hooks/internal/ratelimit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/sources"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/subscribe"
	"github.com/onebusaway/hooks/internal/tokens"
	pkgUsers "github.com/onebusaway/hooks/internal/users"
	"github.com/onebusaway/hooks/internal/web"
	"github.com/onebusaway/hooks/internal/webpages"
)

// Server bundles all the runtime components.
type Server struct {
	Cfg      *config.Config
	Store    *store.SQLite
	Notifier *pubsub.Notifier
	Push     *push.Manager
	Prune    *prune.Pruner
	Mux      *http.ServeMux
	Logger   *slog.Logger
	Listener string

	AuthManager *auth.Manager
	DevicePair  *devicepair.API

	httpServer *http.Server
	stopOnce   sync.Once
	stopped    chan struct{}
}

// Build constructs a fully wired Server. Caller is responsible for calling
// Run() and Stop().
func Build(cfg *config.Config, registry *sources.Registry, logger *slog.Logger) (*Server, error) {
	st, err := store.OpenSQLite(cfg.DatabaseURL, store.SQLiteOptions{
		DedupeWindow: cfg.DedupeWindow,
	})
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	tokens.AttachVerifier(st)
	st.SetLogger(logger)

	notifier := pubsub.New()

	// Build verifiers for every configured source.
	bindings := map[string]ingest.SourceBinding{}
	configuredSources := make([]string, 0, len(cfg.Sources))
	configuredSourceSet := map[string]bool{}
	retentions := map[string]time.Duration{}
	for name, src := range cfg.Sources {
		v, ok := registry.Build(src.Verifier, src.Secret.Reveal(), sources.Options{
			SkewWindow: src.SkewWindow,
		})
		if !ok {
			_ = st.Close()
			return nil, fmt.Errorf("verifier %q not registered", src.Verifier)
		}
		bindings[name] = ingest.SourceBinding{
			Name:          name,
			Verifier:      v,
			BodySizeLimit: src.BodySizeLimit,
		}
		configuredSources = append(configuredSources, name)
		configuredSourceSet[name] = true
		retentions[name] = src.Retention
	}

	bearerAuth := tokens.New(st.Tokens())
	pmgr := push.New(st.Events(), st.PushSubscriptions(), notifier, logger)
	pruner := prune.New(st, retentions, logger)
	pruner.Tokens = st

	auditRec := audit.New(st.Audit(), logger)

	authMgr := auth.NewManager(st.Sessions(), st.Users(), auditRec, auth.CookieOptions{
		TTL:               cfg.Web.SessionTTL,
		TrustProxyHeaders: cfg.Web.TrustProxyHeaders,
	})
	authMgr.SetLogger(logger)

	authAPI := auth.NewAPI(authMgr)

	invitesAPI := invites.NewAPI(st.Invites(), st.Users(), auditRec, authMgr)
	invitesAPI.Logger = logger

	verificationURL := strings.TrimRight(cfg.Web.PublicURL, "/") + "/device"
	if cfg.Web.PublicURL == "" {
		verificationURL = "/device"
	}
	devicePairAPI := devicepair.NewAPI(st, authMgr, auditRec, verificationURL)
	devicePairAPI.Logger = logger

	meAPI := &me.API{
		Users:             st.Users(),
		Tokens:            st.Tokens(),
		Subs:              st.PushSubscriptions(),
		Audit:             auditRec,
		Logger:            logger,
		Auth:              authMgr,
		Bearer:            bearerAuth,
		PushManager:       pmgr,
		HashSecret:        tokens.Hash,
		ConfiguredSources: configuredSourceSet,
	}

	adminAPI := &admin.API{
		Users:        st.Users(),
		Sessions:     st.Sessions(),
		Tokens:       st.Tokens(),
		Subs:         st.PushSubscriptions(),
		Audit:        auditRec,
		AuditReader:  st.Audit(),
		Cascader:     st,
		HashPassword: func(p string) (string, error) { return pkgUsers.HashPassword(secret.String(p)) },
		ValidatePolicy: func(email, plain string) error {
			return pkgUsers.ValidatePassword(email, secret.String(plain))
		},
		Logger: logger,
		Auth:   authMgr,
		Bearer: bearerAuth,
	}

	mux := http.NewServeMux()

	// Ingest.
	ingestHandler := ingest.New(bindings, st, notifier, logger)
	ingestHandler.Register(mux, "/ingest/")

	// Subscribe (SSE).
	sseHandler := subscribe.New(st, notifier, bearerAuth, configuredSources, logger)
	mux.Handle("GET /subscribe/{source}", sseHandler)

	// Token API (admin).
	tokenAPI := tokens.NewAPI(st.Tokens(), bearerAuth)
	tokenAPI.Logger = logger
	tokenAPI.Audit = auditRec
	tokenAPI.Register(mux)

	// Push API (admin).
	pushAPI := push.NewAPI(pmgr, st.PushSubscriptions(), bearerAuth, configuredSources, tokens.Hash)
	pushAPI.Logger = logger
	pushAPI.Audit = auditRec
	pushAPI.Register(mux)

	// Inspector. The session manager wires up cookie-session auth that
	// complements the legacy bearer-cookie path (tasks 11.10, 11.12).
	insp, err := inspector.New(st.Events(), st.Tokens(), st.PushSubscriptions(), notifier, pmgr, bearerAuth, configuredSources, logger)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	insp.Sessions = authMgr
	insp.Audit = auditRec
	insp.Users = st.Users()
	insp.AuditReader = st.Audit()
	insp.Invites = st.Invites()
	insp.Cascader = st
	insp.HashPassword = func(p string) (string, error) { return pkgUsers.HashPassword(secret.String(p)) }
	insp.ValidatePolicy = func(email, plain string) error {
		return pkgUsers.ValidatePassword(email, secret.String(plain))
	}
	insp.Register(mux)

	// Server-rendered /login and /signup pages (the JSON /api/auth/login
	// and /api/auth/signup endpoints remain for hooksctl + SPA callers).
	signupFn := webpages.DefaultSignupFunc(st.Invites(), st.Users(), auditRec)
	pages, err := webpages.New(authMgr, signupFn, logger)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	pages.MountDevice(devicePairAPI)
	// Run page handlers through the session middleware so DeviceGET
	// can read (*User, *Session) from context and DevicePOST's CSRF
	// check has the post-session cookie to compare against. /login and
	// /signup also run through the middleware; it's a no-op when the
	// caller has no existing session cookie.
	pages.RegisterWithMiddleware(mux, authMgr.Middleware)

	// Auth + me + admin + invites + devicepair routes.
	registerAuthRoutes(mux, authMgr, authAPI, invitesAPI, devicePairAPI, meAPI, adminAPI)

	s := &Server{
		Cfg:         cfg,
		Store:       st,
		Notifier:    notifier,
		Push:        pmgr,
		Prune:       pruner,
		Mux:         mux,
		Logger:      logger,
		Listener:    cfg.ListenAddr,
		AuthManager: authMgr,
		DevicePair:  devicePairAPI,
		stopped:     make(chan struct{}),
	}

	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)

	return s, nil
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.Ping(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

// Run starts the HTTP listener and background goroutines. It blocks until
// Stop or the listener fails. The session sweeper and device-pairing
// sweeper run alongside the push manager and event pruner.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Push.Start(ctx); err != nil {
		return err
	}
	pruneCtx, pruneCancel := context.WithCancel(ctx)
	defer pruneCancel()
	go s.Prune.Run(pruneCtx)

	if s.AuthManager != nil {
		go s.AuthManager.RunSweeper(pruneCtx, s.Logger)
	}
	if s.DevicePair != nil {
		go s.DevicePair.RunSweeper(pruneCtx, time.Minute)
	}

	s.httpServer = &http.Server{
		Addr:              s.Listener,
		Handler:           s.Mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.Logger.Info("hooks: listening", slog.String("addr", s.Listener))
	err := s.httpServer.ListenAndServe()
	close(s.stopped)
	if stderrors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Stop gracefully shuts down the HTTP server and stops dispatchers.
func (s *Server) Stop(ctx context.Context) error {
	var stopErr error
	s.stopOnce.Do(func() {
		if s.httpServer != nil {
			stopErr = s.httpServer.Shutdown(ctx)
		}
		s.Push.Stop()
	})
	return stopErr
}

// Close releases resources held by the store. Call after Stop.
func (s *Server) Close() error {
	return s.Store.Close()
}

// registerAuthRoutes mounts /api/auth/*, /api/invites/*, /api/me/*,
// /api/users/*, /api/audit. Each route gets the appropriate combination
// of session middleware, CSRF middleware, and rate limiting.
func registerAuthRoutes(mux *http.ServeMux, mgr *auth.Manager, authAPI *auth.API, invAPI *invites.API, dpAPI *devicepair.API, meAPI *me.API, admAPI *admin.API) {
	loginRL := ratelimit.New(
		ratelimit.Limit{Per: time.Minute, Burst: 5},
		ratelimit.Limit{Per: time.Hour, Burst: 30},
	)
	signupRL := ratelimit.New(
		ratelimit.Limit{Per: time.Minute, Burst: 3},
		ratelimit.Limit{Per: time.Hour, Burst: 10},
	)
	devStartRL := ratelimit.New(ratelimit.Limit{Per: time.Minute, Burst: 10})
	devPollRL := ratelimit.New(ratelimit.Limit{Per: time.Minute, Burst: 60})
	devApproveRL := ratelimit.New(ratelimit.Limit{Per: time.Minute, Burst: 10})

	csrfCfg := web.CSRFConfig{}
	csrf := func(h http.Handler) http.Handler { return web.Middleware(csrfCfg, h) }
	session := mgr.Middleware
	rlIP := func(l *ratelimit.Limiter, h http.Handler) http.Handler {
		return ratelimit.Middleware(l, ratelimit.KeyByIP, h)
	}
	rlUser := func(l *ratelimit.Limiter, h http.Handler) http.Handler {
		return wrapUserRateLimit(mgr, l, h)
	}

	// Auth (login/logout/signup) ----------------------------------------
	mux.Handle("POST /api/auth/login", session(csrf(rlIP(loginRL, http.HandlerFunc(authAPI.Login)))))
	mux.Handle("POST /api/auth/logout", session(csrf(http.HandlerFunc(authAPI.Logout))))
	mux.Handle("POST /api/auth/signup", session(csrf(rlIP(signupRL, http.HandlerFunc(invAPI.Signup)))))

	// Device pairing (poll is unauthenticated; approve is per-user) -----
	mux.Handle("POST /api/auth/device/start", csrf(rlIP(devStartRL, http.HandlerFunc(dpAPI.Start))))
	mux.Handle("POST /api/auth/device/poll", rlIP(devPollRL, http.HandlerFunc(dpAPI.Poll)))
	mux.Handle("POST /api/auth/device/approve", session(csrf(rlUser(devApproveRL, http.HandlerFunc(dpAPI.Approve)))))
	mux.Handle("POST /api/auth/device/deny", session(csrf(http.HandlerFunc(dpAPI.Deny))))

	// Invites (admin) ---------------------------------------------------
	mux.Handle("POST /api/invites", session(csrf(http.HandlerFunc(invAPI.Create))))
	mux.Handle("GET /api/invites", session(http.HandlerFunc(invAPI.List)))
	mux.Handle("DELETE /api/invites/{code}", session(csrf(http.HandlerFunc(invAPI.Delete))))

	// /api/me/* ---------------------------------------------------------
	mux.Handle("GET /api/me", session(http.HandlerFunc(meAPI.GetMe)))
	mux.Handle("PATCH /api/me", session(csrf(http.HandlerFunc(meAPI.PatchMe))))
	mux.Handle("GET /api/me/tokens", session(http.HandlerFunc(meAPI.ListTokens)))
	mux.Handle("POST /api/me/tokens", session(csrf(http.HandlerFunc(meAPI.CreateToken))))
	mux.Handle("POST /api/me/tokens/{id}/revoke", session(csrf(http.HandlerFunc(meAPI.RevokeToken))))
	mux.Handle("GET /api/me/subscriptions", session(http.HandlerFunc(meAPI.ListSubs)))
	mux.Handle("POST /api/me/subscriptions", session(csrf(http.HandlerFunc(meAPI.CreateSub))))
	mux.Handle("GET /api/me/subscriptions/{id}", session(http.HandlerFunc(meAPI.GetSub)))
	mux.Handle("DELETE /api/me/subscriptions/{id}", session(csrf(http.HandlerFunc(meAPI.DeleteSub))))
	mux.Handle("POST /api/me/subscriptions/{id}/pause", session(csrf(http.HandlerFunc(meAPI.PauseSub))))
	mux.Handle("POST /api/me/subscriptions/{id}/resume", session(csrf(http.HandlerFunc(meAPI.ResumeSub))))
	mux.Handle("POST /api/me/subscriptions/{id}/rotate-secret", session(csrf(http.HandlerFunc(meAPI.RotateSub))))
	mux.Handle("POST /api/me/subscriptions/{id}/test", session(csrf(http.HandlerFunc(meAPI.TestSub))))

	// /api/users/* and /api/audit (admin) -------------------------------
	mux.Handle("GET /api/users", session(http.HandlerFunc(admAPI.ListUsers)))
	mux.Handle("GET /api/users/{id}", session(http.HandlerFunc(admAPI.GetUser)))
	mux.Handle("PATCH /api/users/{id}", session(csrf(http.HandlerFunc(admAPI.PatchUser))))
	mux.Handle("POST /api/users/{id}/deactivate", session(csrf(http.HandlerFunc(admAPI.Deactivate))))
	mux.Handle("POST /api/users/{id}/reactivate", session(csrf(http.HandlerFunc(admAPI.Reactivate))))
	mux.Handle("POST /api/users/{id}/reset-password", session(csrf(http.HandlerFunc(admAPI.ResetPassword))))
	mux.Handle("GET /api/audit", session(http.HandlerFunc(admAPI.ListAudit)))
}

// wrapUserRateLimit composes session-attached user-id with a per-user
// rate limiter. The user-id MUST be tagged into the context before the
// limiter runs — `ratelimit.Middleware` calls `KeyByUser(r)` once at
// request time, so a tag-after-limiter ordering would have the limiter
// always see an empty key and silently bypass accounting.
func wrapUserRateLimit(mgr *auth.Manager, l *ratelimit.Limiter, h http.Handler) http.Handler {
	limited := ratelimit.Middleware(l, ratelimit.KeyByUser, h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, _, ok := mgr.FromContext(r.Context()); ok {
			r = r.WithContext(ratelimit.WithUserKey(r.Context(), user.ID))
		}
		limited.ServeHTTP(w, r)
	})
}
