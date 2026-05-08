// Package server wires the storage layer, ingestion handler, SSE handler,
// push manager, pruner, inspector, and HTTP routes together. It is consumed
// by cmd/hooks for both the long-running server and `hooks --dev` mode.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/onebusaway/hooks/internal/config"
	"github.com/onebusaway/hooks/internal/ingest"
	"github.com/onebusaway/hooks/internal/inspector"
	"github.com/onebusaway/hooks/internal/prune"
	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/push"
	"github.com/onebusaway/hooks/internal/sources"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/subscribe"
	"github.com/onebusaway/hooks/internal/tokens"
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

	httpServer *http.Server
	stopOnce   sync.Once
	stopped    chan struct{}
	readyOK    bool
	readyMu    sync.RWMutex
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

	notifier := pubsub.New()

	// Build verifiers for every configured source.
	bindings := map[string]ingest.SourceBinding{}
	configuredSources := make([]string, 0, len(cfg.Sources))
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
		retentions[name] = src.Retention
	}

	auth := tokens.New(st.Tokens())
	pmgr := push.New(st.Events(), st.PushSubscriptions(), notifier, logger)
	pruner := prune.New(st, retentions, logger)

	mux := http.NewServeMux()

	// Ingest.
	ingestHandler := ingest.New(bindings, st, notifier, logger)
	ingestHandler.Register(mux, "/ingest/")

	// Subscribe (SSE).
	sseHandler := subscribe.New(st, notifier, auth, configuredSources, logger)
	mux.Handle("GET /subscribe/{source}", sseHandler)

	// Token API.
	tokenAPI := tokens.NewAPI(st.Tokens(), auth)
	tokenAPI.Register(mux)

	// Push API.
	pushAPI := push.NewAPI(pmgr, st.PushSubscriptions(), auth, configuredSources, tokens.Hash)
	pushAPI.Register(mux)

	// Inspector.
	insp, err := inspector.New(st.Events(), st.Tokens(), st.PushSubscriptions(), notifier, pmgr, auth, configuredSources, logger)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	insp.Register(mux)

	s := &Server{
		Cfg:      cfg,
		Store:    st,
		Notifier: notifier,
		Push:     pmgr,
		Prune:    pruner,
		Mux:      mux,
		Logger:   logger,
		Listener: cfg.ListenAddr,
		stopped:  make(chan struct{}),
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
// Stop or the listener fails.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Push.Start(ctx); err != nil {
		return err
	}
	pruneCtx, pruneCancel := context.WithCancel(ctx)
	defer pruneCancel()
	go s.Prune.Run(pruneCtx)

	s.httpServer = &http.Server{
		Addr:              s.Listener,
		Handler:           s.Mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.Logger.Info("hooks: listening", slog.String("addr", s.Listener))
	err := s.httpServer.ListenAndServe()
	close(s.stopped)
	if errors.Is(err, http.ErrServerClosed) {
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

// silenced
var _ = os.Stderr
