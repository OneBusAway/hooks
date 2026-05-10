// Command hooks runs the webhook relay server (and a small CLI: init, prune, verify).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"strings"

	"github.com/onebusaway/hooks/internal/config"
	"github.com/onebusaway/hooks/internal/invites"
	"github.com/onebusaway/hooks/internal/prune"
	"github.com/onebusaway/hooks/internal/server"
	"github.com/onebusaway/hooks/internal/sources"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "init":
			os.Exit(runInit(os.Args[2:]))
		case "invite":
			os.Exit(runInvite(os.Args[2:]))
		case "prune":
			os.Exit(runPrune(os.Args[2:]))
		case "verify":
			os.Exit(runVerify(os.Args[2:]))
		case "-h", "--help", "help":
			usage(os.Stdout)
			return
		}
	}
	os.Exit(runServer(os.Args[1:]))
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `hooks: durable webhook relay

Usage:
  hooks                       run the server (defaults from hooks.yaml)
  hooks --dev                 run in dev mode (verbose, opens browser, prints quickstart)
  hooks init                  scaffold hooks.yaml + database, mint admin token
  hooks invite                mint a signup invite directly against the local DB and print the URL
  hooks prune --older-than 7d remove events older than the given duration
  hooks verify                recompute body sha256 for all stored events

Common flags:
  --config <path>             path to hooks.yaml (default: ./hooks.yaml)
  --listen <addr>             listen address (overrides config + env)
`)
}

func runServer(args []string) int {
	fs := flag.NewFlagSet("hooks", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "hooks.yaml", "path to hooks.yaml")
	listen := fs.String("listen", "", "listen address (overrides config and env)")
	dev := fs.Bool("dev", false, "developer mode: verbose logging, open browser, print quickstart")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	logLevel := slog.LevelInfo
	if *dev {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	cfg, err := config.Load(*configPath, sources.Default)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}
	if *listen != "" {
		cfg.ListenAddr = *listen
	}

	srv, err := server.Build(cfg, sources.Default, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build server: %v\n", err)
		return 1
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *dev {
		printDevQuickstart(srv)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		_ = srv.Stop(shutdownCtx)
	}()

	if err := srv.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	return 0
}

func printDevQuickstart(srv *server.Server) {
	addr := srv.Cfg.ListenAddr
	host := addr
	if len(host) > 0 && host[0] == ':' {
		host = "localhost" + host
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "hooks --dev quickstart:")
	fmt.Fprintf(os.Stderr, "  inspector: http://%s/inspector\n", host)
	for source := range srv.Cfg.Sources {
		fmt.Fprintf(os.Stderr, "  ingest:    http://%s/ingest/%s\n", host, source)
		fmt.Fprintf(os.Stderr, "  forward:   hooksctl forward %s --to http://localhost:3000/webhooks/%s\n", source, source)
		fmt.Fprintf(os.Stderr, "  push add:  hooksctl push add --source %s --to https://my-svc.example.com/hooks\n", source)
	}
	fmt.Fprintln(os.Stderr, "")
	openBrowser(fmt.Sprintf("http://%s/inspector", host))
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	// G204: the URL is built from `--listen` flag in `hooks --dev` mode only;
	// it's the operator's own machine and the OS-specific helper handles quoting.
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url) //nolint:gosec
	case "linux":
		cmd = exec.Command("xdg-open", url) //nolint:gosec
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url) //nolint:gosec
	default:
		return
	}
	_ = cmd.Start()
}

// --- subcommand: init -------------------------------------------------------

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	force := fs.Bool("force", false, "overwrite existing hooks.yaml")
	dir := fs.String("dir", ".", "directory to scaffold into")
	tokenName := fs.String("token-name", "operator", "name for the generated admin token")
	serverURL := fs.String("server-url", "", "public URL for the printed signup link (env: HOOKS_PUBLIC_URL)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *serverURL == "" {
		*serverURL = os.Getenv("HOOKS_PUBLIC_URL")
	}

	configPath := filepath.Join(*dir, "hooks.yaml")
	dbPath := filepath.Join(*dir, "hooks.db")

	if !*force {
		if _, err := os.Stat(configPath); err == nil {
			fmt.Fprintf(os.Stderr, "init: %s already exists; pass --force to overwrite\n", configPath)
			return 1
		}
	}

	defaultConfig := []byte(`# hooks.yaml — generated by ` + "`hooks init`" + `

# Per-source secrets and retention. Tokens and push subscriptions live in the
# database, not here — manage them with hooksctl or the inspector.
sources:
  render:
    verifier: render
    secret: ${RENDER_WEBHOOK_SECRET}
    retention: 30d
`)
	if err := os.WriteFile(configPath, defaultConfig, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "init: write config: %v\n", err)
		return 1
	}

	st, err := store.OpenSQLite(dbPath, store.SQLiteOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: open db: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()
	tokens.AttachVerifier(st)

	res, err := tokens.Issue(context.Background(), st.Tokens(), *tokenName, []string{store.ScopeAdmin})
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: issue token: %v\n", err)
		return 1
	}

	// Bootstrap signup invite: only ensure when the users table is empty.
	// Re-running `hooks init --force` against a populated DB does NOT
	// mint a fresh signup link — that would be confusing on existing
	// deployments where accounts already exist.
	bootstrapCode := ""
	bootstrapTTL := ""
	adminCount, adminErr := st.CountActiveAdmins(context.Background())
	if adminErr != nil {
		// Don't silently skip the bootstrap path on a transient DB read —
		// surface so the operator can investigate.
		fmt.Fprintf(os.Stderr, "init: count active admins: %v\n", adminErr)
		return 1
	}
	if adminCount == 0 {
		// Also check the wider users table to handle the
		// "every admin has been deactivated" edge case (still treated
		// as "no admins, re-bootstrap is fine"). Use CountUsers rather
		// than materializing ListUsers — matters once a deployment has
		// thousands of accounts. CRITICAL: do NOT swallow the error here;
		// a transient failure that returned 0 would silently mint a fresh
		// bootstrap admin invite on a populated database.
		total, err := st.CountUsers(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "init: count users: %v\n", err)
			return 1
		}
		if total == 0 {
			now := time.Now().UTC()
			inv, err := st.EnsureBootstrapInvite(context.Background(),
				func() string {
					c, _ := invites.NewCode()
					return c
				},
				24*time.Hour, now,
			)
			if err != nil {
				// A populated DB with zero users is the canonical "fresh
				// install"; if we can't mint the bootstrap invite the
				// operator has no way to sign in. Fail loud so they can
				// investigate (disk full, schema drift, etc).
				fmt.Fprintf(os.Stderr, "init: ensure bootstrap invite: %v\n", err)
				return 1
			}
			bootstrapCode = inv.Code
			if inv.ExpiresAt != nil {
				bootstrapTTL = inv.ExpiresAt.Sub(now).Round(time.Hour).String()
			}
		}
	}

	fmt.Println("hooks init: ready.")
	fmt.Printf("  config: %s\n", configPath)
	fmt.Printf("  db:     %s\n", dbPath)
	fmt.Printf("  admin token (shown ONCE): %s\n", res.Plaintext)
	if bootstrapCode != "" {
		base, placeholder := signupBase(*serverURL)
		fmt.Printf("  signup: %s/signup?code=%s\n", base, bootstrapCode)
		if placeholder {
			fmt.Println("          (set HOOKS_PUBLIC_URL or --server-url to print the real URL)")
		}
		if bootstrapTTL != "" {
			fmt.Printf("          (single-use; expires in %s; auto-disables once any account exists)\n", bootstrapTTL)
		}
	}
	printInitNextSteps(strings.TrimRight(*serverURL, "/"), res.Plaintext, bootstrapCode != "")
	return 0
}

// printInitNextSteps writes the post-init guidance to stdout. The same `hooks
// init` is invoked from a developer laptop AND from docker-entrypoint.sh on a
// fresh Render volume — those two contexts need different instructions:
//
//   - On Render the server is about to start automatically; "hooks --dev" is
//     wrong, RENDER_WEBHOOK_SECRET goes in the service Environment tab (not a
//     local shell), and the public URL is known via HOOKS_PUBLIC_URL.
//   - Locally the operator still needs to start the server, and the public
//     URL is usually unknown until they pick a hostname / proxy.
//
// We detect the Render case via the `RENDER=true` env var that the platform
// injects into every service container, and fall back to the generic guidance
// otherwise.
func printInitNextSteps(publicURL, adminToken string, hasBootstrapInvite bool) {
	host := publicURL
	if host == "" {
		host = "https://<your-public-url>"
	}
	onRender := os.Getenv("RENDER") == "true"

	fmt.Println()
	fmt.Println("Next steps:")

	// Step 1: provider secret. Wording differs by platform because the
	// "environment" the operator has to edit is in different places.
	if onRender {
		fmt.Println("  1. In the Render dashboard → your service → Environment, set")
		fmt.Println("     RENDER_WEBHOOK_SECRET to the signing secret from the Render")
		fmt.Println("     webhook you'll register in step 3. Saving triggers a redeploy;")
		fmt.Println("     this admin token and signup URL persist across the redeploy.")
	} else {
		fmt.Println("  1. Export the per-webhook signing secret in the shell that will")
		fmt.Println("     run hooks (or set it in your process supervisor / .env file):")
		fmt.Println("       export RENDER_WEBHOOK_SECRET=<secret-from-render>")
	}

	// Step 2: claim the admin account. Skip when there's no bootstrap
	// invite (re-run of `hooks init --force` against a populated DB).
	stepNum := 2
	if hasBootstrapInvite {
		fmt.Printf("  %d. Open the signup URL above in a browser to claim your admin\n", stepNum)
		fmt.Println("     account. The one-time admin token shown above also works as a")
		fmt.Println("     bearer credential for hooksctl, but a real account is what")
		fmt.Println("     enables the inspector and per-user PATs.")
		stepNum++
	}

	// Step 3 (or 2): start the server, only outside of Render.
	if !onRender {
		fmt.Printf("  %d. Start the server:  hooks   (or `hooks --dev` for the inspector)\n", stepNum)
		stepNum++
	}

	// Step: register the provider webhook.
	fmt.Printf("  %d. Register a Render webhook pointing at:\n", stepNum)
	fmt.Printf("       %s/ingest/render\n", host)
	fmt.Println("     Use the same secret you set in step 1.")
	stepNum++

	// Step: connect a developer laptop.
	fmt.Printf("  %d. From a dev laptop, pair with the relay:\n", stepNum)
	fmt.Printf("       hooksctl login --server %s --scopes render\n", host)
	fmt.Println("       hooksctl forward render --to http://localhost:3000/webhooks/render")
	if !hasBootstrapInvite {
		// No signup URL was printed — surface the legacy admin-token path
		// so the operator still has a way in.
		fmt.Printf("     (Or skip `login` and use the legacy admin token: HOOKS_TOKEN=%s)\n", adminToken)
	}
	stepNum++

	// Step: long-lived consumer.
	fmt.Printf("  %d. Or register a long-lived consumer:\n", stepNum)
	fmt.Println("       hooksctl me sub add --source render --to https://my-svc.example.com/hooks")
}

// --- subcommand: invite -----------------------------------------------------

// runInvite mints a signup invite directly against the local SQLite DB and
// prints `<server-url>/signup?code=<code>`. Useful for ops who can shell
// into the host but don't want to plumb an admin PAT through hooksctl.
func runInvite(args []string) int {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "hooks.yaml", "path to hooks.yaml")
	role := fs.String("role", "user", "invite role: admin or user")
	scopesFlag := fs.String("scopes", "", "comma-separated default scopes (e.g. render,stripe)")
	ttl := fs.Duration("ttl", 7*24*time.Hour, "invite lifetime")
	serverURL := fs.String("server-url", "", "public URL for the printed signup link (env: HOOKS_PUBLIC_URL)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *serverURL == "" {
		*serverURL = os.Getenv("HOOKS_PUBLIC_URL")
	}
	if *role != "admin" && *role != "user" {
		fmt.Fprintln(os.Stderr, "invite: --role must be admin or user")
		return 2
	}

	cfg, err := config.Load(*configPath, sources.Default)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}
	st, err := store.OpenSQLite(cfg.DatabaseURL, store.SQLiteOptions{DedupeWindow: cfg.DedupeWindow})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()

	code, err := invites.NewCode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "invite: code: %v\n", err)
		return 1
	}
	now := time.Now().UTC()
	exp := now.Add(*ttl)
	scopes := []string{}
	for _, s := range strings.Split(*scopesFlag, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	inv := store.Invite{
		Code:          code,
		Role:          store.Role(*role),
		DefaultScopes: scopes,
		CreatedAt:     now,
		ExpiresAt:     &exp,
	}
	if err := st.InsertInvite(context.Background(), inv); err != nil {
		fmt.Fprintf(os.Stderr, "invite: insert: %v\n", err)
		return 1
	}

	base, placeholder := signupBase(*serverURL)
	fmt.Printf("signup: %s/signup?code=%s\n", base, code)
	if placeholder {
		fmt.Println("        (set HOOKS_PUBLIC_URL or --server-url to print the real URL)")
	}
	fmt.Printf("        (role: %s, single-use, expires in %s)\n", *role, ttl.Round(time.Hour))
	return 0
}

// signupBase returns the URL prefix to use when printing a signup link. If
// `serverURL` is empty (no --server-url flag and no HOOKS_PUBLIC_URL env var),
// it returns a `localhost:8080` placeholder and `placeholder=true` so the
// caller can print a follow-up note rather than concatenating the explanatory
// comment into the URL itself (which previously produced output like
// `http://localhost:8080  # set HOOKS_PUBLIC_URL/signup?code=…`).
func signupBase(serverURL string) (base string, placeholder bool) {
	trimmed := strings.TrimRight(serverURL, "/")
	if trimmed == "" {
		return "http://localhost:8080", true
	}
	return trimmed, false
}

// --- subcommand: prune ------------------------------------------------------

func runPrune(args []string) int {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	older := fs.Duration("older-than", 0, "delete events older than this duration (e.g. 7d would be 168h)")
	configPath := fs.String("config", "hooks.yaml", "path to hooks.yaml")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *older <= 0 {
		fmt.Fprintln(os.Stderr, "prune: --older-than is required and must be > 0")
		return 2
	}
	cfg, err := config.Load(*configPath, sources.Default)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}
	st, err := store.OpenSQLite(cfg.DatabaseURL, store.SQLiteOptions{DedupeWindow: cfg.DedupeWindow})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n, err := prune.PruneOlderThan(context.Background(), st, *older, time.Now, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prune: %v\n", err)
		return 1
	}
	fmt.Printf("prune: deleted %d rows older than %s\n", n, *older)
	return 0
}

// --- subcommand: verify -----------------------------------------------------

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "hooks.yaml", "path to hooks.yaml")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath, sources.Default)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}
	st, err := store.OpenSQLite(cfg.DatabaseURL, store.SQLiteOptions{DedupeWindow: cfg.DedupeWindow})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	srcs, err := st.Sources(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list sources: %v\n", err)
		return 1
	}
	mismatches := 0
	for _, source := range srcs {
		var cursor int64
		for {
			batch, err := st.ReadSince(ctx, source, cursor, 1000)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read: %v\n", err)
				return 1
			}
			if len(batch) == 0 {
				break
			}
			for _, ev := range batch {
				sum := sha256.Sum256(ev.Body)
				got := hex.EncodeToString(sum[:])
				if got != ev.BodySHA256 {
					fmt.Fprintf(os.Stderr, "MISMATCH source=%s sequence=%d stored=%s recomputed=%s\n",
						ev.Source, ev.Sequence, ev.BodySHA256, got)
					mismatches++
				}
				cursor = ev.Sequence
			}
		}
	}
	if mismatches > 0 {
		return 1
	}
	fmt.Println("verify: ok")
	return 0
}
