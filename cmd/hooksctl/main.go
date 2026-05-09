// Command hooksctl is the developer-side CLI for the hooks relay.
//
// Subcommands:
//
//	hooksctl tail <source> [--since <seq|latest>]
//	hooksctl forward <source> --to <url> [--exit-on-error]
//	hooksctl replay <source> <sequence> --to <url>
//	hooksctl token {add,list,revoke}
//	hooksctl push  {add,list,get,pause,resume,rotate-secret,rm,test}
//	hooksctl me    token  {add,list,revoke}
//	hooksctl me    sub    {add,list,get,pause,resume,rotate-secret,rm,test}
//	hooksctl invite {create [--role user|admin] [--scopes <list>] [--ttl 7d], list [--include-consumed], revoke <code>}
//	hooksctl login [--profile <name>] [--scopes <list>] [--admin]
//	hooksctl logout [--profile <name>]
//	hooksctl whoami [--profile <name>]
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const usageText = `hooksctl: developer CLI for hooks

Usage:
  hooksctl <command> [flags]

Commands:
  tail <source> [--since <seq|latest>]                  consume an SSE stream
  forward <source> --to <url> [--exit-on-error]         replay-then-live, POST to local URL
  replay <source> <sequence> --to <url>                 one-shot replay of one event
  token add --name <name> --scopes <list>               issue a new bearer token (plaintext shown once)
  token list [--include-revoked]                        list tokens (no plaintext)
  token revoke <id>                                     invalidate a token
  push add --source <name> --to <url> [--name <label>]  register a push subscription
  push list                                             list push subscriptions
  push get <id>                                         show one push subscription
  push pause <id>                                       pause dispatching
  push resume <id>                                      resume dispatching
  push rotate-secret <id>                               rotate signing secret
  push rm <id>                                          delete a push subscription
  push test <id>                                        send a synthetic ping
  me token add --name <n> --scopes <list>               mint a PAT/listener owned by the caller
       [--kind pat|listener] [--ephemeral]
       [--expires-in 30m|24h|30d]
  me token list [--include-revoked] [--kind <k>]        list caller-owned tokens
  me token revoke <id>                                  revoke one of the caller's tokens
  me sub {add|list|get|pause|resume|rotate-secret|rm|test}
                                                        push subscription parity scoped to caller
  invite create [--role user|admin] [--scopes <list>] [--ttl 7d]
                                                        mint a signup invite (admin only)
  invite list [--include-consumed]                      list invites
  invite revoke <code>                                  delete an unconsumed invite
  login [--profile <name>] [--scopes <list>] [--admin]  device-pair to obtain a PAT
  logout [--profile <name>]                             revoke local PAT and delete creds file
  whoami [--profile <name>]                             show the authenticated user

Global flags (also overridable per-command):
  --server  <url>    server address (default http://localhost:8080)
  --token   <tok>    bearer token (default $HOOKS_TOKEN; falls back to profile)
  --profile <name>   credentials profile name (default "default")
  --json             machine-readable output where supported
`

type globals struct {
	Server  string
	Token   string
	JSON    bool
	Profile string

	// TokenExplicit is true when Token came from --token or HOOKS_TOKEN
	// rather than the credentials profile. `hooksctl forward` uses this
	// to decide whether to auto-mint an ephemeral listener token (only
	// when Token came from the profile, i.e. a user PAT).
	TokenExplicit bool
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usageText)
		return 0
	}

	cmd := args[0]
	rest := args[1:]

	g := globals{
		Server: env("HOOKS_SERVER", defaultServerURL),
		Token:  os.Getenv("HOOKS_TOKEN"),
	}
	if g.Token != "" {
		g.TokenExplicit = true
	}
	rest = splitGlobalFlags(rest, &g)

	// Fill any unset --token / --server from the credentials profile.
	// Precedence is enforced inside resolveProfile: --token > HOOKS_TOKEN >
	// profile file > unauthenticated.
	resolveProfile(&g, g.Profile)

	switch cmd {
	case "tail":
		return cmdTail(g, rest)
	case "forward":
		return cmdForward(g, rest)
	case "replay":
		return cmdReplay(g, rest)
	case "token":
		return cmdToken(g, rest)
	case "push":
		return cmdPush(g, rest)
	case "me":
		return cmdMe(g, rest)
	case "invite":
		return cmdInvite(g, rest)
	case "login":
		return cmdLogin(g, rest)
	case "logout":
		return cmdLogout(g, rest)
	case "whoami":
		return cmdWhoami(g, rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usageText)
		return 2
	}
}

// splitGlobalFlags pulls --server / --token / --json out of args before the
// subcommand parses its own flagset.
func splitGlobalFlags(args []string, g *globals) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--server":
			i++
			if i < len(args) {
				g.Server = args[i]
			}
		case "--token":
			i++
			if i < len(args) {
				g.Token = args[i]
				g.TokenExplicit = true
			}
		case "--profile":
			i++
			if i < len(args) {
				g.Profile = args[i]
			}
		case "--json":
			g.JSON = true
		default:
			if v, ok := strings.CutPrefix(a, "--server="); ok {
				g.Server = v
			} else if v, ok := strings.CutPrefix(a, "--token="); ok {
				g.Token = v
				g.TokenExplicit = true
			} else if v, ok := strings.CutPrefix(a, "--profile="); ok {
				g.Profile = v
			} else {
				out = append(out, a)
			}
		}
	}
	return out
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// helper for sub-flag-sets to print to stderr cleanly.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we'll print our own usage on errors
	return fs
}

// parseInterleaved repeatedly calls fs.Parse so positional args may be mixed
// with flags. Returns the collected positional args.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return positional, nil
}
