package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func cmdPush(g globals, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl push {add|list|get|pause|resume|rotate-secret|rm|test} ...")
		return 2
	}
	switch args[0] {
	case "add":
		return pushAdd(g, args[1:])
	case "list":
		return pushList(g, args[1:])
	case "get":
		return pushSimpleGet(g, args[1:], "/api/push-subscriptions/")
	case "pause":
		return pushAction(g, args[1:], "pause")
	case "resume":
		return pushAction(g, args[1:], "resume")
	case "rotate-secret":
		return pushRotate(g, args[1:])
	case "rm", "delete":
		return pushDelete(g, args[1:])
	case "test":
		return pushTest(g, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown push subcommand: %s\n", args[0])
		return 2
	}
}

func pushAdd(g globals, args []string) int {
	fs := newFlagSet("push add")
	source := fs.String("source", "", "source name")
	to := fs.String("to", "", "target URL")
	name := fs.String("name", "", "label")
	since := fs.String("since", "", "starting cursor (integer or 'latest', default latest)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *source == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "usage: hooksctl push add --source <name> --to <url> [--name <label>] [--since <seq|latest>]")
		return 2
	}
	body, _ := json.Marshal(map[string]any{
		"source":     *source,
		"target_url": *to,
		"name":       *name,
		"since":      *since,
	})
	resp, err := authedRequest(g, http.MethodPost, "/api/push-subscriptions", body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "create: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	var out struct {
		ID            string `json:"id"`
		Source        string `json:"source"`
		Cursor        int64  `json:"cursor"`
		SigningSecret string `json:"signing_secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if g.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
	} else {
		fmt.Printf("id:             %s\n", out.ID)
		fmt.Printf("source:         %s\n", out.Source)
		fmt.Printf("cursor:         %d\n", out.Cursor)
		fmt.Printf("signing secret (shown ONCE): %s\n", out.SigningSecret)
	}
	return 0
}

func pushList(g globals, args []string) int {
	resp, err := authedRequest(g, http.MethodGet, "/api/push-subscriptions", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "list: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	if g.JSON {
		_, _ = io.Copy(os.Stdout, resp.Body)
		return 0
	}
	var out struct {
		Subscriptions []struct {
			ID, Source, TargetURL string
			Cursor                int64
			QueueDepth            int64
			ConsecutiveFailures   int
			LastError             string
		} `json:"subscriptions"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	fmt.Printf("%-36s %-12s %-40s %8s %8s %8s\n", "ID", "SOURCE", "TARGET", "CURSOR", "QUEUE", "FAIL")
	for _, s := range out.Subscriptions {
		fmt.Printf("%-36s %-12s %-40s %8d %8d %8d\n", s.ID, s.Source, s.TargetURL, s.Cursor, s.QueueDepth, s.ConsecutiveFailures)
	}
	_ = args
	return 0
}

func pushSimpleGet(g globals, args []string, prefix string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl push get <id>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodGet, prefix+args[0], nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "get: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	_, _ = io.Copy(os.Stdout, resp.Body)
	fmt.Println()
	return 0
}

func pushAction(g globals, args []string, action string) int {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: hooksctl push %s <id>\n", action)
		return 2
	}
	resp, err := authedRequest(g, http.MethodPost, "/api/push-subscriptions/"+args[0]+"/"+action, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "%s: %d %s\n", action, resp.StatusCode, bb)
		return 1
	}
	fmt.Println(action)
	return 0
}

func pushRotate(g globals, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl push rotate-secret <id>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodPost, "/api/push-subscriptions/"+args[0]+"/rotate-secret", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "rotate-secret: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	var out struct {
		ID            string `json:"id"`
		SigningSecret string `json:"signing_secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if g.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
	} else {
		fmt.Printf("id:             %s\n", out.ID)
		fmt.Printf("signing secret (shown ONCE): %s\n", out.SigningSecret)
	}
	return 0
}

func pushDelete(g globals, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl push rm <id>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodDelete, "/api/push-subscriptions/"+args[0], nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "rm: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	fmt.Println("removed")
	return 0
}

func pushTest(g globals, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl push test <id>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodPost, "/api/push-subscriptions/"+args[0]+"/test", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "test: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	fmt.Println("ok")
	return 0
}
