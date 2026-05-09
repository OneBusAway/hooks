package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/web"
)

// Alice is the user inserted by startTestServerWithUser; the e2e tests
// drive /api/auth/login as her.
const (
	aliceEmail    = "alice@example.com"
	alicePassword = "supercalifragilistic"
)

// captureStdoutLive replaces os.Stdout with a pipe and starts a scanner
// goroutine that streams every line into an internal buffer AND yields
// any "Code: XXXX-XXXX" line on `codeCh` (non-blocking — only the first
// such line is delivered). captured() returns whatever has been read so
// far under a mutex (it does not wait for EOF).
//
// stop() restores os.Stdout, closes the pipe writer, and waits for the
// scanner goroutine to drain. It is safe to call multiple times via
// sync.Once.
func captureStdoutLive(t *testing.T) (codeCh <-chan string, captured func() string, stop func()) {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = pw

	ch := make(chan string, 1)
	var (
		buf  bytes.Buffer
		mu   sync.Mutex
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			buf.WriteString(line + "\n")
			mu.Unlock()
			if strings.HasPrefix(line, "Code:") {
				select {
				case ch <- strings.TrimSpace(strings.TrimPrefix(line, "Code:")):
				default:
				}
			}
		}
	}()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			os.Stdout = old
			_ = pw.Close()
			<-done
			_ = pr.Close()
		})
	}
	captured = func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
	return ch, captured, stop
}

// browserLogin POSTs /api/auth/login as Alice and returns the CSRF token
// alongside the cookie jar that now carries hooks_session + hooks_csrf.
func browserLogin(t *testing.T, base string) (*http.Client, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]string{
		"email":    aliceEmail,
		"password": alicePassword,
	})
	resp, err := cli.Post(base+"/api/auth/login",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		t.Fatalf("browser login: %d %s", resp.StatusCode, bb)
	}
	var lr struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatal(err)
	}
	if lr.CSRFToken == "" {
		t.Fatal("login response missing csrf_token")
	}
	parsed, _ := url.Parse(base)
	for _, c := range jar.Cookies(parsed) {
		if c.Name == auth.SessionCookie && c.Value != "" {
			return cli, lr.CSRFToken
		}
	}
	t.Fatalf("hooks_session cookie not set after login")
	return nil, ""
}

// postCSRF builds a JSON POST that satisfies CSRF middleware: same-host
// Origin header + the CSRF header. The cookie jar on cli supplies
// hooks_session and hooks_csrf automatically.
func postCSRF(t *testing.T, cli *http.Client, base, path, csrfToken string, body any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	req.Header.Set(web.CSRFTokenHeader, csrfToken)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// runLoginAsync starts cmdLogin in a goroutine and waits for it to print
// the user_code banner. Returns (userCode, exitCh).
func runLoginAsync(t *testing.T, base string, codeCh <-chan string) (string, <-chan int) {
	t.Helper()
	exitCh := make(chan int, 1)
	go func() {
		exitCh <- cmdLogin(globals{
			Server: base, Profile: "default",
		}, []string{"--scopes", "render"})
	}()
	select {
	case code := <-codeCh:
		if code == "" {
			t.Fatal("empty user_code")
		}
		return code, exitCh
	case <-time.After(5 * time.Second):
		t.Fatal("cmdLogin did not print user_code within 5s")
	}
	return "", exitCh
}

// TestLogin_E2E_AgainstRealServer drives `hooksctl login` against a real
// in-process server (built via server.Build, mounted on httptest.NewServer)
// and validates the full device-pairing flow:
//
//   - login start prints user_code to stdout;
//   - a parallel "browser" logs in with email+password, then approves the
//     pairing using the real session cookie + CSRF token plumbing;
//   - cmdLogin polls, sees approved_unfetched, returns the plaintext PAT,
//     and writes the credentials profile.
//
// This is the §7.12 "CLI integration test against an in-process server
// using the existing httptest harness" coverage. It complements
// login_test.go (which uses fake mux handlers) by exercising the real
// /api/auth/device/{start,approve,poll} pipeline with CSRF and rate
// limiting active.
func TestLogin_E2E_AgainstRealServer(t *testing.T) {
	base, _, _, _, _, stop := startTestServerWithUser(t)
	t.Cleanup(stop)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	loginTestClient = &http.Client{Timeout: 10 * time.Second}
	t.Cleanup(func() { loginTestClient = nil })

	codeCh, captured, stopCapture := captureStdoutLive(t)
	t.Cleanup(stopCapture)

	userCode, exitCh := runLoginAsync(t, base, codeCh)

	browser, csrf := browserLogin(t, base)

	approveResp := postCSRF(t, browser, base, "/api/auth/device/approve", csrf, map[string]any{
		"user_code":      userCode,
		"password":       alicePassword,
		"granted_scopes": []string{"render"},
	})
	defer func() { _ = approveResp.Body.Close() }()
	if approveResp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(approveResp.Body)
		t.Fatalf("approve: %d %s", approveResp.StatusCode, bb)
	}

	// cmdLogin's first poll is `interval` seconds out (server returns
	// PollInterval=5). Wait up to 10s for it to return success.
	var exit int
	select {
	case exit = <-exitCh:
	case <-time.After(10 * time.Second):
		stopCapture()
		t.Fatalf("cmdLogin did not return within 10s; stdout=%q", captured())
	}
	stopCapture()
	if exit != 0 {
		t.Fatalf("cmdLogin exit = %d; stdout=%q", exit, captured())
	}

	// Profile must contain the PAT. We do not know the plaintext value here
	// (it was minted server-side), so the assertion is "non-empty + server
	// URL matches".
	prof, err := loadProfile("default")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	if prof.Token == "" {
		t.Fatal("profile written without token")
	}
	if prof.ServerURL != base {
		t.Errorf("profile.ServerURL = %q, want %q", prof.ServerURL, base)
	}
	if !strings.Contains(captured(), "render") {
		t.Errorf("expected stdout to mention granted scope; got %q", captured())
	}

	// Sanity: a PAT was minted with the granted scope.
	bearer, _ := http.NewRequest(http.MethodGet, base+"/api/me", nil)
	bearer.Header.Set("Authorization", "Bearer "+prof.Token)
	meResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(bearer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meResp.Body.Close() }()
	if meResp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(meResp.Body)
		t.Fatalf("/api/me with minted PAT: %d %s", meResp.StatusCode, bb)
	}
	var me struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(meResp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.Email != aliceEmail {
		t.Errorf("/api/me email = %q, want %q", me.Email, aliceEmail)
	}
}

// TestLogin_E2E_AgainstRealServer_Deny drives cmdLogin against the real
// server and denies the pairing from the "browser" side; cmdLogin must
// exit non-zero with no profile written.
func TestLogin_E2E_AgainstRealServer_Deny(t *testing.T) {
	base, _, _, _, _, stop := startTestServerWithUser(t)
	t.Cleanup(stop)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	loginTestClient = &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(func() { loginTestClient = nil })

	codeCh, _, stopCapture := captureStdoutLive(t)
	t.Cleanup(stopCapture)

	userCode, exitCh := runLoginAsync(t, base, codeCh)

	browser, csrf := browserLogin(t, base)
	denyResp := postCSRF(t, browser, base, "/api/auth/device/deny", csrf, map[string]string{
		"user_code": userCode,
	})
	defer func() { _ = denyResp.Body.Close() }()
	if denyResp.StatusCode != http.StatusOK && denyResp.StatusCode != http.StatusNoContent {
		t.Fatalf("deny: %d", denyResp.StatusCode)
	}

	var exit int
	select {
	case exit = <-exitCh:
	case <-time.After(10 * time.Second):
		t.Fatal("cmdLogin did not return within 10s after deny")
	}
	if exit == 0 {
		t.Errorf("cmdLogin exit = 0 after deny; want non-zero")
	}
	if _, err := loadProfile("default"); err == nil {
		t.Errorf("profile was written despite deny")
	}
}
