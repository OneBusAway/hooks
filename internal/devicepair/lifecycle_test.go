package devicepair

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/store"
)

// TestPoll_AfterMarkFetched_Returns410 covers the §16.5 requirement
// (tasks.md:195) that "exactly one returns 200 with the plaintext and
// the other returns 410." We use the OnMarkFetched test hook to wait
// for the deferred update to land, then assert that a follow-up poll
// observes the expected 410.
//
// The relaxed concurrent-burst case (multiple polls hitting
// approved_unfetched before MarkFetched lands) is observation-
// equivalent to a single fetch per design.md; that semantic is covered
// in TestPoll_ConcurrentApprovedFetch_SamePlaintext below.
func TestPoll_AfterMarkFetched_Returns410(t *testing.T) {
	s := newTest(t)
	user, plaintext := mustUser(t, s, store.RoleUser, []string{"render"})
	api := NewAPI(s, fakeAuth{user: user, ok: true}, audit.New(s.Audit(), nil), "https://h.example/device")
	markFetched := make(chan string, 1)
	api.OnMarkFetched = func(deviceCode string, _ error) { markFetched <- deviceCode }
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(startRequest{Scopes: []string{"render"}})
	resp, err := http.Post(srv.URL+"/api/auth/device/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var sr startResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()

	body, _ = json.Marshal(approveRequest{UserCode: sr.UserCode, Password: plaintext, GrantedScopes: []string{"render"}})
	resp, err = http.Post(srv.URL+"/api/auth/device/approve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d", resp.StatusCode)
	}

	// Poll #1 — must succeed with plaintext.
	body, _ = json.Marshal(pollRequest{DeviceCode: sr.DeviceCode})
	resp, err = http.Post(srv.URL+"/api/auth/device/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("first poll: %d (want 200)", resp.StatusCode)
	}
	var pr pollResponse
	_ = json.NewDecoder(resp.Body).Decode(&pr)
	resp.Body.Close()
	if pr.Token == "" {
		t.Fatal("first poll: missing plaintext")
	}

	// Wait for the deferred MarkFetched to land. Without the hook this
	// test was a sleep-and-pray; with it we synchronize on the actual
	// state transition.
	select {
	case <-markFetched:
	case <-time.After(2 * time.Second):
		t.Fatal("MarkFetched did not fire within 2s")
	}

	// Poll #2 — must observe the post-MarkFetched 'done' status as 410.
	body, _ = json.Marshal(pollRequest{DeviceCode: sr.DeviceCode})
	resp, err = http.Post(srv.URL+"/api/auth/device/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("second poll: %d (want 410)", resp.StatusCode)
	}
}

// TestPoll_ConcurrentApprovedFetch_SamePlaintext covers the
// design.md-acknowledged window in which N concurrent polls can each
// observe approved_unfetched before MarkFetched runs. All such polls
// must return the same plaintext (observation-equivalent to a single
// fetch); a regression that minted a different plaintext per poll, or
// that leaked a different row's plaintext, would surface here.
func TestPoll_ConcurrentApprovedFetch_SamePlaintext(t *testing.T) {
	s := newTest(t)
	user, plaintext := mustUser(t, s, store.RoleUser, []string{"render"})
	api := NewAPI(s, fakeAuth{user: user, ok: true}, audit.New(s.Audit(), nil), "https://h.example/device")
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(startRequest{Scopes: []string{"render"}})
	resp, err := http.Post(srv.URL+"/api/auth/device/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var sr startResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()

	body, _ = json.Marshal(approveRequest{UserCode: sr.UserCode, Password: plaintext, GrantedScopes: []string{"render"}})
	resp, err = http.Post(srv.URL+"/api/auth/device/approve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	const N = 8
	var wg sync.WaitGroup
	tokens := make(chan string, N)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			body, _ := json.Marshal(pollRequest{DeviceCode: sr.DeviceCode})
			resp, err := http.Post(srv.URL+"/api/auth/device/poll", "application/json", bytes.NewReader(body))
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var pr pollResponse
				_ = json.NewDecoder(resp.Body).Decode(&pr)
				tokens <- pr.Token
			}
		}()
	}
	close(start)
	wg.Wait()
	close(tokens)

	seen := map[string]struct{}{}
	count := 0
	for tok := range tokens {
		seen[tok] = struct{}{}
		count++
	}
	if count == 0 {
		t.Fatal("no poll received plaintext (one must succeed)")
	}
	if len(seen) != 1 {
		t.Errorf("polls returned %d distinct tokens (want 1)", len(seen))
	}
}

// TestDeny_PollReturns403 covers §16.8: after a deny, a poll should
// return 403.
func TestDeny_PollReturns403(t *testing.T) {
	s := newTest(t)
	user, _ := mustUser(t, s, store.RoleUser, []string{"render"})
	api := NewAPI(s, fakeAuth{user: user, ok: true}, audit.New(s.Audit(), nil), "https://h.example/device")
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(startRequest{Scopes: []string{"render"}})
	resp, err := http.Post(srv.URL+"/api/auth/device/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var sr startResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()

	body, _ = json.Marshal(denyRequest{UserCode: sr.UserCode})
	resp, err = http.Post(srv.URL+"/api/auth/device/deny", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("deny: %d", resp.StatusCode)
	}

	body, _ = json.Marshal(pollRequest{DeviceCode: sr.DeviceCode})
	resp, err = http.Post(srv.URL+"/api/auth/device/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("post-deny poll: %d (want 403)", resp.StatusCode)
	}
}

// TestSweeper_ExpiresPendingAndDeletesTerminal covers §16.8: the 60s
// sweeper transitions stale pendings to expired and hard-deletes
// terminal rows older than 24h. We drive RunSweeper with a 1ms tick so
// the actual ticker / context-cancel / Now-resolution wiring is on the
// hot path of the test, not just the underlying queries.
func TestSweeper_ExpiresPendingAndDeletesTerminal(t *testing.T) {
	s := newTest(t)
	user, _ := mustUser(t, s, store.RoleUser, []string{"render"})
	api := NewAPI(s, fakeAuth{user: user, ok: true}, audit.New(s.Audit(), nil), "https://h.example/device")

	currentNow := time.Now().UTC()
	api.Now = func() time.Time { return currentNow }

	pairing := store.DevicePairing{
		DeviceCode:          "dev-pending-1",
		UserCode:            "ABCD-EFGH",
		Status:              store.DevicePairingStatusPending,
		CreatedAt:           currentNow.Add(-time.Hour),
		ExpiresAt:           currentNow.Add(-time.Minute),
		RequestingIP:        "127.0.0.1",
		RequestingUserAgent: "test",
		RequestedScopes:     []string{"render"},
	}
	if err := s.InsertDevicePairing(context.Background(), pairing); err != nil {
		t.Fatal(err)
	}

	terminal := store.DevicePairing{
		DeviceCode:          "dev-old-denied",
		UserCode:            "WXYZ-1234",
		Status:              store.DevicePairingStatusDenied,
		CreatedAt:           currentNow.Add(-48 * time.Hour),
		ExpiresAt:           currentNow.Add(-47 * time.Hour),
		RequestingIP:        "127.0.0.1",
		RequestingUserAgent: "test",
		RequestedScopes:     []string{"render"},
	}
	if err := s.InsertDevicePairing(context.Background(), terminal); err != nil {
		t.Fatal(err)
	}

	// Drive the actual sweeper goroutine. A 1ms ticker means the first
	// sweep fires effectively immediately; ctx-cancel stops the loop.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		api.RunSweeper(ctx, time.Millisecond)
		close(done)
	}()

	// Poll for both transitions. Bounded retry — if the sweeper isn't
	// running we'll surface a clear timeout, not flake under load.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		dp, err := api.Pairings.GetByDeviceCode(context.Background(), "dev-pending-1")
		expiredOK := err == nil && dp.Status == store.DevicePairingStatusExpired
		_, getOldErr := api.Pairings.GetByDeviceCode(context.Background(), "dev-old-denied")
		deletedOK := getOldErr != nil
		if expiredOK && deletedOK {
			cancel()
			<-done
			return // success
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Diagnostic on timeout.
	dp, err := api.Pairings.GetByDeviceCode(context.Background(), "dev-pending-1")
	t.Errorf("sweeper did not transition pending row within 2s; status=%q err=%v", dp.Status, err)
	if _, err := api.Pairings.GetByDeviceCode(context.Background(), "dev-old-denied"); err == nil {
		t.Errorf("sweeper did not hard-delete old denied row within 2s")
	}
	cancel()
	<-done
}
