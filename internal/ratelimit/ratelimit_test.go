package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiter_BurstThenRefuse(t *testing.T) {
	l := New(Limit{Per: time.Minute, Burst: 3})
	for i := 0; i < 3; i++ {
		ok, _ := l.Allow("k")
		if !ok {
			t.Fatalf("burst %d: refused early", i)
		}
	}
	ok, retry := l.Allow("k")
	if ok {
		t.Fatal("4th request should be refused")
	}
	if retry <= 0 {
		t.Errorf("retry-after should be > 0, got %v", retry)
	}
}

func TestLimiter_DifferentKeysIndependent(t *testing.T) {
	l := New(Limit{Per: time.Minute, Burst: 1})
	if ok, _ := l.Allow("alice"); !ok {
		t.Fatal("alice first should succeed")
	}
	if ok, _ := l.Allow("bob"); !ok {
		t.Fatal("bob first should succeed (independent bucket)")
	}
	if ok, _ := l.Allow("alice"); ok {
		t.Fatal("alice second should be refused")
	}
}

func TestLimiter_Refills(t *testing.T) {
	l := New(Limit{Per: time.Second, Burst: 1})
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("first should succeed")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("second should refuse")
	}
	now = now.Add(2 * time.Second) // bucket fully refills
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("after refill should succeed")
	}
}

func TestMiddleware_429ReturnsRetryAfter(t *testing.T) {
	l := New(Limit{Per: time.Hour, Burst: 1})
	mux := http.NewServeMux()
	mux.Handle("POST /x", Middleware(l, KeyByIP, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, _ := http.Post(srv.URL+"/x", "application/json", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first: %d", resp.StatusCode)
	}
	resp, _ = http.Post(srv.URL+"/x", "application/json", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second: %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("missing Retry-After header")
	}
}

func TestNew_RejectsZeroPer(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for Per=0")
		}
	}()
	New(Limit{Per: 0, Burst: 5})
}

func TestNew_RejectsZeroBurst(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for Burst=0")
		}
	}()
	New(Limit{Per: time.Second, Burst: 0})
}

func TestKeyByUser_KeysOnAuthAttachedID(t *testing.T) {
	l := New(Limit{Per: time.Hour, Burst: 1})
	mux := http.NewServeMux()
	mux.Handle("POST /x", Middleware(l, KeyByUser, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	withUser := func(uid string) *http.Request {
		req := httptest.NewRequest("POST", "/x", nil)
		return req.WithContext(WithUserKey(context.Background(), uid))
	}

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, withUser("alice"))
	if rr.Code != http.StatusOK {
		t.Fatalf("alice first: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, withUser("alice"))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("alice second: %d (want 429)", rr.Code)
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, withUser("bob"))
	if rr.Code != http.StatusOK {
		t.Fatalf("bob first should pass independent of alice: %d", rr.Code)
	}
}

// TestKeyByUser_AndKeyByIP_AreIndependent mounts both limiters as
// chained middleware (matching the §5.2 production shape) and verifies
// that the per-IP and per-user buckets account independently: the same
// user from two different IPs each gets a fresh IP bucket but shares
// one user bucket; the user bucket exhausts after Burst regardless of
// IP.
func TestKeyByUser_AndKeyByIP_AreIndependent(t *testing.T) {
	ipLimiter := New(Limit{Per: time.Hour, Burst: 1})
	userLimiter := New(Limit{Per: time.Hour, Burst: 2})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Outer middleware keys by IP; inner keys by user. Both must pass.
	chained := Middleware(ipLimiter, KeyByIP, Middleware(userLimiter, KeyByUser, handler))

	do := func(ip, uid string) int {
		req := httptest.NewRequest("POST", "/x", nil)
		req.RemoteAddr = ip
		req = req.WithContext(WithUserKey(context.Background(), uid))
		rr := httptest.NewRecorder()
		chained.ServeHTTP(rr, req)
		return rr.Code
	}

	// alice from IP .1 — IP bucket fresh (consumes 1 of 1), user bucket
	// fresh (consumes 1 of 2). Pass.
	if got := do("10.0.0.1:1234", "alice"); got != http.StatusOK {
		t.Fatalf("alice from .1 first request: %d (want 200)", got)
	}
	// alice from IP .2 — IP bucket fresh on the new IP, user bucket on
	// second hit (consumes 2 of 2). Pass.
	if got := do("10.0.0.2:1234", "alice"); got != http.StatusOK {
		t.Fatalf("alice from .2: %d (want 200)", got)
	}
	// alice from IP .3 — IP bucket fresh, but user bucket is now empty.
	// Must 429.
	if got := do("10.0.0.3:1234", "alice"); got != http.StatusTooManyRequests {
		t.Fatalf("alice third request should be refused by user bucket: %d (want 429)", got)
	}
	// bob from IP .1 — IP bucket on .1 already exhausted from alice's
	// first hit. Must 429 even though bob's user bucket is fresh.
	if got := do("10.0.0.1:1234", "bob"); got != http.StatusTooManyRequests {
		t.Fatalf("bob from saturated .1 IP: %d (want 429)", got)
	}
	// bob from IP .9 — fresh on both IP and user buckets. Pass.
	if got := do("10.0.0.9:1234", "bob"); got != http.StatusOK {
		t.Fatalf("bob from fresh .9 IP: %d (want 200)", got)
	}
}

func TestSweep_EvictsIdle(t *testing.T) {
	l := New(Limit{Per: time.Second, Burst: 1})
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	_, _ = l.Allow("k")
	if len(l.keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(l.keys))
	}
	now = now.Add(10 * time.Second)
	l.Sweep()
	if len(l.keys) != 0 {
		t.Errorf("idle key should be swept, got %d", len(l.keys))
	}
}
