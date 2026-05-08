package ratelimit

import (
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
