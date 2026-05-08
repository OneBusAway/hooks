// Package ratelimit provides an in-process token-bucket-per-key middleware
// for the auth surfaces (login, signup, device pairing). Buckets live in
// process memory and are GC'd on idle; on restart they reset to full,
// which is acceptable for a single-process SQLite deployment. A future
// Postgres/Redis backend can swap the implementation behind the same
// middleware contract.
package ratelimit

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Limit names a per-period quota.
type Limit struct {
	Per    time.Duration
	Burst  int
}

// String renders the limit as a debug-friendly hint.
func (l Limit) String() string {
	return strconv.Itoa(l.Burst) + "/" + l.Per.String()
}

// KeyFunc derives a bucket key from the request. Two builtin variants:
// KeyByIP (best-effort RemoteAddr) and KeyByUser (auth-attached user).
type KeyFunc func(r *http.Request) string

// KeyByIP keys buckets by the request's client IP. Strips :port. Returns
// an empty string for malformed RemoteAddr (which causes the request to
// bypass — there is no "anonymous" rate-limit class today).
func KeyByIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Limiter is a single-key token-bucket rate limiter. It is concurrency
// safe; buckets are evicted after 2*Per of idleness.
type Limiter struct {
	limits []Limit
	mu     sync.Mutex
	now    func() time.Time
	keys   map[string]*bucketSet
}

// New returns a Limiter that enforces every Limit in limits per key.
func New(limits ...Limit) *Limiter {
	return &Limiter{
		limits: limits,
		now:    time.Now,
		keys:   map[string]*bucketSet{},
	}
}

// Allow consumes one token for key. The caller receives (allowed,
// retryAfter) where retryAfter is the duration until the most-restrictive
// bucket would be allowed to refill; 0 when allowed.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	bs, ok := l.keys[key]
	now := l.now()
	if !ok {
		bs = &bucketSet{buckets: make([]bucket, len(l.limits))}
		for i, lim := range l.limits {
			bs.buckets[i] = bucket{tokens: float64(lim.Burst), updated: now}
		}
		l.keys[key] = bs
	}
	bs.lastSeen = now

	// Refill every bucket; refusal returns the largest retry-after among
	// limits we'd have to wait on.
	var maxWait time.Duration
	allowed := true
	for i, lim := range l.limits {
		b := &bs.buckets[i]
		elapsed := now.Sub(b.updated)
		rate := float64(lim.Burst) / lim.Per.Seconds()
		b.tokens += elapsed.Seconds() * rate
		if b.tokens > float64(lim.Burst) {
			b.tokens = float64(lim.Burst)
		}
		b.updated = now
		if b.tokens < 1 {
			allowed = false
			deficit := 1 - b.tokens
			wait := time.Duration(deficit / rate * float64(time.Second))
			if wait > maxWait {
				maxWait = wait
			}
		}
	}
	if !allowed {
		return false, maxWait
	}
	for i := range l.limits {
		bs.buckets[i].tokens--
	}
	return true, 0
}

// Sweep evicts entries that have been idle for more than 2*max(Per).
func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var idle time.Duration
	for _, lim := range l.limits {
		if 2*lim.Per > idle {
			idle = 2 * lim.Per
		}
	}
	for k, bs := range l.keys {
		if now.Sub(bs.lastSeen) > idle {
			delete(l.keys, k)
		}
	}
}

type bucketSet struct {
	buckets  []bucket
	lastSeen time.Time
}

type bucket struct {
	tokens  float64
	updated time.Time
}

// Middleware returns an http.Handler middleware that consumes one token
// per request, keyed by keyFn. On rejection the response is HTTP 429 with
// a Retry-After header (rounded up to a whole second).
func Middleware(l *Limiter, keyFn KeyFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := keyFn(r)
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		ok, retry := l.Allow(key)
		if !ok {
			secs := int((retry + time.Second - 1) / time.Second)
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
