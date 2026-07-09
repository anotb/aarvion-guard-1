// Package ratelimit is an in-guard, per-key request-rate ceiling evaluated
// cheaply in memory before OPA. It exists to stop a runaway agent (a loop
// hammering an LLM/API endpoint) from burning a bill or earning a rate-ban:
// the guard denies egress once a destination host crosses its per-window limit.
//
// It keys on the destination host (a string), so it works host-level and thus
// functions even in no-inspect mode where there is no MITM. The window is a
// simple fixed-window counter per key: cheap, bounded, and good enough for a
// runaway guardrail (the exact boundary semantics of a sliding window aren't
// worth the extra state for "stop the loop").
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a thread-safe, per-key fixed-window request counter. A key (the
// destination host) is allowed up to a per-window limit; the count resets when
// the window rolls over. Idle keys are evicted so a flood of distinct hosts
// can't grow the map unbounded.
//
// The zero value is not usable; construct with New.
type Limiter struct {
	limit  int           // default per-window ceiling
	window time.Duration // window length (e.g. 60s)
	perKey map[string]int
	nowFn  func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

// bucket is one key's current window: the window-start instant and the number
// of hits recorded since it opened. lastSeen drives idle eviction.
type bucket struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time
}

// New builds a Limiter allowing limit requests per window for every key, with
// perKey overriding the default for named keys (a nil or empty map means "use
// the default for all"). A non-positive limit or window makes every Allow
// return true (the limiter is effectively off), matching the "disabled = zero
// overhead" posture the caller relies on.
func New(limit int, window time.Duration, perKey map[string]int) *Limiter {
	cp := make(map[string]int, len(perKey))
	for k, v := range perKey {
		cp[k] = v
	}
	return &Limiter{
		limit:   limit,
		window:  window,
		perKey:  cp,
		nowFn:   time.Now,
		buckets: make(map[string]*bucket),
	}
}

// SetNow overrides the clock, for tests. Not safe to call concurrently with
// Allow; set it once immediately after New.
func (l *Limiter) SetNow(fn func() time.Time) { l.nowFn = fn }

// limitFor returns the effective ceiling for a key: its per-key override if set,
// else the default.
func (l *Limiter) limitFor(key string) int {
	if v, ok := l.perKey[key]; ok {
		return v
	}
	return l.limit
}

// Allow reports whether a request to key at now is under its per-window ceiling,
// recording the hit when it is. It returns true (allowed) and does NOT count the
// request when the request is over the limit, so a rejected flood doesn't keep
// the window pinned open forever — the window still rolls on the wall clock.
//
// A non-positive effective limit or window disables limiting for the key
// (always allowed, nothing recorded), so an unconfigured limiter is free.
func (l *Limiter) Allow(key string, now time.Time) bool {
	limit := l.limitFor(key)
	if limit <= 0 || l.window <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.evictIdle(now)

	b := l.buckets[key]
	if b == nil || now.Sub(b.windowStart) >= l.window {
		// First hit, or the prior window has fully elapsed: open a fresh window.
		l.buckets[key] = &bucket{windowStart: now, count: 1, lastSeen: now}
		return true
	}
	b.lastSeen = now
	if b.count >= limit {
		return false
	}
	b.count++
	return true
}

// idleWindows is how many windows a key may sit untouched before it's evicted.
// A few windows of grace means a key that resumes within the same rough period
// keeps its window; a truly idle key (a one-off host in a distinct-host flood)
// is reclaimed so the map stays bounded.
const idleWindows = 3

// evictIdle drops keys not seen within idleWindows windows (caller holds the
// lock). It's O(map) but only runs on the Allow path, where the map is already
// bounded by this same eviction, so the sweep stays cheap.
func (l *Limiter) evictIdle(now time.Time) {
	cutoff := time.Duration(idleWindows) * l.window
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) >= cutoff {
			delete(l.buckets, k)
		}
	}
}

// Len returns the number of live keys currently tracked. For tests/introspection.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
