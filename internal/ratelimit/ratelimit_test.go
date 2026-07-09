package ratelimit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixedClock is a manually advanced clock so window/eviction behavior is tested
// deterministically without sleeping.
type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time      { return c.t }
func (c *fixedClock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(limit int, window time.Duration, perHost map[string]int) (*Limiter, *fixedClock) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	l := New(limit, window, perHost)
	l.SetNow(clk.now)
	return l, clk
}

func TestAllowUnderLimit(t *testing.T) {
	l, clk := newTestLimiter(3, time.Minute, nil)
	for i := 0; i < 3; i++ {
		if !l.Allow("host.example", clk.now()) {
			t.Fatalf("request %d should be allowed (under limit)", i+1)
		}
	}
}

func TestDenyOverLimit(t *testing.T) {
	l, clk := newTestLimiter(3, time.Minute, nil)
	for i := 0; i < 3; i++ {
		if !l.Allow("host.example", clk.now()) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	// The 4th within the same window is over the ceiling.
	if l.Allow("host.example", clk.now()) {
		t.Fatal("4th request in the window should be denied (over limit)")
	}
	// And it stays denied while the window holds.
	if l.Allow("host.example", clk.now()) {
		t.Fatal("still over limit within the same window")
	}
}

func TestWindowResetsAfterPeriod(t *testing.T) {
	l, clk := newTestLimiter(2, time.Minute, nil)
	if !l.Allow("h", clk.now()) || !l.Allow("h", clk.now()) {
		t.Fatal("first two should be allowed")
	}
	if l.Allow("h", clk.now()) {
		t.Fatal("third should be denied within the window")
	}
	// Roll past the window: the counter resets and requests flow again.
	clk.add(time.Minute)
	if !l.Allow("h", clk.now()) {
		t.Fatal("request after the window rolled should be allowed")
	}
	if !l.Allow("h", clk.now()) {
		t.Fatal("second request in the fresh window should be allowed")
	}
	if l.Allow("h", clk.now()) {
		t.Fatal("third in the fresh window should be denied again")
	}
}

func TestPerHostOverride(t *testing.T) {
	// Default ceiling 1; api.slow gets a tighter 0 (disabled → unlimited per the
	// contract), api.fast gets a looser 5.
	l, clk := newTestLimiter(1, time.Minute, map[string]int{"api.fast": 5, "api.unlimited": 0})

	// Default host: 1 allowed, 2nd denied.
	if !l.Allow("api.default", clk.now()) {
		t.Fatal("default host first request allowed")
	}
	if l.Allow("api.default", clk.now()) {
		t.Fatal("default host second request denied (ceiling 1)")
	}

	// Override host: 5 allowed, 6th denied.
	for i := 0; i < 5; i++ {
		if !l.Allow("api.fast", clk.now()) {
			t.Fatalf("api.fast request %d should be allowed (override 5)", i+1)
		}
	}
	if l.Allow("api.fast", clk.now()) {
		t.Fatal("api.fast 6th request should be denied")
	}

	// Zero override disables limiting for that host entirely.
	for i := 0; i < 50; i++ {
		if !l.Allow("api.unlimited", clk.now()) {
			t.Fatalf("api.unlimited request %d should always be allowed (override 0)", i+1)
		}
	}
}

func TestIdleKeyEviction(t *testing.T) {
	l, clk := newTestLimiter(1, time.Minute, nil)

	// Touch a batch of distinct hosts, then let them all go idle.
	for i := 0; i < 100; i++ {
		l.Allow(fmt.Sprintf("host-%d.example", i), clk.now())
	}
	if got := l.Len(); got != 100 {
		t.Fatalf("expected 100 live keys, got %d", got)
	}

	// Advance well past the idle window, then poke a single new key: the sweep on
	// that Allow reclaims every stale key so the map doesn't grow unbounded.
	clk.add(idleWindows*time.Minute + time.Second)
	l.Allow("fresh.example", clk.now())
	if got := l.Len(); got != 1 {
		t.Fatalf("idle keys not evicted: expected 1 live key, got %d", got)
	}
}

func TestActiveKeyNotEvicted(t *testing.T) {
	l, clk := newTestLimiter(5, time.Minute, nil)
	// A key touched every window must survive the eviction sweep.
	for i := 0; i < 10; i++ {
		l.Allow("busy.example", clk.now())
		clk.add(time.Minute) // roll into a new window each time, key stays active
	}
	if l.Len() != 1 {
		t.Fatalf("actively-used key was evicted: live keys = %d", l.Len())
	}
}

func TestDisabledLimiterAlwaysAllows(t *testing.T) {
	// Non-positive default limit → limiter is a no-op, never tracks a key.
	l, clk := newTestLimiter(0, time.Minute, nil)
	for i := 0; i < 1000; i++ {
		if !l.Allow("anything", clk.now()) {
			t.Fatal("a disabled limiter must allow everything")
		}
	}
	if l.Len() != 0 {
		t.Fatalf("disabled limiter should track no keys, got %d", l.Len())
	}
}

// TestConcurrentAllow exercises the lock under -race: many goroutines hammering
// a shared key must see exactly `limit` allows and no data race.
func TestConcurrentAllow(t *testing.T) {
	const limit = 100
	const goroutines = 50
	const perG = 20 // 50*20 = 1000 attempts, well over the ceiling

	l, clk := newTestLimiter(limit, time.Minute, nil)
	now := clk.now()

	var allowed int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				if l.Allow("shared.example", now) {
					atomic.AddInt64(&allowed, 1)
				}
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&allowed); got != limit {
		t.Fatalf("concurrent allows = %d, want exactly %d", got, limit)
	}
}

// TestConcurrentDistinctKeys races distinct keys through the map + eviction
// sweep to shake out any concurrent-map access under -race.
func TestConcurrentDistinctKeys(t *testing.T) {
	l, clk := newTestLimiter(5, time.Minute, nil)
	now := clk.now()
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				l.Allow(fmt.Sprintf("g%d-h%d", g, i%7), now)
			}
		}(g)
	}
	wg.Wait()
}
