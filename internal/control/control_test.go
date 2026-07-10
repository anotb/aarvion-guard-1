package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A present freeze file latches Frozen; removing it clears on the next Refresh.
func TestFrozenTracksFile(t *testing.T) {
	dir := t.TempDir()
	freeze := filepath.Join(dir, "freeze")
	c := New(freeze, "", time.Minute, time.Second)

	c.Refresh()
	if c.Frozen() {
		t.Fatal("no freeze file → not frozen")
	}

	touch(t, freeze)
	c.Refresh()
	if !c.Frozen() {
		t.Fatal("freeze file present → frozen")
	}

	if err := os.Remove(freeze); err != nil {
		t.Fatal(err)
	}
	c.Refresh()
	if c.Frozen() {
		t.Fatal("freeze file removed → not frozen after refresh")
	}
}

// Break-glass is active only within the window after the file's mtime, and the
// window is evaluated against the clock on every read (no re-poll needed to
// expire). The clock is injected and the mtime pinned with Chtimes so the
// boundaries are exact.
func TestBreakGlassWindowAndExpiry(t *testing.T) {
	dir := t.TempDir()
	bg := filepath.Join(dir, "breakglass")

	base := time.Unix(1_700_000_000, 0)
	now := base
	c := New("", bg, 15*time.Minute, time.Second)
	c.setNow(func() time.Time { return now })

	c.Refresh()
	if c.BreakGlass() {
		t.Fatal("no break-glass file → inactive")
	}

	touch(t, bg)
	if err := os.Chtimes(bg, base, base); err != nil {
		t.Fatal(err)
	}
	c.Refresh()

	// Just inside the window → active.
	now = base.Add(14 * time.Minute)
	if !c.BreakGlass() {
		t.Fatal("within window → active")
	}
	// Past the window → expired with no intervening Refresh.
	now = base.Add(16 * time.Minute)
	if c.BreakGlass() {
		t.Fatal("past window → expired")
	}
}

// Re-touching the break-glass file moves its mtime forward, which reopens the
// window on the next Refresh — a forgotten bypass closes itself, but an operator
// can keep extending it.
func TestBreakGlassRetouchExtends(t *testing.T) {
	dir := t.TempDir()
	bg := filepath.Join(dir, "breakglass")

	base := time.Unix(1_700_000_000, 0)
	now := base
	c := New("", bg, 15*time.Minute, time.Second)
	c.setNow(func() time.Time { return now })

	touch(t, bg)
	if err := os.Chtimes(bg, base, base); err != nil {
		t.Fatal(err)
	}
	now = base.Add(20 * time.Minute) // 20m after touch, window (15m) has closed
	c.Refresh()
	if c.BreakGlass() {
		t.Fatal("window should be closed 20m after the original touch")
	}

	// Re-touch to "now": the window reopens for another 15m.
	if err := os.Chtimes(bg, now, now); err != nil {
		t.Fatal(err)
	}
	c.Refresh()
	if !c.BreakGlass() {
		t.Fatal("re-touch must reopen the break-glass window")
	}
	// And it closes again 15m after the new mtime.
	now = now.Add(16 * time.Minute)
	if c.BreakGlass() {
		t.Fatal("re-touched window must expire 15m after the new mtime")
	}
}

// Run must do its first Refresh immediately (before the ticker), so the state is
// correct without waiting a whole poll interval.
func TestRunRefreshesImmediately(t *testing.T) {
	dir := t.TempDir()
	freeze := filepath.Join(dir, "freeze")
	touch(t, freeze)

	// A 1h poll interval means only the immediate Refresh can flip the state
	// within the test's lifetime.
	c := New(freeze, "", time.Minute, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for !c.Frozen() {
		if time.Now().After(deadline) {
			t.Fatal("Run should Refresh immediately, before the first (1h) tick")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A nil *Controller is a valid disabled controller: both levers read false and
// nothing panics.
func TestNilControllerDisabled(t *testing.T) {
	var c *Controller
	if c.Frozen() {
		t.Fatal("nil controller must not be frozen")
	}
	if c.BreakGlass() {
		t.Fatal("nil controller must not be in break-glass")
	}
}

// New must fall back to sane defaults for non-positive window/poll so a partial
// config can't produce a 0-length break-glass window or a busy-spin ticker.
func TestNewDefaultsOnNonPositive(t *testing.T) {
	c := New("f", "b", 0, 0)
	if c.window != defaultWindow {
		t.Fatalf("window = %v, want default %v", c.window, defaultWindow)
	}
	if c.pollEvery != defaultPollEvery {
		t.Fatalf("pollEvery = %v, want default %v", c.pollEvery, defaultPollEvery)
	}
}
