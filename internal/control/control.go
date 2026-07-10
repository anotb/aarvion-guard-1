// Package control provides two file-driven emergency levers a fleet operator
// can pull WITHOUT a control-plane round-trip or a guard restart:
//
//   - Kill-switch (freeze): touch the freeze file and the guard hard-denies ALL
//     egress within one poll interval — including the essential/LLM hosts that
//     the fail-closed posture would otherwise keep reachable. A hijacked agent is
//     fully stopped, brain and all.
//   - Break-glass: touch the break-glass file to open a time-boxed, fully-audited
//     bypass (allow everything, but every request tagged so the bypass shows up in
//     the audit). It auto-expires window after the file's mtime, so a forgotten
//     bypass closes itself; re-touching the file extends it.
//
// A Controller polls the two control files on a ticker and keeps atomic state so
// the decision hot path reads it with a single load. The zero value / a nil
// *Controller is disabled and reports false for both levers, so an install that
// doesn't configure control pays zero overhead and behaves exactly as before.
package control

import (
	"context"
	"os"
	"sync/atomic"
	"time"
)

// defaultPollEvery is how often the control files are stat'd when the config
// doesn't set poll_every_seconds.
const defaultPollEvery = 2 * time.Second

// defaultWindow is how long a break-glass bypass stays active after the file's
// mtime when the config doesn't set break_glass_minutes.
const defaultWindow = 15 * time.Minute

// Controller watches two control files and exposes fast, lock-free reads of the
// current emergency state. Frozen is a boolean latch (file present ⇒ frozen);
// break-glass is time-boxed (active until the file's mtime + window), so the
// Controller stores the raw deadline and evaluates it against the clock on every
// read — that keeps re-touching the file (which moves its mtime forward) an
// instant extension without any extra bookkeeping.
//
// Construct with New; the zero value is a valid disabled controller (both levers
// read false).
type Controller struct {
	freezeFile     string
	breakGlassFile string
	window         time.Duration
	pollEvery      time.Duration
	now            func() time.Time

	frozen atomic.Bool
	// breakGlassUntil holds the break-glass deadline (unix nanoseconds) as of the
	// last poll, or 0 when the file is absent. It's compared to the current time
	// on each read so expiry needs no timer.
	breakGlassUntil atomic.Int64
}

// New builds a Controller that polls freezeFile and breakGlassFile every
// pollEvery, treating a present break-glass file as active for window after its
// mtime. Non-positive pollEvery or window fall back to sensible defaults. The
// returned Controller reports false for both levers until Run (or Refresh) does
// its first poll.
func New(freezeFile, breakGlassFile string, window, pollEvery time.Duration) *Controller {
	if pollEvery <= 0 {
		pollEvery = defaultPollEvery
	}
	if window <= 0 {
		window = defaultWindow
	}
	return &Controller{
		freezeFile:     freezeFile,
		breakGlassFile: breakGlassFile,
		window:         window,
		pollEvery:      pollEvery,
		now:            time.Now,
	}
}

// setNow overrides the clock, for tests. Set it once right after New, before Run.
func (c *Controller) setNow(fn func() time.Time) { c.now = fn }

// Frozen reports whether the kill-switch is engaged (freeze file present as of
// the last poll). A nil Controller is disabled and returns false.
func (c *Controller) Frozen() bool {
	if c == nil {
		return false
	}
	return c.frozen.Load()
}

// BreakGlass reports whether a break-glass bypass is currently active: the file
// was present at the last poll AND its mtime + window has not yet elapsed as of
// now. Evaluated against the clock on every call, so a window expires between
// polls without waiting for the next stat. A nil Controller returns false.
func (c *Controller) BreakGlass() bool {
	if c == nil {
		return false
	}
	until := c.breakGlassUntil.Load()
	if until == 0 {
		return false
	}
	return c.now().UnixNano() < until
}

// Refresh polls both control files once and updates the atomic state. Run calls
// it on the ticker; tests call it directly to step the state deterministically.
// A stat error other than "not found" is treated as "file absent" — a control
// file we can't read must not silently latch the guard into a wrong state.
func (c *Controller) Refresh() {
	c.frozen.Store(fileExists(c.freezeFile))

	if mtime, ok := fileMtime(c.breakGlassFile); ok {
		c.breakGlassUntil.Store(mtime.Add(c.window).UnixNano())
	} else {
		c.breakGlassUntil.Store(0)
	}
}

// Run polls the control files every pollEvery until ctx is cancelled. It does an
// immediate Refresh first so the state is correct before the first tick, rather
// than reading false for one interval. Start it in a goroutine.
func (c *Controller) Run(ctx context.Context) {
	c.Refresh()
	t := time.NewTicker(c.pollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Refresh()
		}
	}
}

// fileExists reports whether path names an existing file. An empty path (lever
// unconfigured) is never present.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// fileMtime returns the modification time of path, and false when the path is
// empty or cannot be stat'd (absent / unreadable). Reading the mtime each poll is
// what lets a re-touch extend the break-glass window.
func fileMtime(path string) (time.Time, bool) {
	if path == "" {
		return time.Time{}, false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}
