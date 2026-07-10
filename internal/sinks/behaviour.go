package sinks

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/normalize"
)

// defaultBehaviourInterval is how often the behaviour profile is rewritten when
// the caller passes a non-positive interval.
const defaultBehaviourInterval = 30 * time.Second

// maxProfileTargets caps the distinct targets tracked per {principal,surface,
// verb} key. Once the cap is hit new distinct targets are dropped (existing ones
// keep counting) so a chatty agent can't grow the profile unbounded.
const maxProfileTargets = 50

// ProfileEntry is the running behaviour tally for one {principal,surface,verb}
// key: how often the agent took this action, which targets it hit (bounded),
// when in the day (hour histogram), when last seen, and how many times the
// action WOULD be blocked by policy (a deny/ask would-be verdict). B5 imports
// this to derive tightened packs from observed behaviour.
type ProfileEntry struct {
	Principal  string         `json:"principal"`
	Surface    string         `json:"surface"`
	Verb       string         `json:"verb"`
	Count      int            `json:"count"`
	Targets    map[string]int `json:"targets,omitempty"`
	Hours      [24]int        `json:"hours"`
	LastSeen   string         `json:"last_seen"`
	WouldBlock int            `json:"would_block"`
}

// Profile is a deterministic snapshot of the behaviour observer: every observed
// {principal,surface,verb} entry, sorted for stable output. Exported so the
// console renders it and internal/packs (B5) proposes packs from it.
type Profile struct {
	GeneratedAt string         `json:"generated_at"`
	Entries     []ProfileEntry `json:"entries"`
}

// profileKey is the internal map key: the {principal,surface,verb} tuple.
type profileKey struct {
	Principal string
	Surface   string
	Verb      string
}

// Behaviour is a learn-mode behaviour observer. It implements
// govern.BehaviourObserver: the PDP calls Observe once per governed decision,
// and Behaviour tallies what each agent actually does per {principal,surface,
// verb}. It persists a profile to disk on an interval and once more on Close, so
// the console and the propose step can derive tightened packs from real usage.
//
// Observe is on the decision path (called under the Recorder lock indirectly),
// so it only mutates an in-memory map under a mutex - never touches disk. The
// profile file is written off the hot path by a ticker goroutine and on Close.
type Behaviour struct {
	path     string
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[profileKey]*ProfileEntry

	// writeMu serializes profile writes so the ticker goroutine and a concurrent
	// Close never race on the temp file + rename.
	writeMu sync.Mutex

	stop    chan struct{}
	closeMu sync.Mutex
	closed  bool
}

// NewBehaviour builds a behaviour observer that persists its profile to path
// every interval (a non-positive interval falls back to the default). The caller
// must Run its ticker (sharing ctx) and Close it on shutdown to force a final
// write.
func NewBehaviour(path string, interval time.Duration) *Behaviour {
	if interval <= 0 {
		interval = defaultBehaviourInterval
	}
	return &Behaviour{
		path:     path,
		interval: interval,
		now:      time.Now,
		entries:  map[profileKey]*ProfileEntry{},
		stop:     make(chan struct{}),
	}
}

// Observe is the govern.BehaviourObserver hook. Non-blocking: it only updates
// the in-memory tally under the mutex. wouldBe is the would-be verdict
// ("allow"|"ask"|"deny"); a deny/ask counts toward would_block whether or not it
// was enforced, since either represents policy that WOULD gate this behaviour.
func (b *Behaviour) Observe(sem normalize.Action, principal, wouldBe string, enforced bool) {
	key := profileKey{Principal: principal, Surface: sem.Surface, Verb: sem.Verb}
	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()

	e := b.entries[key]
	if e == nil {
		e = &ProfileEntry{
			Principal: principal,
			Surface:   sem.Surface,
			Verb:      sem.Verb,
			Targets:   map[string]int{},
		}
		b.entries[key] = e
	}
	e.Count++
	e.Hours[now.Hour()%24]++
	e.LastSeen = now.UTC().Format(time.RFC3339)
	if wouldBe == "deny" || wouldBe == "ask" {
		e.WouldBlock++
	}
	for _, t := range sem.Targets {
		if t == "" {
			continue
		}
		if _, seen := e.Targets[t]; !seen && len(e.Targets) >= maxProfileTargets {
			continue // bounded: drop new distinct targets past the cap
		}
		e.Targets[t]++
	}
}

// Profile returns a deterministic snapshot of the current tally, sorted by
// principal/surface/verb. Exported for the console and the propose step.
func (b *Behaviour) Profile() Profile {
	b.mu.Lock()
	entries := make([]ProfileEntry, 0, len(b.entries))
	for _, e := range b.entries {
		// Copy the entry and its target map so callers can't mutate live state.
		cp := *e
		if e.Targets != nil {
			cp.Targets = make(map[string]int, len(e.Targets))
			for k, v := range e.Targets {
				cp.Targets[k] = v
			}
		}
		entries = append(entries, cp)
	}
	b.mu.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		a, c := entries[i], entries[j]
		if a.Principal != c.Principal {
			return a.Principal < c.Principal
		}
		if a.Surface != c.Surface {
			return a.Surface < c.Surface
		}
		return a.Verb < c.Verb
	})

	return Profile{
		GeneratedAt: b.now().UTC().Format(time.RFC3339),
		Entries:     entries,
	}
}

// Run writes the profile on a ticker until ctx is cancelled or Close is called,
// then returns. It does NOT write a final profile itself - Close owns that, so a
// single final write happens whether shutdown comes via ctx (then Close) or Close
// alone. Start it in a goroutine.
func (b *Behaviour) Run(ctx context.Context) {
	t := time.NewTicker(b.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stop:
			return
		case <-t.C:
			_ = b.write()
		}
	}
}

// write serializes the current profile and writes it atomically-ish at 0600. A
// temp-file rename keeps a reader from ever seeing a half-written file. writeMu
// serializes concurrent writers (ticker vs. Close).
func (b *Behaviour) write() error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	p := b.Profile()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}

// Close stops the ticker goroutine and forces one final profile write so the
// last observations aren't lost. Safe to call more than once.
func (b *Behaviour) Close() error {
	b.closeMu.Lock()
	if b.closed {
		b.closeMu.Unlock()
		return nil
	}
	b.closed = true
	close(b.stop)
	b.closeMu.Unlock()

	return b.write()
}
