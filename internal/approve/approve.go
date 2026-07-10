// Package approve implements the pending-approval store behind an `ask` verdict:
// when the PDP cannot decide an action alone it opens a Pending here, notifies
// the owner (Telegram + console inbox), and the PEP polls until a human resolves
// it (allow/deny) or the TTL expires (deny, fail-safe). The store is the single
// source of truth every consumer reads and writes; it is in-memory, thread-safe,
// and optionally mirrors each pending under ~/.aarvion/pending for crash
// visibility.
//
// This package imports the standard library only.
package approve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// The three verdicts a pending can hold. A freshly opened pending is
// VerdictPending until a human (or the reaper) resolves it to allow or deny.
const (
	VerdictPending = "pending"
	VerdictAllow   = "allow"
	VerdictDeny    = "deny"
)

// whoTimeout is recorded as the resolver when the reaper denies an expired
// pending, so the audit shows the deny came from TTL expiry, not a human.
const whoTimeout = "timeout"

// Pending is one action awaiting human approval. DecisionID is the PDP-minted id
// the PEP polls on; Principal/Surface/Verb/Reason describe what is being asked
// for (so the owner sees a meaningful prompt); Created + TTL bound how long the
// request stays open before the reaper denies it.
type Pending struct {
	DecisionID string        `json:"decision_id"`
	Principal  string        `json:"principal"`
	Surface    string        `json:"surface"`
	Verb       string        `json:"verb"`
	Reason     string        `json:"reason"`
	Created    time.Time     `json:"created"`
	TTL        time.Duration `json:"ttl"`
}

// entry is the store's internal record: the opened Pending plus its current
// verdict and, once resolved, who resolved it.
type entry struct {
	pending Pending
	verdict string
	who     string
}

// Store is the in-memory pending-approval registry. All methods are safe for
// concurrent use. When mirrorDir is non-empty each state change is written
// best-effort to a per-decision JSON file so a crash leaves the pending set
// visible on disk; mirror failures never affect the in-memory outcome.
type Store struct {
	mu        sync.Mutex
	entries   map[string]*entry
	mirrorDir string
}

// NewStore builds an empty, in-memory pending store with no disk mirror.
func NewStore() *Store {
	return &Store{entries: map[string]*entry{}}
}

// NewStoreWithMirror builds a pending store that also mirrors each pending to
// dir (best-effort, 0600 files under a 0700 dir) for crash visibility. An empty
// dir disables mirroring, matching NewStore.
func NewStoreWithMirror(dir string) *Store {
	s := NewStore()
	s.mirrorDir = dir
	return s
}

// Open registers p as pending. A second Open of the same DecisionID is ignored
// so a retrying PEP can't reset an already-resolved decision back to pending.
func (s *Store) Open(p Pending) {
	s.mu.Lock()
	if _, exists := s.entries[p.DecisionID]; exists {
		s.mu.Unlock()
		return
	}
	e := &entry{pending: p, verdict: VerdictPending}
	s.entries[p.DecisionID] = e
	s.mu.Unlock()

	s.mirror(e)
}

// Resolve flips a pending to verdict ("allow" or "deny") and records who decided
// it. It returns true only for the first resolution of a still-pending id: an
// unknown id, an already-resolved id, or an invalid verdict all return false and
// change nothing. This makes it idempotent and race-safe — exactly one caller
// wins.
func (s *Store) Resolve(id, verdict, who string) bool {
	if verdict != VerdictAllow && verdict != VerdictDeny {
		return false
	}

	s.mu.Lock()
	e, ok := s.entries[id]
	if !ok || e.verdict != VerdictPending {
		s.mu.Unlock()
		return false
	}
	e.verdict = verdict
	e.who = who
	s.mu.Unlock()

	s.mirror(e)
	return true
}

// Status returns the current verdict ("pending"|"allow"|"deny") for id and
// whether the id is known. An unknown id returns ("", false).
func (s *Store) Status(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return "", false
	}
	return e.verdict, true
}

// List returns a snapshot of the still-pending approvals, oldest first (sorted
// by Created, then DecisionID for stability). Resolved entries are omitted so
// the console inbox shows only what still needs a human.
func (s *Store) List() []Pending {
	s.mu.Lock()
	out := make([]Pending, 0, len(s.entries))
	for _, e := range s.entries {
		if e.verdict == VerdictPending {
			out = append(out, e.pending)
		}
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].DecisionID < out[j].DecisionID
	})
	return out
}

// Reap denies any still-pending approval whose Created+TTL is at or before now,
// recording who="timeout". This is the fail-safe: an owner who never answers
// yields a deny, never a hang. A non-positive TTL means no expiry. Callers run
// Reap on a ticker.
func (s *Store) Reap(now time.Time) {
	var expired []*entry

	s.mu.Lock()
	for _, e := range s.entries {
		if e.verdict != VerdictPending || e.pending.TTL <= 0 {
			continue
		}
		if !now.Before(e.pending.Created.Add(e.pending.TTL)) {
			e.verdict = VerdictDeny
			e.who = whoTimeout
			expired = append(expired, e)
		}
	}
	s.mu.Unlock()

	for _, e := range expired {
		s.mirror(e)
	}
}

// mirror best-effort writes the entry's current state to the mirror dir as a
// 0600 JSON file. It is a no-op when mirroring is disabled, and any failure is
// swallowed: the in-memory store is authoritative.
func (s *Store) mirror(e *entry) {
	if s.mirrorDir == "" {
		return
	}
	if err := os.MkdirAll(s.mirrorDir, 0o700); err != nil {
		return
	}

	s.mu.Lock()
	rec := struct {
		Pending
		Verdict string `json:"verdict"`
		Who     string `json:"who,omitempty"`
	}{Pending: e.pending, Verdict: e.verdict, Who: e.who}
	s.mu.Unlock()

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	path := filepath.Join(s.mirrorDir, rec.DecisionID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
