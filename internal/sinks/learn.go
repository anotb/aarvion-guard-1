package sinks

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
)

// defaultLearnInterval is how often the proposal file is rewritten when the
// config doesn't set write_every_seconds.
const defaultLearnInterval = 30 * time.Second

// hostStat is the running tally for one distinct destination host.
type hostStat struct {
	Host      string `json:"host"`
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Allow     int    `json:"allow"`
	Deny      int    `json:"deny"`
}

// proposal is the on-disk shape: a report the operator reviews, plus a
// ready-to-paste suggested_allowlist (the sorted distinct host set) that drops
// straight into the existing allowlist.hosts config.
type proposal struct {
	GeneratedAt        string     `json:"generated_at"`
	Observed           int        `json:"observed"`
	Hosts              []hostStat `json:"hosts"`
	SuggestedAllowlist []string   `json:"suggested_allowlist"`
}

// LearnSink is a learn-mode observer: it watches real egress and tallies every
// distinct destination host it sees (request count, first/last seen, and an
// allow/deny breakdown), then periodically writes a *proposed allowlist* the
// operator reviews-and-promotes instead of hand-authoring. It exists to make
// default-deny (the allowlist gate) usable: turn it on in observe mode, run a
// normal workload, and read off the hosts to approve.
//
// Record is on the decision path (called under the Recorder lock), so it only
// updates an in-memory map under a mutex - never touches disk. The proposal file
// is written off the hot path by a ticker goroutine and once more on Close.
type LearnSink struct {
	path     string
	interval time.Duration

	mu    sync.Mutex
	hosts map[string]*hostStat

	// writeMu serializes proposal writes so the ticker goroutine and a concurrent
	// Close never race on the temp file + rename.
	writeMu sync.Mutex

	stop    chan struct{}
	closeMu sync.Mutex
	closed  bool
}

// NewLearn builds a learn observer that writes its proposal to path every
// interval (a non-positive interval falls back to the default). The caller must
// Run its ticker (sharing ctx) and Close it on shutdown to force a final write.
func NewLearn(path string, interval time.Duration) *LearnSink {
	if interval <= 0 {
		interval = defaultLearnInterval
	}
	return &LearnSink{
		path:     path,
		interval: interval,
		hosts:    map[string]*hostStat{},
		stop:     make(chan struct{}),
	}
}

// Record is the decisions.Sink hook. Non-blocking: it only updates the in-memory
// tally under the mutex. Rows without a host (nothing to allowlist) are skipped.
func (s *LearnSink) Record(rec decisions.Record) {
	if rec.Host == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	st := s.hosts[rec.Host]
	if st == nil {
		st = &hostStat{Host: rec.Host, FirstSeen: rec.Timestamp}
		s.hosts[rec.Host] = st
	}
	st.Count++
	// Timestamps arrive monotonically on the decision path, but guard against an
	// empty first row and keep last_seen as the latest non-empty stamp.
	if st.FirstSeen == "" {
		st.FirstSeen = rec.Timestamp
	}
	if rec.Timestamp != "" {
		st.LastSeen = rec.Timestamp
	}
	switch rec.Decision {
	case "allow":
		st.Allow++
	case "deny":
		st.Deny++
	}
}

// Run writes the proposal on a ticker until ctx is cancelled or Close is called,
// then returns. It does NOT write a final proposal itself - Close owns that, so a
// single final write happens whether shutdown comes via ctx (then Close) or Close
// alone. Start it in a goroutine.
func (s *LearnSink) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-t.C:
			_ = s.write()
		}
	}
}

// snapshot builds a stable, sorted proposal from the current tally. Held under
// the lock only long enough to copy the values out; the write happens after.
func (s *LearnSink) snapshot() proposal {
	s.mu.Lock()
	hosts := make([]hostStat, 0, len(s.hosts))
	suggested := make([]string, 0, len(s.hosts))
	for _, st := range s.hosts {
		hosts = append(hosts, *st)
		suggested = append(suggested, st.Host)
	}
	s.mu.Unlock()

	// Deterministic output: hosts by name, and suggested_allowlist is the sorted
	// distinct host set (ready to paste into allowlist.hosts).
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	sort.Strings(suggested)

	return proposal{
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
		Observed:           len(hosts),
		Hosts:              hosts,
		SuggestedAllowlist: suggested,
	}
}

// write serializes the current proposal and writes it atomically-ish at 0600. A
// temp-file rename keeps a reader from ever seeing a half-written file. writeMu
// serializes concurrent writers (ticker vs. Close) so they don't clobber the
// shared temp file.
func (s *LearnSink) write() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	p := s.snapshot()
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Close stops the ticker goroutine and forces one final proposal write so the
// last observations aren't lost. Safe to call more than once.
func (s *LearnSink) Close() error {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	s.closeMu.Unlock()

	return s.write()
}
