package sinks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
)

func denyRow(path string) decisions.Record {
	return decisions.Record{
		Timestamp: "2026-07-09T00:00:00Z",
		Method:    "POST",
		Host:      "api.github.com",
		Path:      path,
		Decision:  "deny",
		PolicyID:  "pol-1",
		Reason:    "blocked",
		Origin:    decisions.OriginProxy,
		Seq:       1,
		RowHash:   "abc",
	}
}

// The JSONL sink must append exactly one valid-JSON line per decision, and the
// file must be created 0600.
func TestJSONLWritesOneLinePerDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL: %v", err)
	}

	s.Record(denyRow("/a"))
	s.Record(denyRow("/b"))
	s.Record(denyRow("/c"))
	if err := s.Close(); err != nil { // Close drains + flushes
		t.Fatalf("Close: %v", err)
	}

	// File mode must be 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: got %v want 0600", fi.Mode().Perm())
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	var lines int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines++
		var rec decisions.Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", lines, err, sc.Text())
		}
		if rec.Decision != "deny" {
			t.Fatalf("line %d wrong decision: %q", lines, rec.Decision)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if lines != 3 {
		t.Fatalf("line count: got %d want 3", lines)
	}
}

// The JSONL sink appends to (does not truncate) an existing file, so a restart
// keeps the prior forensic history.
func TestJSONLAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")

	s1, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL: %v", err)
	}
	s1.Record(denyRow("/a"))
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	s2.Record(denyRow("/b"))
	if err := s2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := strings.Count(string(b), "\n"); n != 2 {
		t.Fatalf("append lost history: got %d lines want 2", n)
	}
}

// Close is idempotent.
func TestJSONLCloseIdempotent(t *testing.T) {
	s, err := NewJSONL(filepath.Join(t.TempDir(), "d.jsonl"))
	if err != nil {
		t.Fatalf("NewJSONL: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// The webhook must fire on a deny (POSTing the small JSON payload to the URL)
// and must NOT fire on an allow.
func TestWebhookFiresOnDenyNotOnAllow(t *testing.T) {
	var (
		mu     sync.Mutex
		hits   int
		bodies [][]byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		hits++
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewWebhook(srv.URL)

	// An allow must NOT fire.
	s.Record(decisions.Record{Method: "GET", Host: "h", Path: "/ok", Decision: "allow"})
	// A deny must fire.
	s.Record(denyRow("/blocked"))

	s.Close() // drains queued posts before returning

	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("webhook fired %d times, want exactly 1 (deny only)", hits)
	}
	var p denyPayload
	if err := json.Unmarshal(bodies[0], &p); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if p.Decision != "deny" || p.Path != "/blocked" || p.Host != "api.github.com" {
		t.Fatalf("payload wrong: %+v", p)
	}
	if p.PolicyID != "pol-1" || p.Reason != "blocked" || p.Origin != decisions.OriginProxy {
		t.Fatalf("payload missing fields: %+v", p)
	}
	if p.Timestamp == "" || p.Method != "POST" {
		t.Fatalf("payload missing method/timestamp: %+v", p)
	}
}

// Webhook Close is idempotent.
func TestWebhookCloseIdempotent(t *testing.T) {
	s := NewWebhook("http://127.0.0.1:0")
	s.Close()
	s.Close()
}

// statsStub is a fixed StatsSource for asserting the metrics text.
type statsStub struct{ total, denies, errors, dropped int }

func (s statsStub) Stats() (int, int, int, int) {
	return s.total, s.denies, s.errors, s.dropped
}

// The metrics text must contain the four counters with their correct values,
// plus aarvion_guard_up 1.
func TestMetricsTextContainsCounters(t *testing.T) {
	var buf bytes.Buffer
	writeMetrics(&buf, 12, 3, 1, 2)
	out := buf.String()

	want := []string{
		"aarvion_guard_decisions_total 12",
		"aarvion_guard_denies_total 3",
		"aarvion_guard_errors_total 1",
		"aarvion_guard_dropped_total 2",
		"aarvion_guard_up 1",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Fatalf("metrics output missing %q\n---\n%s", w, out)
		}
	}
	// Every metric line must be preceded by HELP/TYPE comments.
	for _, name := range []string{
		"aarvion_guard_decisions_total", "aarvion_guard_denies_total",
		"aarvion_guard_errors_total", "aarvion_guard_dropped_total", "aarvion_guard_up",
	} {
		if !strings.Contains(out, "# HELP "+name+" ") {
			t.Fatalf("missing HELP for %s", name)
		}
		if !strings.Contains(out, "# TYPE "+name+" ") {
			t.Fatalf("missing TYPE for %s", name)
		}
	}
}

// The metrics HTTP endpoint serves live counters over /metrics and shuts down
// cleanly when its context is cancelled. Binds an ephemeral port so the test is
// hermetic and never collides with a fixed port.
func TestMetricsServerServesAndShutsDown(t *testing.T) {
	src := statsStub{total: 5, denies: 2, errors: 0, dropped: 1}

	// Grab a free loopback port, then hand it to the server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	server := NewMetrics(addr, src, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx) }()

	// Poll until the endpoint answers.
	var body string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, "aarvion_guard_decisions_total 5") {
		t.Fatalf("served metrics missing live counter\n%s", body)
	}
	if !strings.Contains(body, "aarvion_guard_up 1") {
		t.Fatalf("served metrics missing up gauge\n%s", body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned error on shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not shut down after ctx cancel")
	}
}

// Multi fans a row out to every member.
func TestMultiFansOut(t *testing.T) {
	a, b := &countSink{}, &countSink{}
	m := NewMulti(a, nil, b) // nil member must be skipped
	if m.Len() != 2 {
		t.Fatalf("Len: got %d want 2", m.Len())
	}
	m.Record(denyRow("/x"))
	if a.n != 1 || b.n != 1 {
		t.Fatalf("fanout failed: a=%d b=%d", a.n, b.n)
	}
}

type countSink struct{ n int }

func (c *countSink) Record(decisions.Record) { c.n++ }

// learnRow is a compact decision row for the learn observer tests.
func learnRow(host, decision, ts string) decisions.Record {
	return decisions.Record{
		Host:      host,
		Decision:  decision,
		Timestamp: ts,
		Method:    "GET",
		Path:      "/",
	}
}

// readProposal unmarshals the proposal file written by a LearnSink.
func readProposal(t *testing.T, path string) proposal {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read proposal: %v", err)
	}
	var p proposal
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("proposal is not valid JSON: %v\n%s", err, b)
	}
	return p
}

// The learn observer must tally each DISTINCT host with the correct request
// count, allow/deny breakdown, and first/last_seen across many Record calls, and
// Close() must force a final write of a valid 0600 JSON proposal whose
// suggested_allowlist is the sorted distinct host set that was fed.
func TestLearnTalliesDistinctHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proposed-allowlist.json")
	s := NewLearn(path, time.Hour) // long interval: only Close() writes

	// Feed a mix: repeated hosts, mixed allow/deny, out-of-order host names so we
	// can assert the suggested list comes out sorted.
	feed := []decisions.Record{
		learnRow("api.github.com", "allow", "2026-07-09T00:00:01Z"),
		learnRow("api.github.com", "allow", "2026-07-09T00:00:02Z"),
		learnRow("api.github.com", "deny", "2026-07-09T00:00:03Z"),
		learnRow("api.anthropic.com", "allow", "2026-07-09T00:00:04Z"),
		learnRow("api.anthropic.com", "allow", "2026-07-09T00:00:05Z"),
		learnRow("evil.example.com", "deny", "2026-07-09T00:00:06Z"),
	}
	for _, r := range feed {
		s.Record(r)
	}
	// A host-less row must be ignored (nothing to allowlist).
	s.Record(learnRow("", "allow", "2026-07-09T00:00:07Z"))

	if err := s.Close(); err != nil { // forces the final write
		t.Fatalf("Close: %v", err)
	}

	// File mode must be 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: got %v want 0600", fi.Mode().Perm())
	}

	p := readProposal(t, path)

	if p.Observed != 3 {
		t.Fatalf("observed: got %d want 3", p.Observed)
	}
	if p.GeneratedAt == "" {
		t.Fatalf("generated_at empty")
	}

	// suggested_allowlist is the sorted distinct host set.
	wantSuggested := []string{"api.anthropic.com", "api.github.com", "evil.example.com"}
	if !reflect.DeepEqual(p.SuggestedAllowlist, wantSuggested) {
		t.Fatalf("suggested_allowlist: got %v want %v", p.SuggestedAllowlist, wantSuggested)
	}

	// Per-host tallies, keyed for lookup.
	byHost := map[string]hostStat{}
	for _, h := range p.Hosts {
		byHost[h.Host] = h
	}
	cases := []struct {
		host                string
		count, allow, deny  int
		firstSeen, lastSeen string
	}{
		{"api.github.com", 3, 2, 1, "2026-07-09T00:00:01Z", "2026-07-09T00:00:03Z"},
		{"api.anthropic.com", 2, 2, 0, "2026-07-09T00:00:04Z", "2026-07-09T00:00:05Z"},
		{"evil.example.com", 1, 0, 1, "2026-07-09T00:00:06Z", "2026-07-09T00:00:06Z"},
	}
	for _, c := range cases {
		h, ok := byHost[c.host]
		if !ok {
			t.Fatalf("missing host %q in proposal", c.host)
		}
		if h.Count != c.count || h.Allow != c.allow || h.Deny != c.deny {
			t.Fatalf("%s tally: got count=%d allow=%d deny=%d want %d/%d/%d",
				c.host, h.Count, h.Allow, h.Deny, c.count, c.allow, c.deny)
		}
		if h.FirstSeen != c.firstSeen || h.LastSeen != c.lastSeen {
			t.Fatalf("%s seen: got first=%q last=%q want %q/%q",
				c.host, h.FirstSeen, h.LastSeen, c.firstSeen, c.lastSeen)
		}
	}

	// hosts must be sorted by name (deterministic output).
	for i := 1; i < len(p.Hosts); i++ {
		if p.Hosts[i-1].Host > p.Hosts[i].Host {
			t.Fatalf("hosts not sorted: %v", p.Hosts)
		}
	}
}

// The ticker goroutine must produce a proposal file on its interval (before any
// Close), and stop cleanly when its context is cancelled.
func TestLearnTickerWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proposed-allowlist.json")
	s := NewLearn(path, 20*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	s.Record(learnRow("api.github.com", "allow", "2026-07-09T00:00:01Z"))

	// Poll until the ticker has written the file.
	deadline := time.Now().Add(2 * time.Second)
	var p proposal
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			p = readProposal(t, path)
			if p.Observed == 1 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p.Observed != 1 || len(p.SuggestedAllowlist) != 1 || p.SuggestedAllowlist[0] != "api.github.com" {
		t.Fatalf("ticker did not write expected proposal: %+v", p)
	}

	cancel() // Run must return promptly
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// Learn Close is idempotent and only the first call needs to succeed at writing.
func TestLearnCloseIdempotent(t *testing.T) {
	s := NewLearn(filepath.Join(t.TempDir(), "p.json"), time.Hour)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// The learn observer must be safe under concurrent Record calls racing a write.
// Run under -race; the assertion is that no host count is lost.
func TestLearnConcurrentRecordAndWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proposed-allowlist.json")
	s := NewLearn(path, time.Hour)

	const writers = 8
	const perWriter = 500
	hosts := []string{"a.example.com", "b.example.com", "c.example.com"}

	var wg sync.WaitGroup
	// Writers hammer Record concurrently.
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				host := hosts[(w+i)%len(hosts)]
				s.Record(learnRow(host, "allow", "2026-07-09T00:00:00Z"))
			}
		}(w)
	}
	// A concurrent writer races the file write against the Records.
	stop := make(chan struct{})
	var writeWg sync.WaitGroup
	writeWg.Add(1)
	go func() {
		defer writeWg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.write()
			}
		}
	}()

	wg.Wait()
	close(stop)
	writeWg.Wait()

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	p := readProposal(t, path)
	if p.Observed != len(hosts) {
		t.Fatalf("observed: got %d want %d", p.Observed, len(hosts))
	}
	var total int
	for _, h := range p.Hosts {
		total += h.Count
	}
	if total != writers*perWriter {
		t.Fatalf("lost counts under race: got %d want %d", total, writers*perWriter)
	}
}
