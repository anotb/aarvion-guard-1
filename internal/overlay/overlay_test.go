package overlay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T, rules []Rule) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.Replace(rules); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	return s
}

func TestLoadMissingFileEmptyStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load missing file: unexpected error %v", err)
	}
	if got := s.Rules(); len(got) != 0 {
		t.Fatalf("expected empty store, got %d rules", len(got))
	}
	if s.Path() != path {
		t.Fatalf("Path()=%q want %q", s.Path(), path)
	}
	// A missing file must not match anything.
	if _, ok := s.Match(Action{Tool: "bash"}); ok {
		t.Fatalf("empty store matched an action")
	}
}

func TestLoadBadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error loading bad JSON, got nil")
	}
}

func TestAllEmptyMatchNeverMatches(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "empty", Verdict: VerdictDeny, Enabled: true, Match: Match{}},
	})
	if _, ok := s.Match(Action{Tool: "bash", Command: "anything", Host: "x.com", Method: "GET"}); ok {
		t.Fatal("all-empty Match should never match")
	}
}

func TestANDAcrossFacets(t *testing.T) {
	s := newStore(t, []Rule{
		{
			ID:      "r1",
			Verdict: VerdictDeny,
			Enabled: true,
			Match: Match{
				Tools:           []string{"bash"},
				CommandContains: []string{"rm -rf"},
			},
		},
	})

	// Both facets satisfied -> match.
	if _, ok := s.Match(Action{Tool: "bash", Command: "sudo rm -rf /"}); !ok {
		t.Fatal("expected match when all facets satisfied")
	}
	// Tool matches but command does not -> no match (AND).
	if _, ok := s.Match(Action{Tool: "bash", Command: "ls -la"}); ok {
		t.Fatal("expected no match when one facet fails (command)")
	}
	// Command matches but tool does not -> no match (AND).
	if _, ok := s.Match(Action{Tool: "python", Command: "rm -rf tmp"}); ok {
		t.Fatal("expected no match when one facet fails (tool)")
	}
}

func TestORWithinFacet(t *testing.T) {
	s := newStore(t, []Rule{
		{
			ID:      "r1",
			Verdict: VerdictAsk,
			Enabled: true,
			Match:   Match{Tools: []string{"bash", "python", "node"}},
		},
	})
	for _, tool := range []string{"bash", "python", "node"} {
		if _, ok := s.Match(Action{Tool: tool}); !ok {
			t.Fatalf("expected OR-within-facet match for tool %q", tool)
		}
	}
	if _, ok := s.Match(Action{Tool: "ruby"}); ok {
		t.Fatal("expected no match for tool not in list")
	}
}

func TestCaseInsensitiveCommand(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{CommandContains: []string{"CURL"}}},
	})
	if _, ok := s.Match(Action{Command: "curl https://x"}); !ok {
		t.Fatal("command match should be case-insensitive")
	}
	if _, ok := s.Match(Action{Command: "CuRl https://x"}); !ok {
		t.Fatal("command match should be case-insensitive (mixed)")
	}
}

func TestCaseInsensitiveMethod(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{Methods: []string{"post"}}},
	})
	if _, ok := s.Match(Action{Method: "POST"}); !ok {
		t.Fatal("method match should be case-insensitive")
	}
	if _, ok := s.Match(Action{Method: "GET"}); ok {
		t.Fatal("GET should not match a POST rule")
	}
}

func TestCaseInsensitiveHost(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{HostSuffixes: []string{"Example.COM"}}},
	})
	if _, ok := s.Match(Action{Host: "api.example.com"}); !ok {
		t.Fatal("host match should be case-insensitive")
	}
}

func TestHostSuffixMatching(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{HostSuffixes: []string{"example.com"}}},
	})
	// Subdomain matches.
	if _, ok := s.Match(Action{Host: "sub.example.com"}); !ok {
		t.Fatal("suffix should match subdomain")
	}
	// Deep subdomain matches.
	if _, ok := s.Match(Action{Host: "a.b.example.com"}); !ok {
		t.Fatal("suffix should match deep subdomain")
	}
	// Bare domain matches.
	if _, ok := s.Match(Action{Host: "example.com"}); !ok {
		t.Fatal("suffix should match bare domain")
	}
	// Non-matching, but tricky, host must NOT match.
	if _, ok := s.Match(Action{Host: "notexample.com"}); ok {
		t.Fatal("notexample.com must not match example.com suffix")
	}
	if _, ok := s.Match(Action{Host: "evilexample.com"}); ok {
		t.Fatal("evilexample.com must not match example.com suffix")
	}
	if _, ok := s.Match(Action{Host: "example.com.evil.net"}); ok {
		t.Fatal("example.com.evil.net must not match example.com suffix")
	}
}

func TestHostSuffixWithLeadingDot(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{HostSuffixes: []string{".example.com"}}},
	})
	if _, ok := s.Match(Action{Host: "sub.example.com"}); !ok {
		t.Fatal("leading-dot suffix should match subdomain")
	}
	if _, ok := s.Match(Action{Host: "example.com"}); !ok {
		t.Fatal("leading-dot suffix should still match bare domain")
	}
}

func TestDisabledRulesSkipped(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "off", Verdict: VerdictDeny, Enabled: false,
			Match: Match{Tools: []string{"bash"}}},
	})
	if _, ok := s.Match(Action{Tool: "bash"}); ok {
		t.Fatal("disabled rule should be skipped")
	}
}

func TestMatchReturnsFirstEnabled(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "disabled-first", Verdict: VerdictAsk, Enabled: false,
			Match: Match{Tools: []string{"bash"}}},
		{ID: "enabled-deny", Verdict: VerdictDeny, Enabled: true,
			Match: Match{Tools: []string{"bash"}}},
		{ID: "enabled-ask", Verdict: VerdictAsk, Enabled: true,
			Match: Match{Tools: []string{"bash"}}},
	})
	r, ok := s.Match(Action{Tool: "bash"})
	if !ok {
		t.Fatal("expected a match")
	}
	if r.ID != "enabled-deny" {
		t.Fatalf("expected first ENABLED match 'enabled-deny', got %q", r.ID)
	}
	if r.Verdict != VerdictDeny {
		t.Fatalf("expected verdict deny, got %q", r.Verdict)
	}
}

func TestReplaceRejectsBadVerdict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	// Verdict "allow" is looser than allow-through and must be rejected.
	if err := s.Replace([]Rule{
		{ID: "loose", Verdict: Verdict("allow"), Enabled: true,
			Match: Match{Tools: []string{"bash"}}},
	}); err == nil {
		t.Fatal("expected rejection of verdict 'allow'")
	}

	// Empty verdict must be rejected.
	if err := s.Replace([]Rule{
		{ID: "novrd", Verdict: Verdict(""), Enabled: true,
			Match: Match{Tools: []string{"bash"}}},
	}); err == nil {
		t.Fatal("expected rejection of empty verdict")
	}

	// A rejected Replace must not have written the file.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected Replace should not create file, stat err=%v", err)
	}
}

func TestReplaceRejectsEmptyID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace([]Rule{
		{ID: "", Verdict: VerdictDeny, Enabled: true,
			Match: Match{Tools: []string{"bash"}}},
	}); err == nil {
		t.Fatal("expected rejection of empty ID")
	}
}

func TestReplaceRejectsDuplicateID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace([]Rule{
		{ID: "dup", Verdict: VerdictDeny, Enabled: true,
			Match: Match{Tools: []string{"bash"}}},
		{ID: "dup", Verdict: VerdictAsk, Enabled: true,
			Match: Match{Tools: []string{"python"}}},
	}); err == nil {
		t.Fatal("expected rejection of duplicate ID")
	}
}

func TestReplaceAcceptsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rules := []Rule{
		{ID: "a", Verdict: VerdictDeny, Enabled: true, Match: Match{Tools: []string{"bash"}}},
		{ID: "b", Verdict: VerdictAsk, Enabled: true, Match: Match{Methods: []string{"POST"}}},
	}
	if err := s.Replace(rules); err != nil {
		t.Fatalf("Replace valid rules: %v", err)
	}
	if got := s.Rules(); len(got) != 2 {
		t.Fatalf("expected 2 rules in memory, got %d", len(got))
	}
	// File must be present with 0600 perms.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after Replace: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 perms, got %o", perm)
	}
}

func TestReplaceDefensiveCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rules := []Rule{
		{ID: "a", Verdict: VerdictDeny, Enabled: true, Match: Match{Tools: []string{"bash"}}},
	}
	if err := s.Replace(rules); err != nil {
		t.Fatal(err)
	}
	// Mutate the caller's slice; the store must be unaffected.
	rules[0].ID = "mutated"
	rules[0].Verdict = "allow"
	if got := s.Rules(); got[0].ID != "a" || got[0].Verdict != VerdictDeny {
		t.Fatalf("store must not alias caller slice, got %+v", got[0])
	}
}

func TestRulesSnapshotIsCopy(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "a", Verdict: VerdictDeny, Enabled: true, Match: Match{Tools: []string{"bash"}}},
	})
	snap := s.Rules()
	snap[0].ID = "hacked"
	if got := s.Rules(); got[0].ID != "a" {
		t.Fatal("Rules() must return a copy, not the backing slice")
	}
}

func TestAtomicWriteAndReloadPicksUpExternalChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace([]Rule{
		{ID: "a", Verdict: VerdictDeny, Enabled: true, Match: Match{Tools: []string{"bash"}}},
	}); err != nil {
		t.Fatal(err)
	}

	// Simulate an external process rewriting the file.
	external := file{Rules: []Rule{
		{ID: "ext", Verdict: VerdictAsk, Enabled: true, Match: Match{Methods: []string{"DELETE"}}},
	}}
	data, err := json.Marshal(external)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Before reload, memory still reflects the old rules.
	if _, ok := s.Match(Action{Tool: "bash"}); !ok {
		t.Fatal("pre-reload: expected old rule to still match")
	}

	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// After reload, the external rule is in effect and the old one is gone.
	if _, ok := s.Match(Action{Tool: "bash"}); ok {
		t.Fatal("post-reload: old rule should be gone")
	}
	r, ok := s.Match(Action{Method: "DELETE"})
	if !ok {
		t.Fatal("post-reload: expected external rule to match")
	}
	if r.ID != "ext" {
		t.Fatalf("post-reload: expected rule 'ext', got %q", r.ID)
	}
}

func TestReloadMissingFileResetsToEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace([]Rule{
		{ID: "a", Verdict: VerdictDeny, Enabled: true, Match: Match{Tools: []string{"bash"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload after removal: %v", err)
	}
	if got := s.Rules(); len(got) != 0 {
		t.Fatalf("expected empty store after file removal, got %d rules", len(got))
	}
}

func TestReloadBadJSONLeavesMemoryIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace([]Rule{
		{ID: "a", Verdict: VerdictDeny, Enabled: true, Match: Match{Tools: []string{"bash"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Fatal("expected error reloading broken JSON")
	}
	// In-memory rules should be untouched.
	if _, ok := s.Match(Action{Tool: "bash"}); !ok {
		t.Fatal("failed reload must leave in-memory rules intact")
	}
}

func TestOnDiskFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace([]Rule{
		{ID: "a", Verdict: VerdictDeny, Enabled: true,
			Match: Match{HostSuffixes: []string{"example.com"}}},
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("on-disk format not {\"rules\":[...]}: %v", err)
	}
	if len(f.Rules) != 1 || f.Rules[0].ID != "a" {
		t.Fatalf("unexpected on-disk contents: %+v", f)
	}
}

// --- semantic facets (Task A3) ---

func TestSurfacesFacet(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{Surfaces: []string{"twitter", "comms"}}},
	})
	if _, ok := s.Match(Action{Surface: "twitter"}); !ok {
		t.Fatal("expected surface match")
	}
	if _, ok := s.Match(Action{Surface: "TWITTER"}); !ok {
		t.Fatal("surface match should be case-insensitive")
	}
	if _, ok := s.Match(Action{Surface: "github"}); ok {
		t.Fatal("github must not match a twitter/comms surface rule")
	}
}

func TestVerbsFacet(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{
				Surfaces: []string{"twitter"},
				Verbs:    []string{"post", "reply", "dm", "follow"},
			}},
	})
	// A post on twitter matches (surface AND verb).
	if _, ok := s.Match(Action{Surface: "twitter", Verb: "post"}); !ok {
		t.Fatal("expected match for twitter post")
	}
	if _, ok := s.Match(Action{Surface: "twitter", Verb: "REPLY"}); !ok {
		t.Fatal("verb match should be case-insensitive")
	}
	// A read on twitter does NOT match (verb facet excludes read).
	if _, ok := s.Match(Action{Surface: "twitter", Verb: "read"}); ok {
		t.Fatal("twitter read must not match a post/reply/dm/follow rule")
	}
	// Right verb, wrong surface -> no match (AND across facets).
	if _, ok := s.Match(Action{Surface: "github", Verb: "post"}); ok {
		t.Fatal("wrong surface must not match even with a matching verb")
	}
}

func TestPrincipalsFacet(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{Principals: []string{"llm-twitter"}}},
	})
	if _, ok := s.Match(Action{Principal: "llm-twitter"}); !ok {
		t.Fatal("expected principal match")
	}
	if _, ok := s.Match(Action{Principal: "LLM-Twitter"}); !ok {
		t.Fatal("principal match should be case-insensitive")
	}
	if _, ok := s.Match(Action{Principal: "main"}); ok {
		t.Fatal("a different principal must not match")
	}
	if _, ok := s.Match(Action{}); ok {
		t.Fatal("empty principal must not match a principals rule")
	}
}

func TestChannelsFacet(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictAsk, Enabled: true,
			Match: Match{Channels: []string{"telegram", "discord"}}},
	})
	if _, ok := s.Match(Action{Channel: "telegram"}); !ok {
		t.Fatal("expected channel match")
	}
	if _, ok := s.Match(Action{Channel: "Discord"}); !ok {
		t.Fatal("channel match should be case-insensitive")
	}
	if _, ok := s.Match(Action{Channel: "whatsapp"}); ok {
		t.Fatal("whatsapp must not match a telegram/discord rule")
	}
}

func TestFlagsAllFacet(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{FlagsAll: []string{"force", "destructive"}}},
	})
	// Both flags true -> match (AND).
	if _, ok := s.Match(Action{Flags: map[string]bool{"force": true, "destructive": true}}); !ok {
		t.Fatal("expected match when all named flags are true")
	}
	// Only one flag true -> no match.
	if _, ok := s.Match(Action{Flags: map[string]bool{"force": true}}); ok {
		t.Fatal("must not match when only some named flags are true")
	}
	// A flag present but false -> no match.
	if _, ok := s.Match(Action{Flags: map[string]bool{"force": true, "destructive": false}}); ok {
		t.Fatal("a false flag must not satisfy FlagsAll")
	}
	// Nil flags -> no match.
	if _, ok := s.Match(Action{}); ok {
		t.Fatal("nil flags must not match a FlagsAll rule")
	}
}

func TestFindingsAnyFacet(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{FindingsAny: []string{"secret:ghp", "secret:aws"}}},
	})
	// Any listed label present -> match (OR).
	if _, ok := s.Match(Action{Findings: []string{"pii:email", "secret:ghp"}}); !ok {
		t.Fatal("expected match when a listed finding is present")
	}
	// No listed label -> no match.
	if _, ok := s.Match(Action{Findings: []string{"pii:email"}}); ok {
		t.Fatal("must not match when no listed finding is present")
	}
	// Empty findings -> no match.
	if _, ok := s.Match(Action{}); ok {
		t.Fatal("empty findings must not match a FindingsAny rule")
	}
}

func TestFindingsAnyCaseInsensitive(t *testing.T) {
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{FindingsAny: []string{"Secret:GHP"}}},
	})
	if _, ok := s.Match(Action{Findings: []string{"secret:ghp"}}); !ok {
		t.Fatal("findings match should be case-insensitive")
	}
}

func TestNotTargetsFacet(t *testing.T) {
	// NotTargets is a recipient/host allowlist inversion: it matches (fires)
	// when NONE of the action's targets is in the allowlist.
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictDeny, Enabled: true,
			Match: Match{NotTargets: []string{"a@x.com", "b@x.com"}}},
	})
	// Recipient not in the allowlist -> fires.
	if _, ok := s.Match(Action{Targets: []string{"stranger@y.com"}}); !ok {
		t.Fatal("expected fire when target is outside the allowlist")
	}
	// Recipient in the allowlist -> does not fire.
	if _, ok := s.Match(Action{Targets: []string{"a@x.com"}}); ok {
		t.Fatal("must not fire when target is in the allowlist")
	}
	// Case-insensitive allowlist membership.
	if _, ok := s.Match(Action{Targets: []string{"A@X.com"}}); ok {
		t.Fatal("allowlist membership should be case-insensitive")
	}
	// ANY target in the allowlist means the action is allowed (does not fire).
	if _, ok := s.Match(Action{Targets: []string{"stranger@y.com", "a@x.com"}}); ok {
		t.Fatal("a single allowlisted target must spare the whole action")
	}
	// Empty targets -> does NOT match (avoid blocking targetless actions).
	if _, ok := s.Match(Action{}); ok {
		t.Fatal("empty targets must not match a NotTargets rule")
	}
}

func TestTimeWindowFacetWraparound(t *testing.T) {
	// Quiet hours 23:00-07:00 (wraps midnight).
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictAsk, Enabled: true,
			Match: Match{TimeWindow: &Window{Start: "23:00", End: "07:00"}}},
	})
	at := func(h, m int) Action {
		return Action{Now: time.Date(2026, 7, 10, h, m, 0, 0, time.Local)}
	}
	// 02:00 is inside the quiet window.
	if _, ok := s.Match(at(2, 0)); !ok {
		t.Fatal("02:00 should be inside 23:00-07:00")
	}
	// 23:30 is inside.
	if _, ok := s.Match(at(23, 30)); !ok {
		t.Fatal("23:30 should be inside 23:00-07:00")
	}
	// 12:00 is outside.
	if _, ok := s.Match(at(12, 0)); ok {
		t.Fatal("12:00 should be outside 23:00-07:00")
	}
	// 07:00 is the exclusive end -> outside.
	if _, ok := s.Match(at(7, 0)); ok {
		t.Fatal("07:00 (end) should be outside the window")
	}
	// 23:00 is the inclusive start -> inside.
	if _, ok := s.Match(at(23, 0)); !ok {
		t.Fatal("23:00 (start) should be inside the window")
	}
}

func TestTimeWindowFacetSameDay(t *testing.T) {
	// A non-wrapping window 09:00-17:00.
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictAsk, Enabled: true,
			Match: Match{TimeWindow: &Window{Start: "09:00", End: "17:00"}}},
	})
	at := func(h, m int) Action {
		return Action{Now: time.Date(2026, 7, 10, h, m, 0, 0, time.Local)}
	}
	if _, ok := s.Match(at(12, 0)); !ok {
		t.Fatal("12:00 should be inside 09:00-17:00")
	}
	if _, ok := s.Match(at(8, 0)); ok {
		t.Fatal("08:00 should be outside 09:00-17:00")
	}
	if _, ok := s.Match(at(18, 0)); ok {
		t.Fatal("18:00 should be outside 09:00-17:00")
	}
}

func TestTimeWindowFacetDays(t *testing.T) {
	// 2026-07-10 is a Friday.
	friday := time.Date(2026, 7, 10, 2, 0, 0, 0, time.Local)
	saturday := time.Date(2026, 7, 11, 2, 0, 0, 0, time.Local)

	// Restricted to Fridays only.
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictAsk, Enabled: true,
			Match: Match{TimeWindow: &Window{Start: "23:00", End: "07:00", Days: []string{"fri"}}}},
	})
	if _, ok := s.Match(Action{Now: friday}); !ok {
		t.Fatal("Friday 02:00 should match a fri-only window")
	}
	if _, ok := s.Match(Action{Now: saturday}); ok {
		t.Fatal("Saturday 02:00 should NOT match a fri-only window")
	}

	// Full day name also accepted, case-insensitive.
	s2 := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictAsk, Enabled: true,
			Match: Match{TimeWindow: &Window{Start: "23:00", End: "07:00", Days: []string{"Friday"}}}},
	})
	if _, ok := s2.Match(Action{Now: friday}); !ok {
		t.Fatal("full day name 'Friday' should match")
	}
}

func TestTimeWindowZeroNowNeverMatches(t *testing.T) {
	// A rule with only a TimeWindow but a zero Action.Now must not match,
	// so an action that never populated Now is not silently gated.
	s := newStore(t, []Rule{
		{ID: "r1", Verdict: VerdictAsk, Enabled: true,
			Match: Match{TimeWindow: &Window{Start: "23:00", End: "07:00"}}},
	})
	if _, ok := s.Match(Action{}); ok {
		t.Fatal("a zero Now must not match a TimeWindow rule")
	}
}

func TestObserveRuleValidatesAndMatches(t *testing.T) {
	// An Observe rule is an ordinary enabled rule as far as overlay is
	// concerned: it must validate (verdict still deny/ask, so tighten-only
	// holds) and be returned by Match. The caller (govern.decide) is the one
	// that reads Observe to record WouldBe and leave the effective decision
	// ALLOW; overlay itself does not special-case it.
	s := newStore(t, []Rule{
		{ID: "obs", Verdict: VerdictDeny, Enabled: true, Observe: true,
			Match: Match{Surfaces: []string{"twitter"}, Verbs: []string{"post"}}},
	})
	r, ok := s.Match(Action{Surface: "twitter", Verb: "post"})
	if !ok {
		t.Fatal("an Observe rule should still be returned by Match")
	}
	if !r.Observe {
		t.Fatalf("Observe flag lost through Match: %+v", r)
	}
	if r.Verdict != VerdictDeny {
		t.Fatalf("Observe rule verdict = %q want deny", r.Verdict)
	}

	// Observe must survive a JSON round-trip and default to false when absent.
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := s.Rules(); len(got) != 1 || !got[0].Observe {
		t.Fatalf("Observe did not survive round-trip: %+v", got)
	}
}

func TestSemanticFacetsAreTightenOnly(t *testing.T) {
	// Adding semantic facets must not weaken the tighten-only invariant:
	// a rule using new facets with a non-tighten verdict is still rejected.
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace([]Rule{
		{ID: "loose", Verdict: Verdict("allow"), Enabled: true,
			Match: Match{Surfaces: []string{"twitter"}}},
	}); err == nil {
		t.Fatal("expected rejection of verdict 'allow' on a semantic-facet rule")
	}
}

func TestSemanticFacetsJSONRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rules := []Rule{
		{ID: "sem", Verdict: VerdictDeny, Enabled: true, Match: Match{
			Surfaces:    []string{"twitter"},
			Verbs:       []string{"post"},
			Principals:  []string{"llm-twitter"},
			Channels:    []string{"telegram"},
			FlagsAll:    []string{"force"},
			FindingsAny: []string{"secret:ghp"},
			NotTargets:  []string{"a@x.com"},
			TimeWindow:  &Window{Start: "23:00", End: "07:00", Days: []string{"fri"}},
		}},
	}
	if err := s.Replace(rules); err != nil {
		t.Fatalf("Replace semantic rule: %v", err)
	}
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	got := s.Rules()
	if len(got) != 1 {
		t.Fatalf("expected 1 rule after round-trip, got %d", len(got))
	}
	m := got[0].Match
	if len(m.Surfaces) != 1 || m.Surfaces[0] != "twitter" {
		t.Fatalf("Surfaces did not survive round-trip: %+v", m.Surfaces)
	}
	if m.TimeWindow == nil || m.TimeWindow.Start != "23:00" || m.TimeWindow.End != "07:00" {
		t.Fatalf("TimeWindow did not survive round-trip: %+v", m.TimeWindow)
	}
}
