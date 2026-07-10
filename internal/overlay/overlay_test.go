package overlay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
