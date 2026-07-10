package packs

import (
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
)

// matchStore loads rules into a real overlay Store so tests exercise the
// overlay's actual match semantics rather than a re-implementation.
func matchStore(t *testing.T, rules []overlay.Rule) *overlay.Store {
	t.Helper()
	s, err := overlay.Load(filepath.Join(t.TempDir(), "overlay.json"))
	if err != nil {
		t.Fatalf("overlay.Load: %v", err)
	}
	if err := s.Replace(rules); err != nil {
		t.Fatalf("overlay.Replace (compiled rules must be tighten-only valid): %v", err)
	}
	return s
}

func TestCompileDeterministicSortedIDs(t *testing.T) {
	set := Set{Packs: []Pack{
		{ID: "github-guard", Title: "gh", Mode: "enforce"},
		{ID: "social-guard", Title: "social", Mode: "enforce"},
	}}
	a := CompileOverlay(set)
	b := CompileOverlay(set)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("CompileOverlay is not deterministic across calls")
	}
	ids := make([]string, len(a))
	seen := map[string]struct{}{}
	for i, r := range a {
		ids[i] = r.ID
		if !strings.HasPrefix(r.ID, "pack:") {
			t.Fatalf("rule id %q missing pack: prefix", r.ID)
		}
		if _, dup := seen[r.ID]; dup {
			t.Fatalf("duplicate compiled rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("rule ids not sorted: %v", ids)
	}
	// Every compiled rule must be a valid tighten-only overlay set.
	matchStore(t, a)
}

func TestCompileOffEmitsNothing(t *testing.T) {
	set := Set{Packs: []Pack{{ID: "social-guard", Title: "s", Mode: "off"}}}
	if got := CompileOverlay(set); len(got) != 0 {
		t.Fatalf("off pack emitted %d rules, want 0", len(got))
	}
}

func TestSocialGuardEnforce(t *testing.T) {
	rules := CompileOverlay(Set{Packs: []Pack{{ID: "social-guard", Title: "s", Mode: "enforce"}}})
	s := matchStore(t, rules)

	// A twitter post is a HARD rule -> deny in enforce.
	r, ok := s.Match(overlay.Action{Surface: "twitter", Verb: "post"})
	if !ok {
		t.Fatal("social-guard enforce did not match a twitter post")
	}
	if r.Verdict != overlay.VerdictDeny {
		t.Fatalf("twitter post verdict = %q want deny", r.Verdict)
	}
	if r.Observe {
		t.Fatal("enforce rule must not be marked Observe")
	}

	// A twitter read must NOT match (read verb not gated).
	if _, ok := s.Match(overlay.Action{Surface: "twitter", Verb: "read"}); ok {
		t.Fatal("social-guard must not gate a twitter read")
	}
}

func TestSocialGuardAskMode(t *testing.T) {
	rules := CompileOverlay(Set{Packs: []Pack{{ID: "social-guard", Title: "s", Mode: "ask"}}})
	s := matchStore(t, rules)
	r, ok := s.Match(overlay.Action{Surface: "twitter", Verb: "post"})
	if !ok {
		t.Fatal("social-guard ask did not match a twitter post")
	}
	if r.Verdict != overlay.VerdictAsk {
		t.Fatalf("ask mode: twitter post verdict = %q want ask", r.Verdict)
	}
}

func TestSocialGuardObserveMarks(t *testing.T) {
	rules := CompileOverlay(Set{Packs: []Pack{{ID: "social-guard", Title: "s", Mode: "observe"}}})
	s := matchStore(t, rules)
	r, ok := s.Match(overlay.Action{Surface: "twitter", Verb: "post"})
	if !ok {
		t.Fatal("social-guard observe did not match a twitter post")
	}
	// observe: intrinsic verdict (hard->deny) but recorded-only.
	if r.Verdict != overlay.VerdictDeny {
		t.Fatalf("observe: twitter post verdict = %q want deny (intrinsic)", r.Verdict)
	}
	if !r.Observe {
		t.Fatal("observe-mode rule must set Observe=true")
	}
}

func TestGoogleGuardEnforce(t *testing.T) {
	rules := CompileOverlay(Set{Packs: []Pack{{ID: "google-guard", Title: "g", Mode: "enforce"}}})
	s := matchStore(t, rules)

	// Drive delete is HARD -> deny.
	r, ok := s.Match(overlay.Action{Surface: "file", Verb: "delete"})
	if !ok {
		t.Fatal("google-guard enforce did not match a file delete")
	}
	if r.Verdict != overlay.VerdictDeny {
		t.Fatalf("file delete verdict = %q want deny", r.Verdict)
	}

	// Email send is SOFT -> ask in enforce. With no contact_allowlist a plain
	// email-send rule fires for any recipient.
	r2, ok := s.Match(overlay.Action{Surface: "email", Verb: "send", Targets: []string{"a@x.com"}})
	if !ok {
		t.Fatal("google-guard enforce did not match an email send")
	}
	if r2.Verdict != overlay.VerdictAsk {
		t.Fatalf("email send verdict = %q want ask", r2.Verdict)
	}

	// Public share is HARD -> deny.
	r3, ok := s.Match(overlay.Action{Surface: "doc", Verb: "share",
		Flags: map[string]bool{"public_share": true}})
	if !ok {
		t.Fatal("google-guard enforce did not match a public share")
	}
	if r3.Verdict != overlay.VerdictDeny {
		t.Fatalf("public share verdict = %q want deny", r3.Verdict)
	}

	// Force delete is HARD -> deny.
	r4, ok := s.Match(overlay.Action{Surface: "file", Verb: "delete",
		Flags: map[string]bool{"force": true}})
	if !ok {
		t.Fatal("google-guard enforce did not match a force delete")
	}
	if r4.Verdict != overlay.VerdictDeny {
		t.Fatalf("force delete verdict = %q want deny", r4.Verdict)
	}
}

func TestGoogleGuardContactAllowlist(t *testing.T) {
	// With a contact_allowlist, email to a stranger fires (soft/ask) but email
	// to an allowlisted contact does not.
	set := Set{Packs: []Pack{{
		ID: "google-guard", Title: "g", Mode: "enforce",
		Params: map[string]any{"contact_allowlist": []any{"friend@x.com"}},
	}}}
	s := matchStore(t, CompileOverlay(set))

	if _, ok := s.Match(overlay.Action{Surface: "email", Verb: "send",
		Targets: []string{"stranger@y.com"}}); !ok {
		t.Fatal("email to a non-contact should fire under a contact_allowlist")
	}
	if _, ok := s.Match(overlay.Action{Surface: "email", Verb: "send",
		Targets: []string{"friend@x.com"}}); ok {
		t.Fatal("email to an allowlisted contact must not fire")
	}
}

func TestCommsGuardQuietHours(t *testing.T) {
	set := Set{Packs: []Pack{{
		ID: "comms-guard", Title: "c", Mode: "enforce",
		Params: map[string]any{
			"quiet_hours": map[string]any{"start": "23:00", "end": "07:00"},
		},
	}}}
	rules := CompileOverlay(set)

	var hasTimeWindow bool
	for _, r := range rules {
		if r.Match.TimeWindow != nil {
			hasTimeWindow = true
			if r.Match.TimeWindow.Start != "23:00" || r.Match.TimeWindow.End != "07:00" {
				t.Fatalf("quiet_hours window = %+v want 23:00-07:00", r.Match.TimeWindow)
			}
		}
	}
	if !hasTimeWindow {
		t.Fatal("comms-guard with quiet_hours did not emit a TimeWindow rule")
	}
}

func TestDLPGuardEnforce(t *testing.T) {
	rules := CompileOverlay(Set{Packs: []Pack{{ID: "dlp-guard", Title: "d", Mode: "enforce"}}})
	s := matchStore(t, rules)

	// A secret finding is HARD -> deny.
	r, ok := s.Match(overlay.Action{Findings: []string{"secret:ghp"}})
	if !ok {
		t.Fatal("dlp-guard enforce did not match a secret finding")
	}
	if r.Verdict != overlay.VerdictDeny {
		t.Fatalf("secret finding verdict = %q want deny", r.Verdict)
	}

	// PII is SOFT and only present when ask_on_pii; a bare pack (no params)
	// must NOT emit a PII rule.
	if _, ok := s.Match(overlay.Action{Findings: []string{"pii:email"}}); ok {
		t.Fatal("dlp-guard without ask_on_pii must not gate PII")
	}
}

func TestDLPGuardPII(t *testing.T) {
	set := Set{Packs: []Pack{{
		ID: "dlp-guard", Title: "d", Mode: "enforce",
		Params: map[string]any{"ask_on_pii": true},
	}}}
	s := matchStore(t, CompileOverlay(set))
	r, ok := s.Match(overlay.Action{Findings: []string{"pii:phone"}})
	if !ok {
		t.Fatal("dlp-guard with ask_on_pii did not match a PII finding")
	}
	if r.Verdict != overlay.VerdictAsk {
		t.Fatalf("PII finding verdict = %q want ask", r.Verdict)
	}
}

func TestGithubGuardEnforce(t *testing.T) {
	rules := CompileOverlay(Set{Packs: []Pack{{ID: "github-guard", Title: "gh", Mode: "enforce"}}})
	s := matchStore(t, rules)

	for _, tc := range []struct {
		name string
		act  overlay.Action
		want overlay.Verdict
	}{
		{"force_push", overlay.Action{Surface: "github", Verb: "force_push"}, overlay.VerdictDeny},
		{"repo_delete", overlay.Action{Surface: "github", Verb: "repo_delete"}, overlay.VerdictDeny},
		{"secret_set", overlay.Action{Surface: "github", Verb: "secret_set"}, overlay.VerdictDeny},
		{"workflow_edit", overlay.Action{Surface: "github", Command: "git add .github/workflows/ci.yml"}, overlay.VerdictAsk},
	} {
		r, ok := s.Match(tc.act)
		if !ok {
			t.Fatalf("%s: no match", tc.name)
		}
		if r.Verdict != tc.want {
			t.Fatalf("%s: verdict = %q want %q", tc.name, r.Verdict, tc.want)
		}
	}
}

func TestInfraGuardEnforce(t *testing.T) {
	rules := CompileOverlay(Set{Packs: []Pack{{ID: "infra-guard", Title: "i", Mode: "enforce"}}})
	s := matchStore(t, rules)

	// Destructive infra flag is HARD -> deny.
	r, ok := s.Match(overlay.Action{Surface: "infra",
		Flags: map[string]bool{"destructive": true}})
	if !ok {
		t.Fatal("infra-guard enforce did not match a destructive infra action")
	}
	if r.Verdict != overlay.VerdictDeny {
		t.Fatalf("destructive infra verdict = %q want deny", r.Verdict)
	}

	// A dangerous command substring is HARD -> deny.
	for _, cmd := range []string{
		"docker system prune -f",
		"sudo systemctl stop nginx",
		"shutdown -h now",
	} {
		r2, ok := s.Match(overlay.Action{Command: cmd})
		if !ok {
			t.Fatalf("infra-guard did not match %q", cmd)
		}
		if r2.Verdict != overlay.VerdictDeny {
			t.Fatalf("%q verdict = %q want deny", cmd, r2.Verdict)
		}
	}
}

func TestAPIGuardEnforce(t *testing.T) {
	rules := CompileOverlay(Set{Packs: []Pack{{ID: "api-guard", Title: "a", Mode: "enforce",
		Params: map[string]any{"block_destructive": true}}}})
	s := matchStore(t, rules)

	// A destructive API verb is HARD -> deny.
	r, ok := s.Match(overlay.Action{Surface: "api",
		Flags: map[string]bool{"delete_verb": true}})
	if !ok {
		t.Fatal("api-guard enforce did not match a destructive api call")
	}
	if r.Verdict != overlay.VerdictDeny {
		t.Fatalf("destructive api verdict = %q want deny", r.Verdict)
	}
}

func TestPerAgentStricterOrderedFirst(t *testing.T) {
	// An ask-mode pack with a per-agent enforce override: the per-agent rules
	// are principal-scoped, verdict at the stricter (enforce) level, and ordered
	// BEFORE the base rules.
	set := Set{Packs: []Pack{{
		ID: "social-guard", Title: "s", Mode: "ask",
		PerAgent: map[string]string{"llm-twitter": "enforce"},
	}}}
	rules := CompileOverlay(set)

	firstScopedIdx, firstBaseIdx := -1, -1
	for i, r := range rules {
		switch {
		case len(r.Match.Principals) == 1 && r.Match.Principals[0] == "llm-twitter":
			if firstScopedIdx == -1 {
				firstScopedIdx = i
			}
		case len(r.Match.Principals) == 0:
			if firstBaseIdx == -1 {
				firstBaseIdx = i
			}
		}
	}
	if firstScopedIdx == -1 {
		t.Fatal("no llm-twitter-scoped rule emitted")
	}
	if firstBaseIdx == -1 {
		t.Fatal("no base rule emitted")
	}
	if firstScopedIdx > firstBaseIdx {
		t.Fatalf("per-agent rules (idx %d) must precede base rules (idx %d)", firstScopedIdx, firstBaseIdx)
	}

	s := matchStore(t, rules)
	// The per-agent post rule denies for llm-twitter (enforce beats base ask).
	rScoped, ok := s.Match(overlay.Action{Surface: "twitter", Verb: "post", Principal: "llm-twitter"})
	if !ok {
		t.Fatal("no rule matched an llm-twitter post")
	}
	if rScoped.Verdict != overlay.VerdictDeny {
		t.Fatalf("llm-twitter post = %q want deny", rScoped.Verdict)
	}
	// A different principal falls through to the base ask rule.
	rBase, ok := s.Match(overlay.Action{Surface: "twitter", Verb: "post", Principal: "main"})
	if !ok {
		t.Fatal("no rule matched a main post")
	}
	if rBase.Verdict != overlay.VerdictAsk {
		t.Fatalf("main post = %q want ask (base pack mode)", rBase.Verdict)
	}
}

func TestPerAgentLooserDropped(t *testing.T) {
	// A per-agent override LOOSER than the pack mode is dropped: no
	// principal-scoped rule is emitted, and the stricter base rules still stand.
	set := Set{Packs: []Pack{{
		ID: "social-guard", Title: "s", Mode: "enforce",
		PerAgent: map[string]string{"llm-twitter": "observe"},
	}}}
	rules := CompileOverlay(set)
	for _, r := range rules {
		if len(r.Match.Principals) == 1 && r.Match.Principals[0] == "llm-twitter" {
			t.Fatalf("a looser per-agent override must be dropped, found rule %q", r.ID)
		}
	}
	s := matchStore(t, rules)
	if _, ok := s.Match(overlay.Action{Surface: "twitter", Verb: "post"}); !ok {
		t.Fatal("base enforce rules should still be present")
	}
}

func TestCompileDefaultCatalogGolden(t *testing.T) {
	// The default catalog is all-observe; every emitted rule must be Observe and
	// tighten-only valid. This is the golden shape the console ships with.
	rules := CompileOverlay(Set{Packs: Catalog()})
	if len(rules) == 0 {
		t.Fatal("default catalog compiled to zero rules")
	}
	for _, r := range rules {
		if !r.Observe {
			t.Fatalf("default (observe) catalog rule %q is not Observe", r.ID)
		}
		if r.Verdict != overlay.VerdictDeny && r.Verdict != overlay.VerdictAsk {
			t.Fatalf("rule %q verdict %q not tighten-only", r.ID, r.Verdict)
		}
	}
	// Must be persistable as a valid overlay set.
	matchStore(t, rules)

	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("default catalog ids not sorted: %v", ids)
	}
	if !reflect.DeepEqual(rules, CompileOverlay(Set{Packs: Catalog()})) {
		t.Fatal("default catalog compile is not deterministic")
	}
}
