package packs

import (
	"reflect"
	"sort"
	"testing"

	"github.com/aarvion-ai/aarvion-guard/internal/sinks"
)

// findPack returns the proposed pack with id or fails the test.
func findPack(t *testing.T, s Set, id string) Pack {
	t.Helper()
	for _, p := range s.Packs {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("proposal missing pack %q; got %v", id, packIDs(s))
	return Pack{}
}

// hasPack reports whether the proposed set contains a pack with id.
func hasPack(s Set, id string) bool {
	for _, p := range s.Packs {
		if p.ID == id {
			return true
		}
	}
	return false
}

func packIDs(s Set) []string {
	ids := make([]string, len(s.Packs))
	for i, p := range s.Packs {
		ids[i] = p.ID
	}
	return ids
}

func entry(principal, surface, verb string, targets ...string) sinks.ProfileEntry {
	tm := map[string]int{}
	for _, tgt := range targets {
		tm[tgt]++
	}
	return sinks.ProfileEntry{
		Principal: principal,
		Surface:   surface,
		Verb:      verb,
		Count:     1,
		Targets:   tm,
	}
}

// TestProposeDeterministic: proposing twice from the same profile yields the
// identical Set, and pack ids come out sorted.
func TestProposeDeterministic(t *testing.T) {
	p := sinks.Profile{Entries: []sinks.ProfileEntry{
		entry("llm-twitter", "twitter", "read"),
		entry("main", "email", "send", "a@x.com", "b@x.com"),
		entry("main", "github", "push", "o/r"),
	}}
	a := ProposeFromProfile(p)
	b := ProposeFromProfile(p)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("ProposeFromProfile not deterministic:\n a=%#v\n b=%#v", a, b)
	}
	ids := packIDs(a)
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("proposed pack ids not sorted: %v", ids)
	}
}

// TestProposeDLPAlwaysEnforce: dlp-guard is always proposed at enforce, even on
// an empty profile.
func TestProposeDLPAlwaysEnforce(t *testing.T) {
	got := ProposeFromProfile(sinks.Profile{})
	dlp := findPack(t, got, "dlp-guard")
	if dlp.Mode != ModeEnforce {
		t.Fatalf("dlp-guard mode = %q, want enforce", dlp.Mode)
	}
	// A non-empty profile that never touches dlp must still enforce dlp-guard.
	got = ProposeFromProfile(sinks.Profile{Entries: []sinks.ProfileEntry{
		entry("main", "twitter", "read"),
	}})
	dlp = findPack(t, got, "dlp-guard")
	if dlp.Mode != ModeEnforce {
		t.Fatalf("dlp-guard mode = %q with non-empty profile, want enforce", dlp.Mode)
	}
}

// TestProposeReadOnlyLocksAgent: a principal that only ever read a surface gets
// that surface's pack in enforce, scoped to that principal via PerAgent, and the
// pack is not globally forced to enforce.
func TestProposeReadOnlyLocksAgent(t *testing.T) {
	p := sinks.Profile{Entries: []sinks.ProfileEntry{
		entry("llm-twitter", "twitter", "read"),
		entry("llm-twitter", "twitter", "read"),
	}}
	got := ProposeFromProfile(p)
	social := findPack(t, got, "social-guard")
	if social.PerAgent["llm-twitter"] != ModeEnforce {
		t.Fatalf("social-guard PerAgent = %v, want llm-twitter:enforce", social.PerAgent)
	}
	// Read-only lock is per-agent; the global pack mode must not be enforce
	// (nothing sensitive was ever observed globally).
	if social.Mode == ModeEnforce {
		t.Fatalf("social-guard global mode = enforce, want a non-enforce base (per-agent lock only)")
	}
}

// TestProposeSensitiveVerbAsksGloballyWithAllowlist: a principal that sent email
// to a small stable set of addresses yields google-guard in ask, with those
// addresses seeded into contact_allowlist.
func TestProposeSensitiveVerbAsksGloballyWithAllowlist(t *testing.T) {
	p := sinks.Profile{Entries: []sinks.ProfileEntry{
		entry("main", "email", "send", "alice@x.com"),
		entry("main", "email", "send", "bob@x.com", "carol@x.com"),
	}}
	got := ProposeFromProfile(p)
	g := findPack(t, got, "google-guard")
	if g.Mode != ModeAsk {
		t.Fatalf("google-guard mode = %q, want ask", g.Mode)
	}
	allow := stringSet(g.Params["contact_allowlist"])
	want := []string{"alice@x.com", "bob@x.com", "carol@x.com"}
	if !reflect.DeepEqual(allow, want) {
		t.Fatalf("contact_allowlist = %v, want %v", allow, want)
	}
}

// TestProposeCommsSensitiveSeedsRecipientAllowlist: a comms send seeds the
// recipient_allowlist (the comms pack's allowlist key), not contact_allowlist.
func TestProposeCommsSensitiveSeedsRecipientAllowlist(t *testing.T) {
	p := sinks.Profile{Entries: []sinks.ProfileEntry{
		entry("main", "comms", "dm", "mum"),
	}}
	got := ProposeFromProfile(p)
	c := findPack(t, got, "comms-guard")
	if c.Mode != ModeAsk {
		t.Fatalf("comms-guard mode = %q, want ask", c.Mode)
	}
	allow := stringSet(c.Params["recipient_allowlist"])
	if !reflect.DeepEqual(allow, []string{"mum"}) {
		t.Fatalf("recipient_allowlist = %v, want [mum]", allow)
	}
}

// TestProposeNeverSeenDestructiveLeftAtDefault: a surface never observed is not
// fabricated into the proposal (except dlp-guard). No infra activity → no
// infra-guard pack proposed.
func TestProposeNeverSeenDestructiveLeftAtDefault(t *testing.T) {
	p := sinks.Profile{Entries: []sinks.ProfileEntry{
		entry("main", "twitter", "read"),
	}}
	got := ProposeFromProfile(p)
	if hasPack(got, "infra-guard") {
		t.Fatalf("infra-guard proposed despite no infra activity: %v", packIDs(got))
	}
	if hasPack(got, "github-guard") {
		t.Fatalf("github-guard proposed despite no github activity: %v", packIDs(got))
	}
}

// TestProposeManyTargetsNotSeeded: when the observed target set is large (not a
// small stable set) the pack is still ask but the allowlist is left empty rather
// than seeded with a sprawling list.
func TestProposeManyTargetsNotSeeded(t *testing.T) {
	e := entry("main", "email", "send")
	e.Targets = map[string]int{}
	for i := 0; i < maxAllowlistSeed+1; i++ {
		e.Targets[string(rune('a'+i))+"@x.com"] = 1
	}
	p := sinks.Profile{Entries: []sinks.ProfileEntry{e}}
	got := ProposeFromProfile(p)
	g := findPack(t, got, "google-guard")
	if g.Mode != ModeAsk {
		t.Fatalf("google-guard mode = %q, want ask", g.Mode)
	}
	if allow := stringSet(g.Params["contact_allowlist"]); len(allow) != 0 {
		t.Fatalf("contact_allowlist seeded with %d targets, want empty (not a small stable set)", len(allow))
	}
}

// TestProposeMixedReadAndSensitiveSameSurface: one agent reads twitter (locks it)
// while another posts (asks globally). Both facets land on social-guard.
func TestProposeMixedReadAndSensitiveSameSurface(t *testing.T) {
	p := sinks.Profile{Entries: []sinks.ProfileEntry{
		entry("llm-reader", "twitter", "read"),
		entry("llm-poster", "twitter", "post"),
	}}
	got := ProposeFromProfile(p)
	social := findPack(t, got, "social-guard")
	if social.Mode != ModeAsk {
		t.Fatalf("social-guard mode = %q, want ask (a principal posted)", social.Mode)
	}
	if social.PerAgent["llm-reader"] != ModeEnforce {
		t.Fatalf("social-guard PerAgent = %v, want llm-reader:enforce", social.PerAgent)
	}
	// The poster read-locked nothing, so it must not get a per-agent enforce.
	if _, ok := social.PerAgent["llm-poster"]; ok {
		t.Fatalf("social-guard PerAgent unexpectedly locked the poster: %v", social.PerAgent)
	}
}

// stringSet coerces a Params allowlist value ([]any of strings, or []string)
// into a []string for comparison.
func stringSet(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
