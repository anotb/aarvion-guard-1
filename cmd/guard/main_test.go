package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
	"github.com/aarvion-ai/aarvion-guard/internal/packs"
)

// emptyOverlay builds a fresh, file-backed overlay store on a temp path (missing
// file → empty store), so a test can Replace/Rules against a real Store.
func emptyOverlay(t *testing.T) *overlay.Store {
	t.Helper()
	ov, err := overlay.Load(filepath.Join(t.TempDir(), "overlay.json"))
	if err != nil {
		t.Fatalf("overlay.Load: %v", err)
	}
	return ov
}

// handRule is a hand-authored (non-"pack:") tighten-only rule an operator wrote in
// the console. mergePacks must never drop or clobber it.
func handRule(id string) overlay.Rule {
	return overlay.Rule{
		ID:      id,
		Match:   overlay.Match{Surfaces: []string{"twitter"}, Verbs: []string{"post"}},
		Verdict: overlay.VerdictDeny,
		Reason:  "hand-authored",
		Enabled: true,
	}
}

// mergePacks must preserve hand-authored overlay rules: only prior "pack:"-prefixed
// rules are replaced by the freshly compiled pack rules; everything else survives.
func TestMergePacksPreservesHandAuthoredRules(t *testing.T) {
	ov := emptyOverlay(t)
	if err := ov.Replace([]overlay.Rule{handRule("hand:no-tweets")}); err != nil {
		t.Fatalf("seed hand rule: %v", err)
	}

	set := packs.Set{Packs: []packs.Pack{{ID: "social-guard", Mode: "enforce"}}}
	if err := mergePacks(ov, set); err != nil {
		t.Fatalf("mergePacks: %v", err)
	}

	rules := ov.Rules()
	var hand, pack int
	for _, r := range rules {
		switch {
		case r.ID == "hand:no-tweets":
			hand++
		case strings.HasPrefix(r.ID, "pack:"):
			pack++
		}
	}
	if hand != 1 {
		t.Fatalf("hand-authored rule not preserved: want 1, got %d (rules=%v)", hand, ruleIDs(rules))
	}
	if pack == 0 {
		t.Fatalf("no pack rules compiled in: %v", ruleIDs(rules))
	}
}

// Re-applying packs must be idempotent: the SECOND merge replaces the prior
// "pack:" rules rather than appending them, so Replace never fails on a duplicate
// id and the hand rule still survives.
func TestMergePacksReapplyIsIdempotent(t *testing.T) {
	ov := emptyOverlay(t)
	if err := ov.Replace([]overlay.Rule{handRule("hand:no-tweets")}); err != nil {
		t.Fatalf("seed hand rule: %v", err)
	}
	set := packs.Set{Packs: []packs.Pack{{ID: "social-guard", Mode: "enforce"}}}

	if err := mergePacks(ov, set); err != nil {
		t.Fatalf("first mergePacks: %v", err)
	}
	firstPack := countPrefix(ov.Rules(), "pack:")

	// Second application of the SAME set must not duplicate-id-fail and must not
	// grow the pack-rule count.
	if err := mergePacks(ov, set); err != nil {
		t.Fatalf("second mergePacks (idempotency): %v", err)
	}
	secondPack := countPrefix(ov.Rules(), "pack:")

	if secondPack != firstPack {
		t.Fatalf("re-apply changed pack rule count: first=%d second=%d", firstPack, secondPack)
	}
	if countPrefix(ov.Rules(), "hand:") != 1 {
		t.Fatalf("hand-authored rule lost on re-apply: %v", ruleIDs(ov.Rules()))
	}
}

// Disabling a pack (empty set) after it was applied must strip its "pack:" rules
// while keeping the hand-authored ones.
func TestMergePacksEmptySetStripsPackRulesKeepsHand(t *testing.T) {
	ov := emptyOverlay(t)
	if err := ov.Replace([]overlay.Rule{handRule("hand:no-tweets")}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := mergePacks(ov, packs.Set{Packs: []packs.Pack{{ID: "social-guard", Mode: "enforce"}}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if countPrefix(ov.Rules(), "pack:") == 0 {
		t.Fatal("expected pack rules after apply")
	}

	// Now the operator disables everything: an empty set compiles to no pack rules.
	if err := mergePacks(ov, packs.Set{}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if got := countPrefix(ov.Rules(), "pack:"); got != 0 {
		t.Fatalf("pack rules not stripped on empty set: got %d", got)
	}
	if countPrefix(ov.Rules(), "hand:") != 1 {
		t.Fatalf("hand rule lost when packs disabled: %v", ruleIDs(ov.Rules()))
	}
}

func countPrefix(rules []overlay.Rule, prefix string) int {
	n := 0
	for _, r := range rules {
		if strings.HasPrefix(r.ID, prefix) {
			n++
		}
	}
	return n
}

func ruleIDs(rules []overlay.Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}
