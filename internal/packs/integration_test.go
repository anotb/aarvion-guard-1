package packs

import (
	"testing"

	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
)

// catalogWith returns the default Catalog with the pack matching id forced to
// mode. It panics if id is not in the catalog, so a renamed pack fails loudly.
func catalogWith(t *testing.T, id, mode string) Set {
	t.Helper()
	packs := Catalog()
	found := false
	for i := range packs {
		if packs[i].ID == id {
			packs[i].Mode = mode
			found = true
		}
	}
	if !found {
		t.Fatalf("pack %q not present in Catalog()", id)
	}
	return Set{Packs: packs}
}

// TestPhaseBIntegration exercises the whole Phase B overlay path end to end:
// compile the shipped catalog (with social-guard promoted to enforce) into
// overlay rules, load them into a real overlay.Store, and drive semantic
// actions through overlay.Match exactly as the PDP does. This is the
// integration seam between the packs compiler and the overlay matcher.
func TestPhaseBIntegration(t *testing.T) {
	// Default catalog, social-guard forced to enforce. Every other pack stays at
	// its observe default, so their rules compile as Observe (recorded-only) and
	// must not turn a match into a hard deny on the enforcing social rule.
	set := catalogWith(t, "social-guard", ModeEnforce)
	rules := CompileOverlay(set)
	if len(rules) == 0 {
		t.Fatal("catalog compiled to zero rules")
	}
	s := matchStore(t, rules) // also asserts the whole set is tighten-only valid

	// 1) bird tweet "hello" -> {twitter, post}: social-guard enforce is HARD, so
	//    the matched rule denies and is NOT observe-marked.
	post := overlay.Action{Surface: "twitter", Verb: "post", Principal: "llm-twitter"}
	r, ok := s.Match(post)
	if !ok {
		t.Fatal("a twitter post was not matched by the enforcing social-guard")
	}
	if r.Verdict != overlay.VerdictDeny {
		t.Fatalf("twitter post verdict = %q, want deny", r.Verdict)
	}
	if r.Observe {
		t.Fatalf("social-guard at enforce must not be observe-marked (rule %q)", r.ID)
	}
	if r.Reason != "social_guard:write" {
		t.Fatalf("twitter post reason = %q, want social_guard:write", r.Reason)
	}

	// 2) bird search x -> {twitter, read}: the read verb is deliberately excluded
	//    from social-guard, so NO enforcing rule matches it. (Other catalog packs
	//    are observe, and none gate a bare twitter read either.)
	read := overlay.Action{Surface: "twitter", Verb: "read", Principal: "llm-twitter"}
	if rr, ok := s.Match(read); ok {
		t.Fatalf("a twitter read must not be matched, got rule %q (%s)", rr.ID, rr.Verdict)
	}

	// 3) A DLP finding: a comms send carrying a leaked secret. dlp-guard is at its
	//    observe default in this set, so the match is Observe (recorded-only) with
	//    the intrinsic hard verdict deny. This proves the DLP facet fires on the
	//    catalog and that observe leaves the verdict intrinsic while marking it
	//    non-enforcing.
	leak := overlay.Action{
		Surface:  "comms",
		Verb:     "send",
		Channel:  "telegram",
		Targets:  []string{"mum"},
		Findings: []string{"secret:ghp"},
	}
	dr, ok := s.Match(leak)
	if !ok {
		t.Fatal("a payload carrying secret:ghp was not matched by dlp-guard")
	}
	if dr.Verdict != overlay.VerdictDeny {
		t.Fatalf("dlp secret verdict = %q, want deny (intrinsic hard)", dr.Verdict)
	}
	if !dr.Observe {
		t.Fatalf("dlp-guard at its observe default must be observe-marked (rule %q)", dr.ID)
	}
	if dr.Reason != "dlp_guard:secret" {
		t.Fatalf("dlp secret reason = %q, want dlp_guard:secret", dr.Reason)
	}

	// Bonus: promoting dlp-guard to enforce makes the same leak an enforcing deny.
	enfSet := catalogWith(t, "dlp-guard", ModeEnforce)
	enf := matchStore(t, CompileOverlay(enfSet))
	er, ok := enf.Match(leak)
	if !ok {
		t.Fatal("dlp-guard enforce did not match the secret leak")
	}
	if er.Verdict != overlay.VerdictDeny || er.Observe {
		t.Fatalf("dlp-guard enforce: verdict=%q observe=%v, want deny/false", er.Verdict, er.Observe)
	}
}
