package packs

import (
	"path/filepath"
	"testing"

	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
)

// TestApiGuardHostAllowlistFires proves the api-guard host allowlist actually
// gates egress: the normalizer targets an api action on its HOST, so a
// {Surfaces:[api], NotTargets: host_allowlist} rule fires for an off-allowlist
// host and stays silent for an allowlisted one. (Regression guard for the fix
// that made api actions carry the host, not the full URL, in Targets.)
func TestApiGuardHostAllowlistFires(t *testing.T) {
	set := Set{Packs: []Pack{{
		ID:    "api-guard",
		Title: "API",
		Mode:  ModeEnforce,
		Params: map[string]any{
			"host_allowlist":    []any{"good.com"},
			"block_destructive": true,
		},
	}}}

	st, err := overlay.Load(filepath.Join(t.TempDir(), "overlay.json"))
	if err != nil {
		t.Fatalf("overlay.Load: %v", err)
	}
	if err := st.Replace(CompileOverlay(set)); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	// An off-allowlist host is gated.
	if _, ok := st.Match(overlay.Action{Surface: "api", Verb: "call", Host: "bad.com", Targets: []string{"bad.com"}}); !ok {
		t.Errorf("api call to bad.com should be gated by the host allowlist")
	}
	// An allowlisted host passes the allowlist rule (a read is not otherwise gated).
	if r, ok := st.Match(overlay.Action{Surface: "api", Verb: "read", Host: "good.com", Targets: []string{"good.com"}}); ok {
		t.Errorf("api read to good.com should not be gated, matched %q", r.ID)
	}
}
