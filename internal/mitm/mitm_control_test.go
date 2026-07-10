package mitm

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/control"
	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// frozenController returns a Controller whose freeze file exists (kill-switch on).
func frozenController(t *testing.T) *control.Controller {
	t.Helper()
	freeze := filepath.Join(t.TempDir(), "freeze")
	if err := os.WriteFile(freeze, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c := control.New(freeze, "", time.Minute, time.Second)
	c.Refresh()
	return c
}

// breakGlassController returns a Controller with a fresh break-glass file inside
// a long window, so the bypass is active.
func breakGlassController(t *testing.T) *control.Controller {
	t.Helper()
	bg := filepath.Join(t.TempDir(), "breakglass")
	if err := os.WriteFile(bg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c := control.New("", bg, time.Hour, time.Second)
	c.Refresh()
	return c
}

// While frozen, the guard hard-denies everything — including an essential host
// that OPA would allow. Freeze overrides the fail-closed-with-essential posture.
func TestDecideFrozenDeniesEvenEssential(t *testing.T) {
	opa := allowAllOPA(t) // OPA would ALLOW; a deny proves freeze short-circuits it
	d := Deps{
		Pol:       policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:       decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Essential: Essentials([]string{"api.anthropic.com"}),
		Control:   frozenController(t),
	}
	dec := d.Decide("GET", "api.anthropic.com", "/", "", nil)
	if dec.Allowed {
		t.Fatalf("frozen guard must deny even an essential host: %+v", dec)
	}
	if dec.HTTPStatus != http.StatusForbidden || dec.Reason != "frozen" || dec.PolicyID != "guard" || !dec.Enforced {
		t.Fatalf("frozen decision = %+v, want 403 reason=frozen policy_id=guard enforced=true", dec)
	}
}

// Break-glass opens a fully-audited bypass: even an OPA-denied host is allowed,
// but the decision is marked non-enforced so the audit shows a bypass rather
// than a policy-backed allow.
func TestDecideBreakGlassAllowsNonEnforced(t *testing.T) {
	opa := denyAllOPA(t) // OPA would DENY; an allow proves break-glass overrides it
	d := Deps{
		Pol:     policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:     decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Control: breakGlassController(t),
	}
	dec := d.Decide("POST", "evil.example", "/", "", nil)
	if !dec.Allowed {
		t.Fatalf("break-glass must allow even an OPA-denied host: %+v", dec)
	}
	if dec.Reason != "break_glass" || dec.Enforced {
		t.Fatalf("break-glass decision = %+v, want reason=break_glass enforced=false", dec)
	}
}

// When both levers are pulled at once, freeze (deny-all) must win over
// break-glass (allow-all): a compromised agent stays stopped.
func TestDecideFrozenBeatsBreakGlass(t *testing.T) {
	opa := allowAllOPA(t)
	dir := t.TempDir()
	freeze := filepath.Join(dir, "freeze")
	bg := filepath.Join(dir, "breakglass")
	for _, p := range []string{freeze, bg} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := control.New(freeze, bg, time.Hour, time.Second)
	c.Refresh()

	d := Deps{
		Pol:     policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:     decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Control: c,
	}
	dec := d.Decide("GET", "any.example", "/", "", nil)
	if dec.Allowed || dec.Reason != "frozen" {
		t.Fatalf("freeze must take precedence over break-glass: %+v", dec)
	}
}

// A nil controller (control disabled) must not touch the decision path: OPA's
// verdict stands exactly as before the feature.
func TestDecideNilControllerUnchanged(t *testing.T) {
	opa := denyAllOPA(t)
	d := Deps{
		Pol:     policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:     decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Control: nil,
	}
	dec := d.Decide("GET", "evil.example", "/", "", nil)
	if dec.Allowed || dec.Reason == "frozen" || dec.Reason == "break_glass" {
		t.Fatalf("nil controller must leave OPA governance intact: %+v", dec)
	}
}
