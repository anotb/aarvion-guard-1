package packs

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const opaBin = "/opt/homebrew/bin/opa"

// opaPath returns the path to the opa binary, or "" if it is not available.
func opaPath(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("opa"); err == nil {
		return p
	}
	if _, err := os.Stat(opaBin); err == nil {
		return opaBin
	}
	return ""
}

// runEval writes rego+data+input to a temp dir and evaluates
// data.envoy.authz.allow, returning the decision object.
func runEval(t *testing.T, opa, rego string, data []byte, input map[string]any) map[string]any {
	t.Helper()
	dir := t.TempDir()
	regoPath := filepath.Join(dir, "governance.rego")
	dataPath := filepath.Join(dir, "data.json")
	inputPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(regoPath, []byte(rego), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	inBytes, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, inBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(opa, "eval", "-d", regoPath, "-d", dataPath, "-i", inputPath,
		"data.envoy.authz.allow", "-f", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("opa eval failed: %v\n%s", err, out)
	}

	var parsed struct {
		Result []struct {
			Expressions []struct {
				Value map[string]any `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("parse opa output: %v\n%s", err, out)
	}
	if len(parsed.Result) == 0 || len(parsed.Result[0].Expressions) == 0 {
		t.Fatalf("no result from opa eval:\n%s", out)
	}
	return parsed.Result[0].Expressions[0].Value
}

func semanticInput(action map[string]any, principal string) map[string]any {
	return map[string]any{
		"action": map[string]any{"semantic": action},
		"ctx":    map[string]any{"caller": map[string]any{"principal_id": principal}},
	}
}

func TestEmitRegoParses(t *testing.T) {
	opa := opaPath(t)
	if opa == "" {
		t.Skip("opa not available")
	}
	rego, data := EmitRego(Set{Packs: Catalog()})

	// Rego must pass `opa check` (with the data document present).
	dir := t.TempDir()
	regoPath := filepath.Join(dir, "governance.rego")
	dataPath := filepath.Join(dir, "data.json")
	if err := os.WriteFile(regoPath, []byte(rego), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(opa, "check", regoPath, dataPath).CombinedOutput()
	if err != nil {
		t.Fatalf("opa check failed: %v\n%s", err, out)
	}

	// data must be valid JSON with a packs map.
	var dm struct {
		Packs map[string]any `json:"packs"`
	}
	if err := json.Unmarshal(data, &dm); err != nil {
		t.Fatalf("data.json is not valid JSON: %v", err)
	}
	if dm.Packs == nil {
		t.Fatalf("data.json missing packs map: %s", data)
	}
	if _, ok := dm.Packs["social-guard"]; !ok {
		t.Fatalf("data.json packs missing social-guard: %s", data)
	}

	// Rego must declare package envoy.authz so the guard's entrypoint resolves.
	if !strings.Contains(rego, "package envoy.authz") {
		t.Fatalf("emitted rego missing package envoy.authz")
	}
}

func TestEmitRegoBirdTweetDenied(t *testing.T) {
	opa := opaPath(t)
	if opa == "" {
		t.Skip("opa not available")
	}
	// social-guard in enforce mode; everything else off so only social fires.
	set := Set{Packs: []Pack{{
		ID: "social-guard", Title: "Social", Mode: ModeEnforce,
	}}}
	rego, data := EmitRego(set)

	input := semanticInput(map[string]any{
		"surface": "twitter",
		"verb":    "post",
	}, "llm-twitter")

	dec := runEval(t, opa, rego, data, input)
	if allowed, _ := dec["allowed"].(bool); allowed {
		t.Fatalf("bird tweet with social-guard enforce should be denied, got %+v", dec)
	}
	if status, _ := dec["http_status"].(float64); int(status) != 403 {
		t.Fatalf("expected http_status 403, got %v (%+v)", dec["http_status"], dec)
	}
	headers, _ := dec["headers"].(map[string]any)
	if headers == nil {
		t.Fatalf("decision missing headers: %+v", dec)
	}
	if _, ok := headers["x-policy-violated"]; !ok {
		t.Fatalf("decision missing x-policy-violated header: %+v", headers)
	}
	if _, ok := headers["x-policy-reason"]; !ok {
		t.Fatalf("decision missing x-policy-reason header: %+v", headers)
	}
}

func TestEmitRegoBirdSearchAllowed(t *testing.T) {
	opa := opaPath(t)
	if opa == "" {
		t.Skip("opa not available")
	}
	set := Set{Packs: []Pack{{ID: "social-guard", Title: "Social", Mode: ModeEnforce}}}
	rego, data := EmitRego(set)

	// A read verb on twitter is not a write; social-guard must not fire.
	input := semanticInput(map[string]any{
		"surface": "twitter",
		"verb":    "read",
	}, "llm-twitter")

	dec := runEval(t, opa, rego, data, input)
	if allowed, _ := dec["allowed"].(bool); !allowed {
		t.Fatalf("bird search (read) should be allowed, got %+v", dec)
	}
}

func TestEmitRegoOffPackDoesNotFire(t *testing.T) {
	opa := opaPath(t)
	if opa == "" {
		t.Skip("opa not available")
	}
	set := Set{Packs: []Pack{{ID: "social-guard", Title: "Social", Mode: ModeOff}}}
	rego, data := EmitRego(set)

	input := semanticInput(map[string]any{"surface": "twitter", "verb": "post"}, "llm-twitter")
	dec := runEval(t, opa, rego, data, input)
	if allowed, _ := dec["allowed"].(bool); !allowed {
		t.Fatalf("off pack must not fire; twitter post should be allowed, got %+v", dec)
	}
}

func TestEmitRegoDLPSecretDenied(t *testing.T) {
	opa := opaPath(t)
	if opa == "" {
		t.Skip("opa not available")
	}
	set := Set{Packs: []Pack{{ID: "dlp-guard", Title: "DLP", Mode: ModeEnforce}}}
	rego, data := EmitRego(set)

	input := semanticInput(map[string]any{
		"surface":  "comms",
		"verb":     "send",
		"findings": []any{"secret:ghp"},
	}, "main")
	dec := runEval(t, opa, rego, data, input)
	if allowed, _ := dec["allowed"].(bool); allowed {
		t.Fatalf("dlp-guard enforce must deny a secret finding, got %+v", dec)
	}
	if status, _ := dec["http_status"].(float64); int(status) != 403 {
		t.Fatalf("dlp secret expected 403, got %v", dec["http_status"])
	}
}

func TestEmitRegoDriveDeleteDenied(t *testing.T) {
	opa := opaPath(t)
	if opa == "" {
		t.Skip("opa not available")
	}
	set := Set{Packs: []Pack{{ID: "google-guard", Title: "Google", Mode: ModeEnforce}}}
	rego, data := EmitRego(set)

	input := semanticInput(map[string]any{
		"surface": "file",
		"verb":    "delete",
		"flags":   map[string]any{"destructive": true},
	}, "main")
	dec := runEval(t, opa, rego, data, input)
	if allowed, _ := dec["allowed"].(bool); allowed {
		t.Fatalf("google-guard enforce must deny drive delete, got %+v", dec)
	}
}

func TestEmitRegoEmailSendAsks(t *testing.T) {
	opa := opaPath(t)
	if opa == "" {
		t.Skip("opa not available")
	}
	set := Set{Packs: []Pack{{ID: "google-guard", Title: "Google", Mode: ModeEnforce}}}
	rego, data := EmitRego(set)

	// Email send is soft -> ask under enforce (202 + verdict header).
	input := semanticInput(map[string]any{
		"surface": "email",
		"verb":    "send",
		"targets": []any{"someone@example.com"},
	}, "main")
	dec := runEval(t, opa, rego, data, input)
	if allowed, _ := dec["allowed"].(bool); allowed {
		t.Fatalf("email send under enforce should not be allowed outright (ask), got %+v", dec)
	}
	if status, _ := dec["http_status"].(float64); int(status) != 202 {
		t.Fatalf("ask verdict expected http_status 202, got %v (%+v)", dec["http_status"], dec)
	}
	headers, _ := dec["headers"].(map[string]any)
	if headers == nil || headers["x-aarvion-verdict"] != "ask" {
		t.Fatalf("ask verdict expected x-aarvion-verdict: ask, got %+v", headers)
	}
}

func TestEmitRegoAskModeEverythingAsks(t *testing.T) {
	opa := opaPath(t)
	if opa == "" {
		t.Skip("opa not available")
	}
	// social-guard in ask mode -> a twitter post asks, not denies.
	set := Set{Packs: []Pack{{ID: "social-guard", Title: "Social", Mode: ModeAsk}}}
	rego, data := EmitRego(set)

	input := semanticInput(map[string]any{"surface": "twitter", "verb": "post"}, "llm-twitter")
	dec := runEval(t, opa, rego, data, input)
	if status, _ := dec["http_status"].(float64); int(status) != 202 {
		t.Fatalf("ask mode should yield 202, got %v (%+v)", dec["http_status"], dec)
	}
}

func TestEmitRegoPerAgentTighten(t *testing.T) {
	opa := opaPath(t)
	if opa == "" {
		t.Skip("opa not available")
	}
	// Pack in ask, but llm-twitter tightened to enforce -> a twitter post by
	// llm-twitter is denied, while the same post by another agent asks.
	set := Set{Packs: []Pack{{
		ID: "social-guard", Title: "Social", Mode: ModeAsk,
		PerAgent: map[string]string{"llm-twitter": ModeEnforce},
	}}}
	rego, data := EmitRego(set)

	denied := runEval(t, opa, rego, data,
		semanticInput(map[string]any{"surface": "twitter", "verb": "post"}, "llm-twitter"))
	if allowed, _ := denied["allowed"].(bool); allowed {
		t.Fatalf("per-agent enforce should deny llm-twitter post, got %+v", denied)
	}
	if status, _ := denied["http_status"].(float64); int(status) != 403 {
		t.Fatalf("per-agent enforce should be 403, got %v", denied["http_status"])
	}

	asked := runEval(t, opa, rego, data,
		semanticInput(map[string]any{"surface": "twitter", "verb": "post"}, "main"))
	if status, _ := asked["http_status"].(float64); int(status) != 202 {
		t.Fatalf("base ask should apply to other agents (202), got %v", asked["http_status"])
	}
}

func TestEmitRegoDeterministic(t *testing.T) {
	set := Set{Packs: Catalog()}
	r1, d1 := EmitRego(set)
	r2, d2 := EmitRego(set)
	if r1 != r2 {
		t.Fatal("EmitRego rego output is not deterministic")
	}
	if string(d1) != string(d2) {
		t.Fatal("EmitRego data output is not deterministic")
	}
}

// TestExamplePacksSnapshot asserts the committed examples/packs/ files match the
// current emitter output for the default catalog. Regenerate with -update.
func TestExamplePacksSnapshot(t *testing.T) {
	rego, data := EmitRego(Set{Packs: Catalog()})
	root := repoRoot(t)
	regoFile := filepath.Join(root, "examples", "packs", "governance.rego")
	dataFile := filepath.Join(root, "examples", "packs", "data.json")

	if *update {
		if err := os.MkdirAll(filepath.Dir(regoFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(regoFile, []byte(rego), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dataFile, data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("updated examples/packs snapshot")
		return
	}

	wantRego, err := os.ReadFile(regoFile)
	if err != nil {
		t.Fatalf("read %s (run go test -update to generate): %v", regoFile, err)
	}
	if string(wantRego) != rego {
		t.Fatalf("examples/packs/governance.rego is stale; run: go test ./internal/packs/ -run Snapshot -update")
	}
	wantData, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatalf("read %s (run go test -update to generate): %v", dataFile, err)
	}
	if string(wantData) != string(data) {
		t.Fatalf("examples/packs/data.json is stale; run: go test ./internal/packs/ -run Snapshot -update")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// The test runs in the package dir: internal/packs. Repo root is two up.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}
