package wiring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The proxy and govern-env blocks coexist, each replaces itself on re-inject
// (never stacks), and Restore removes both while keeping the user's own content.
func TestInjectBothBlocksAndRestore(t *testing.T) {
	env := filepath.Join(t.TempDir(), "gateway.env")
	if err := os.WriteFile(env, []byte("export FOO=bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := InjectProxy(env, "http://127.0.0.1:8899", "/ca.crt"); err != nil {
		t.Fatal(err)
	}
	if err := InjectGuardEnv(env, "/g.sock", "tok", "closed", "actions"); err != nil {
		t.Fatal(err)
	}

	got := read(t, env)
	for _, want := range []string{
		"export FOO=bar",
		"export HTTPS_PROXY=http://127.0.0.1:8899",
		"export NODE_EXTRA_CA_CERTS=/ca.crt",
		"export OPENCLAW_GUARD_ENABLED=1",
		"export OPENCLAW_GUARD_SOCKET=/g.sock",
		"export OPENCLAW_GUARD_TOKEN=tok",
		"export OPENCLAW_GUARD_FAIL_MODE=closed",
		"export OPENCLAW_GUARD_TOOLS=actions",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}

	// Re-inject the guard block with new values → replaced, not stacked; proxy untouched.
	if err := InjectGuardEnv(env, "/g2.sock", "tok2", "open", "all"); err != nil {
		t.Fatal(err)
	}
	got = read(t, env)
	if n := strings.Count(got, "OPENCLAW_GUARD_SOCKET="); n != 1 {
		t.Fatalf("guard block stacked (%d socket lines):\n%s", n, got)
	}
	if !strings.Contains(got, "OPENCLAW_GUARD_SOCKET=/g2.sock") {
		t.Fatalf("new socket not written:\n%s", got)
	}
	if strings.Contains(got, "OPENCLAW_GUARD_SOCKET=/g.sock") {
		t.Fatalf("old socket not replaced:\n%s", got)
	}
	if n := strings.Count(got, "HTTPS_PROXY="); n != 1 {
		t.Fatalf("proxy block disturbed (%d lines):\n%s", n, got)
	}

	// Restore removes both aarvion blocks, keeps user content.
	if err := Restore(env); err != nil {
		t.Fatal(err)
	}
	got = read(t, env)
	if !strings.Contains(got, "export FOO=bar") {
		t.Fatalf("user content lost:\n%s", got)
	}
	for _, gone := range []string{"aarvion-guard", "OPENCLAW_GUARD", "HTTPS_PROXY"} {
		if strings.Contains(got, gone) {
			t.Fatalf("aarvion content %q not removed:\n%s", gone, got)
		}
	}
}
