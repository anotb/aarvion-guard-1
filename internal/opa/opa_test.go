package opa

import (
	"strings"
	"testing"
)

// wantAssets is the set of asset names verified live against
// openpolicyagent.org for opaVersion (HTTP 200 following redirects).
var wantAssets = map[string]string{
	"darwin/amd64": "opa_darwin_amd64",
	"darwin/arm64": "opa_darwin_arm64_static",
	"linux/amd64":  "opa_linux_amd64_static",
	"linux/arm64":  "opa_linux_arm64_static",
}

func TestOPAAssetsPerPlatform(t *testing.T) {
	for platform, want := range wantAssets {
		got, ok := opaAssets[platform]
		if !ok {
			t.Errorf("opaAssets missing entry for %s", platform)
			continue
		}
		if got != want {
			t.Errorf("opaAssets[%s] = %q, want %q", platform, got, want)
		}
	}
	if len(opaAssets) != len(wantAssets) {
		t.Errorf("opaAssets has %d entries, want %d", len(opaAssets), len(wantAssets))
	}
}

func TestPinMapHasEntryPerPlatform(t *testing.T) {
	for platform := range opaAssets {
		pin, ok := opaSHA256[platform]
		if !ok {
			t.Errorf("opaSHA256 missing pin for %s", platform)
			continue
		}
		if len(pin) != 64 {
			t.Errorf("opaSHA256[%s] = %q, want 64 hex chars", platform, pin)
		}
	}
	if len(opaSHA256) != len(opaAssets) {
		t.Errorf("opaSHA256 has %d entries, opaAssets has %d; they must match", len(opaSHA256), len(opaAssets))
	}
}

func TestVerifySHA(t *testing.T) {
	const good = "cbe0f536725ddd594c7c44c298a20a95bc7eb63b5404d240b92199ef24573d41"

	if err := verifySHA(good, good); err != nil {
		t.Errorf("verifySHA(good, good) = %v, want nil", err)
	}
	// Case-insensitive: uppercased digest must still match.
	if err := verifySHA(strings.ToUpper(good), good); err != nil {
		t.Errorf("verifySHA(upper, good) = %v, want nil", err)
	}
	if err := verifySHA("deadbeef", good); err == nil {
		t.Error("verifySHA(wrong, good) = nil, want mismatch error")
	}
}

func TestParseOPAVersion(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{"standard", "Version: 0.68.0\nBuild Commit: abc123\n", "0.68.0"},
		{"leading-space", "  Version: 0.68.0  \n", "0.68.0"},
		{"absent", "Build Commit: abc123\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseOPAVersion(tc.out); got != tc.want {
				t.Errorf("parseOPAVersion(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}

func TestWantSHAOverride(t *testing.T) {
	const override = "0000000000000000000000000000000000000000000000000000000000000000"
	t.Setenv("AARVION_OPA_SHA256", override)
	got, err := wantSHA("darwin/arm64")
	if err != nil {
		t.Fatalf("wantSHA with override = %v", err)
	}
	if got != override {
		t.Errorf("wantSHA override = %q, want %q", got, override)
	}
}

func TestWantSHABakedPin(t *testing.T) {
	t.Setenv("AARVION_OPA_SHA256", "")
	got, err := wantSHA("darwin/arm64")
	if err != nil {
		t.Fatalf("wantSHA baked = %v", err)
	}
	if got != opaSHA256["darwin/arm64"] {
		t.Errorf("wantSHA baked = %q, want %q", got, opaSHA256["darwin/arm64"])
	}
	if _, err := wantSHA("plan9/mips"); err == nil {
		t.Error("wantSHA(unknown platform) = nil error, want failure")
	}
}
