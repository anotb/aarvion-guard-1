package opa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/config"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// Pinned to match the production data plane's OPA so policy eval is identical.
const opaVersion = "0.68.0"

// opaAssets maps GOOS/GOARCH to the release asset name served by
// openpolicyagent.org for opaVersion. These were verified live (HTTP 200
// following redirects); the naming is inconsistent across platforms (some carry
// a _static suffix, some don't), so they are enumerated explicitly rather than
// derived.
var opaAssets = map[string]string{
	"darwin/amd64": "opa_darwin_amd64",
	"darwin/arm64": "opa_darwin_arm64_static",
	"linux/amd64":  "opa_linux_amd64_static",
	"linux/arm64":  "opa_linux_arm64_static",
}

// opaSHA256 pins the sha256 of each opaVersion asset. Enforced unconditionally
// after download so a compromised mirror or MITM can't slip a different binary
// past the HTTPS transport. Regenerate for a version bump by downloading each
// asset in opaAssets and running `shasum -a 256`.
var opaSHA256 = map[string]string{
	"darwin/amd64": "cbe0f536725ddd594c7c44c298a20a95bc7eb63b5404d240b92199ef24573d41",
	"darwin/arm64": "bde5d5f1b50b19d4f044a8a10cc018a324aa5ca014dd81cf7a0c89c68533dda7",
	"linux/amd64":  "dfd5081fc6f930dfeaf2a225e31e616fc227dc0c7b43019b73d6f8fb8a1de1aa",
	"linux/arm64":  "1a583e593cdf4931c0b0bbedd3c9f585012953449115bcc3e15b3806d0f5ee68",
}

const configTemplate = `services:
  aarvion-cp:
    url: %s
    headers:
      Authorization: "Bearer %s"
keys:
  aarvion:
    algorithm: HS256
    key: %s
bundles:
  policy:
    service: aarvion-cp
    resource: api/v1/bundles/%s/%s/policy.tar.gz
    persist: false
    signing:
      keyid: aarvion
    polling:
      min_delay_seconds: 5
      max_delay_seconds: 15
`

// RenderConfig writes the OPA config that pulls and verifies this entity's
// signed bundle from the control plane.
func RenderConfig(c *config.Config) error {
	body := fmt.Sprintf(configTemplate, c.CPUrl, c.EnrollmentToken, c.SigningSecret, c.Tenant, c.EntityID)
	return os.WriteFile(config.OPAConfigPath(), []byte(body), 0o600)
}

// Binary resolves the opa executable: the guard-managed pinned copy under
// ~/.aarvion/bin takes precedence, else whatever is on PATH.
func Binary() (string, error) {
	local := localBinPath()
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	return exec.LookPath("opa")
}

func localBinPath() string { return filepath.Join(config.Dir(), "bin", "opa") }

// platformKey identifies the current build target for asset/pin lookup.
func platformKey() string { return runtime.GOOS + "/" + runtime.GOARCH }

// wantSHA returns the checksum EnsureBinary must enforce for the given platform.
// AARVION_OPA_SHA256 overrides the baked pin so a pinned-version upgrade can be
// rolled out without a code change; otherwise the baked pin is authoritative.
func wantSHA(platform string) (string, error) {
	if env := os.Getenv("AARVION_OPA_SHA256"); env != "" {
		return env, nil
	}
	pin, ok := opaSHA256[platform]
	if !ok {
		return "", fmt.Errorf("no pinned opa sha256 for %s; install opa manually", platform)
	}
	return pin, nil
}

// verifySHA compares a computed digest against the expected pin, case-insensitively.
func verifySHA(got, want string) error {
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("opa checksum mismatch: got %s want %s", got, want)
	}
	return nil
}

// EnsureBinary returns a usable opa path. It guarantees ~/.aarvion/bin/opa is the
// pinned opaVersion build: if the managed copy is missing or fails its sha256
// pin, a fresh copy is downloaded and verified. A verified managed copy is
// always preferred, so once present the guard runs offline. If no managed copy
// exists and only a PATH opa is available, its version is checked and a warning
// is logged when it differs from opaVersion. The sha256 pin is enforced
// unconditionally after every download (fail closed, temp deleted on mismatch);
// AARVION_OPA_SHA256 overrides the baked pin for pinned-version upgrades.
func EnsureBinary(ctx context.Context) (string, error) {
	dest := localBinPath()

	// A managed copy that matches the pin wins outright (works offline).
	if want, err := wantSHA(platformKey()); err == nil {
		if sum, err := fileSHA256(dest); err == nil && verifySHA(sum, want) == nil {
			return dest, nil
		}
	}

	// No good managed copy. If we can't self-provision this platform, fall back
	// to a PATH opa (warning if version-skewed) before giving up.
	url, err := downloadURL()
	if err != nil {
		if p, lookErr := exec.LookPath("opa"); lookErr == nil {
			warnIfSkewed(ctx, p)
			return p, nil
		}
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	if err := downloadPinned(ctx, url, dest); err != nil {
		// Last resort: a PATH opa lets the guard keep running (with a warning)
		// even if provisioning failed (e.g. offline with no managed copy).
		if p, lookErr := exec.LookPath("opa"); lookErr == nil {
			fmt.Fprintf(os.Stderr, "[opa] could not provision pinned opa %s (%v); using PATH opa\n", opaVersion, err)
			warnIfSkewed(ctx, p)
			return p, nil
		}
		return "", err
	}
	return dest, nil
}

// downloadPinned fetches url into a temp file in dest's dir, enforces the sha256
// pin, and atomically renames into place. Using os.CreateTemp (rather than a
// fixed dest+".tmp") avoids clobbering between concurrently starting guards.
func downloadPinned(ctx context.Context, url, dest string) error {
	want, err := wantSHA(platformKey())
	if err != nil {
		return err
	}

	fmt.Printf("fetching policy engine (opa %s)...\n", opaVersion)
	dlCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("opa download %s: %s", url, resp.Status)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), "opa-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Ensure the temp is cleaned up unless we successfully rename it away.
	renamed := false
	defer func() {
		if !renamed {
			os.Remove(tmpName)
		}
	}()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	sum := hex.EncodeToString(h.Sum(nil))
	if err := verifySHA(sum, want); err != nil {
		return err
	}

	if err := os.Rename(tmpName, dest); err != nil {
		return err
	}
	renamed = true
	return nil
}

// fileSHA256 returns the hex sha256 of a file, or an error if it can't be read.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// warnIfSkewed logs when a PATH opa reports a version other than opaVersion, so
// operators notice policy-eval drift from the managed build.
func warnIfSkewed(ctx context.Context, bin string) {
	v, err := opaBinaryVersion(ctx, bin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[opa] using PATH opa %s (could not read version: %v); guard pins %s\n", bin, err, opaVersion)
		return
	}
	if v != opaVersion {
		fmt.Fprintf(os.Stderr, "[opa] WARNING: PATH opa is %s but guard pins %s; policy eval may differ. Remove it or let guard manage ~/.aarvion/bin/opa\n", v, opaVersion)
	}
}

// opaBinaryVersion runs `opa version` and parses the reported version string.
func opaBinaryVersion(ctx context.Context, bin string) (string, error) {
	vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(vctx, bin, "version").Output()
	if err != nil {
		return "", err
	}
	return parseOPAVersion(string(out)), nil
}

// parseOPAVersion extracts the version from `opa version` output, whose first
// line reads e.g. "Version: 0.68.0".
func parseOPAVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Version:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// downloadURL returns the pinned opa asset URL for the current platform.
func downloadURL() (string, error) {
	asset, ok := opaAssets[platformKey()]
	if !ok {
		return "", fmt.Errorf("no pinned opa build for %s; install opa manually", platformKey())
	}
	return fmt.Sprintf("https://openpolicyagent.org/downloads/v%s/%s", opaVersion, asset), nil
}

// Supervisor runs the OPA sidecar and keeps it alive with backoff.
type Supervisor struct {
	addr string
}

func New(addr string) *Supervisor { return &Supervisor{addr: addr} }

// Run blocks until ctx is cancelled, restarting OPA if it exits early.
func (s *Supervisor) Run(ctx context.Context) error {
	bin, err := Binary()
	if err != nil {
		return fmt.Errorf("opa binary not found (install opa or ship it under ~/.aarvion/bin): %w", err)
	}

	backoff := time.Second
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, bin,
			"run", "--server",
			"--addr", s.addr,
			"--config-file", config.OPAConfigPath(),
		)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr

		start := time.Now()
		runErr := cmd.Run()
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		}
		fmt.Fprintf(os.Stderr, "[opa] exited (%v); restarting in %s\n", runErr, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	return nil
}

// WaitHealthy blocks until OPA answers or the deadline passes.
func (s *Supervisor) WaitHealthy(ctx context.Context, timeout time.Duration) error {
	client := policy.New(s.addr)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if client.Healthy(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("opa did not become healthy at %s", strings.TrimPrefix(s.addr, "http://"))
}
