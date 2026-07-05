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

// Binary resolves the opa executable: a guard-managed copy under ~/.aarvion/bin
// takes precedence, else whatever is on PATH.
func Binary() (string, error) {
	local := localBinPath()
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	return exec.LookPath("opa")
}

func localBinPath() string { return filepath.Join(config.Dir(), "bin", "opa") }

// EnsureBinary returns a usable opa path, downloading a pinned build into
// ~/.aarvion/bin on first run if opa isn't already present. Set
// AARVION_OPA_SHA256 to enforce a checksum pin; otherwise the HTTPS transport
// is the integrity guarantee and a warning is logged.
func EnsureBinary(ctx context.Context) (string, error) {
	if p, err := Binary(); err == nil {
		return p, nil
	}
	dest := localBinPath()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	url, err := downloadURL()
	if err != nil {
		return "", err
	}

	fmt.Printf("fetching policy engine (opa %s)...\n", opaVersion)
	dlCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("opa download %s: %s", url, resp.Status)
	}

	tmp := dest + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	f.Close()

	sum := hex.EncodeToString(h.Sum(nil))
	if want := os.Getenv("AARVION_OPA_SHA256"); want != "" {
		if !strings.EqualFold(want, sum) {
			os.Remove(tmp)
			return "", fmt.Errorf("opa checksum mismatch: got %s want %s", sum, want)
		}
	} else {
		fmt.Fprintln(os.Stderr, "[opa] no AARVION_OPA_SHA256 pin set; trusting HTTPS transport")
	}

	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func downloadURL() (string, error) {
	var asset string
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/amd64":
		asset = "opa_darwin_amd64"
	case "darwin/arm64":
		asset = "opa_darwin_arm64"
	case "linux/amd64":
		asset = "opa_linux_amd64_static"
	case "linux/arm64":
		asset = "opa_linux_arm64_static"
	default:
		return "", fmt.Errorf("no pinned opa build for %s/%s; install opa manually", runtime.GOOS, runtime.GOARCH)
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
