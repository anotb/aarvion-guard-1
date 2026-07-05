package wiring

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const marker = "# --- aarvion-guard (forward proxy) ---"

// ServiceEnvPath returns OpenClaw's gateway service-env file, or "" if no
// OpenClaw install is found under home.
func ServiceEnvPath(openclawHome string) string {
	if openclawHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		openclawHome = filepath.Join(home, ".openclaw")
	}
	if _, err := os.Stat(openclawHome); err != nil {
		return ""
	}
	return filepath.Join(openclawHome, "service-env", "ai.openclaw.gateway.env")
}

// InjectProxy appends the proxy env to OpenClaw's service-env, backing up the
// original once. Idempotent: a prior aarvion block is replaced, not stacked.
func InjectProxy(envPath, proxyURL string) error {
	if err := os.MkdirAll(filepath.Dir(envPath), 0o755); err != nil {
		return err
	}
	existing, _ := os.ReadFile(envPath)

	if len(existing) > 0 {
		backup := envPath + ".aarvion.bak"
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			if err := os.WriteFile(backup, existing, 0o600); err != nil {
				return err
			}
		}
	}

	cleaned := stripBlock(string(existing))
	block := strings.Join([]string{
		marker,
		fmt.Sprintf("export HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("export https_proxy=%s", proxyURL),
		fmt.Sprintf("export HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("export http_proxy=%s", proxyURL),
		"export NO_PROXY=127.0.0.1,localhost,::1",
		"export no_proxy=127.0.0.1,localhost,::1",
		"# --- end aarvion-guard ---",
	}, "\n")

	out := cleaned
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += block + "\n"
	return os.WriteFile(envPath, []byte(out), 0o600)
}

// Restore removes the aarvion block (or restores the backup if present).
func Restore(envPath string) error {
	backup := envPath + ".aarvion.bak"
	if raw, err := os.ReadFile(backup); err == nil {
		if err := os.WriteFile(envPath, raw, 0o600); err != nil {
			return err
		}
		return os.Remove(backup)
	}
	existing, err := os.ReadFile(envPath)
	if err != nil {
		return nil
	}
	return os.WriteFile(envPath, []byte(stripBlock(string(existing))), 0o600)
}

func stripBlock(content string) string {
	if !strings.Contains(content, marker) {
		return content
	}
	lines := strings.Split(content, "\n")
	var out []string
	skip := false
	for _, ln := range lines {
		if strings.TrimSpace(ln) == marker {
			skip = true
			continue
		}
		if skip {
			if strings.TrimSpace(ln) == "# --- end aarvion-guard ---" {
				skip = false
			}
			continue
		}
		out = append(out, ln)
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}
