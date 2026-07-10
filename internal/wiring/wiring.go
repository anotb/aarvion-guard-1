package wiring

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Each managed block in OpenClaw's service-env has its own begin/end markers so
// the proxy wiring and the govern-env wiring coexist and can be replaced or
// removed independently. The proxy markers are unchanged from prior releases for
// backward compatibility with already-wired installs.
const (
	proxyBegin = "# --- aarvion-guard (forward proxy) ---"
	proxyEnd   = "# --- end aarvion-guard ---"
	guardBegin = "# --- aarvion-guard (govern env) ---"
	guardEnd   = "# --- end aarvion-guard (govern env) ---"
)

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

// InjectProxy appends the proxy env to OpenClaw's service-env (routing its egress
// through the guard). When caCertPath is set, NODE_EXTRA_CA_CERTS is added so
// OpenClaw's Node runtime trusts the guard's intercepted TLS.
func InjectProxy(envPath, proxyURL, caCertPath string) error {
	body := []string{
		fmt.Sprintf("export HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("export https_proxy=%s", proxyURL),
		fmt.Sprintf("export HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("export http_proxy=%s", proxyURL),
		"export NO_PROXY=127.0.0.1,localhost,::1",
		"export no_proxy=127.0.0.1,localhost,::1",
	}
	if caCertPath != "" {
		body = append(body, fmt.Sprintf("export NODE_EXTRA_CA_CERTS=%s", caCertPath))
	}
	return writeBlock(envPath, proxyBegin, proxyEnd, body)
}

// InjectGuardEnv writes the OPENCLAW_GUARD_* env the plugin reads (socket path +
// token + fail-mode + governed tool set) into OpenClaw's service-env, so the PEP
// plugin can reach the guard PDP. Its own marker block, so it coexists with the
// proxy block and is replaced idempotently on re-run.
func InjectGuardEnv(envPath, socket, token, failMode, tools string) error {
	body := []string{
		"export OPENCLAW_GUARD_ENABLED=1",
		fmt.Sprintf("export OPENCLAW_GUARD_SOCKET=%s", socket),
		fmt.Sprintf("export OPENCLAW_GUARD_TOKEN=%s", token),
		fmt.Sprintf("export OPENCLAW_GUARD_FAIL_MODE=%s", failMode),
		fmt.Sprintf("export OPENCLAW_GUARD_TOOLS=%s", tools),
	}
	return writeBlock(envPath, guardBegin, guardEnd, body)
}

// writeBlock appends a marker-delimited block to envPath, backing the original up
// once and replacing (not stacking) any prior block with the same markers.
func writeBlock(envPath, begin, end string, body []string) error {
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

	cleaned := stripNamedBlock(string(existing), begin, end)
	lines := append([]string{begin}, body...)
	lines = append(lines, end)

	out := cleaned
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += strings.Join(lines, "\n") + "\n"
	return os.WriteFile(envPath, []byte(out), 0o600)
}

// Restore removes both aarvion blocks (or restores the pre-injection backup).
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
	cleaned := stripNamedBlock(string(existing), proxyBegin, proxyEnd)
	cleaned = stripNamedBlock(cleaned, guardBegin, guardEnd)
	return os.WriteFile(envPath, []byte(cleaned), 0o600)
}

// stripNamedBlock removes a single begin..end marker block (exact-line match) and
// leaves the rest untouched.
func stripNamedBlock(content, begin, end string) string {
	if !strings.Contains(content, begin) {
		return content
	}
	lines := strings.Split(content, "\n")
	var out []string
	skip := false
	for _, ln := range lines {
		if strings.TrimSpace(ln) == begin {
			skip = true
			continue
		}
		if skip {
			if strings.TrimSpace(ln) == end {
				skip = false
			}
			continue
		}
		out = append(out, ln)
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}
