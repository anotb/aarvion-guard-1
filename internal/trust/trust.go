package trust

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const linuxCertPath = "/usr/local/share/ca-certificates/aarvion-guard.crt"

// Install makes the guard CA trusted so intercepted TLS validates for
// system-trust-store clients (gh, git, curl, Go). On macOS this prompts once
// for admin. OpenClaw's Node runtime is handled separately via
// NODE_EXTRA_CA_CERTS in the service-env.
func Install(caCertPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return run("security", "add-trusted-cert", "-d", "-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain", caCertPath)
	case "linux":
		data, err := os.ReadFile(caCertPath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(linuxCertPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(linuxCertPath, data, 0o644); err != nil {
			return err
		}
		return run("update-ca-certificates")
	default:
		return fmt.Errorf("CA trust install unsupported on %s", runtime.GOOS)
	}
}

func Remove(caCertPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return run("security", "remove-trusted-cert", "-d", caCertPath)
	case "linux":
		_ = os.Remove(linuxCertPath)
		return run("update-ca-certificates")
	default:
		return nil
	}
}

func run(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", bin, err, out)
	}
	return nil
}
