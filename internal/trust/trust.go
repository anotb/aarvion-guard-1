package trust

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

const linuxCertPath = "/usr/local/share/ca-certificates/aarvion-guard.crt"

// Install makes the guard CA trusted so intercepted TLS validates for
// system-trust-store clients (gh, git, curl, Go). Writing to the system trust
// store needs root, so this elevates via sudo (prompting once) unless already
// root. OpenClaw's Node runtime is handled separately via NODE_EXTRA_CA_CERTS.
func Install(caCertPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return elevate("security", "add-trusted-cert", "-d", "-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain", caCertPath)
	case "linux":
		if err := elevate("cp", caCertPath, linuxCertPath); err != nil {
			return err
		}
		return elevate("update-ca-certificates")
	default:
		return fmt.Errorf("CA trust install unsupported on %s", runtime.GOOS)
	}
}

func Remove(caCertPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return elevate("security", "remove-trusted-cert", "-d", caCertPath)
	case "linux":
		_ = elevate("rm", "-f", linuxCertPath)
		return elevate("update-ca-certificates")
	default:
		return nil
	}
}

// elevate runs a command as root, via sudo (with the terminal attached so it
// can prompt) when we aren't already root.
func elevate(bin string, args ...string) error {
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.Command(bin, args...)
	} else {
		cmd = exec.Command("sudo", append([]string{bin}, args...)...)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
