package svc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const launchdLabel = "ai.aarvion.guard"

// Install registers the guard to run in the background as the current user
// (macOS LaunchAgent / Linux systemd user service), starting at login and
// restarting on crash. Running as the user - not root - is deliberate: the
// pairing config and CA live in the user's ~/.aarvion, and forward-proxy mode
// needs no elevated privileges.
func Install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "darwin":
		return installLaunchd(exe)
	case "linux":
		return installSystemdUser(exe)
	default:
		return fmt.Errorf("background service unsupported on %s", runtime.GOOS)
	}
}

func Uninstall() error {
	switch runtime.GOOS {
	case "darwin":
		p, err := launchAgentPath()
		if err != nil {
			return err
		}
		_ = exec.Command("launchctl", "unload", p).Run()
		_ = os.Remove(p)
		return nil
	case "linux":
		_ = exec.Command("systemctl", "--user", "disable", "--now", "aarvion-guard").Run()
		_ = os.Remove(systemdUserUnit())
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		return nil
	default:
		return fmt.Errorf("background service unsupported on %s", runtime.GOOS)
	}
}

func logPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aarvion", "guard.log")
}

func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist"), nil
}

func installLaunchd(exe string) error {
	p, err := launchAgentPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	lp := logPath()
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array><string>%s</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, launchdLabel, exe, lp, lp)
	if err := os.WriteFile(p, []byte(plist), 0o644); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "unload", p).Run()
	return exec.Command("launchctl", "load", "-w", p).Run()
}

func systemdUserUnit() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", "aarvion-guard.service")
}

func installSystemdUser(exe string) error {
	unit := fmt.Sprintf(`[Unit]
Description=Aarvion Guard
After=network-online.target

[Service]
ExecStart=%s run
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
`, exe)
	p := systemdUserUnit()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(unit), 0o644); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "--user", "enable", "--now", "aarvion-guard").Run()
}
