package svc

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

const (
	systemdUnit  = "/etc/systemd/system/aarvion-guard.service"
	launchdLabel = "ai.aarvion.guard"
	launchdPlist = "/Library/LaunchDaemons/ai.aarvion.guard.plist"
)

// Install registers the guard to start on boot and stay up (Restart=always /
// KeepAlive) so a crash self-heals rather than leaving OpenClaw's egress stuck.
func Install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "linux":
		return installSystemd(exe)
	case "darwin":
		return installLaunchd(exe)
	default:
		return fmt.Errorf("service install unsupported on %s", runtime.GOOS)
	}
}

func Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		_ = exec.Command("systemctl", "disable", "--now", "aarvion-guard").Run()
		_ = os.Remove(systemdUnit)
		return exec.Command("systemctl", "daemon-reload").Run()
	case "darwin":
		_ = exec.Command("launchctl", "unload", launchdPlist).Run()
		return os.Remove(launchdPlist)
	default:
		return fmt.Errorf("service uninstall unsupported on %s", runtime.GOOS)
	}
}

func installSystemd(exe string) error {
	unit := fmt.Sprintf(`[Unit]
Description=Aarvion Guard
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s run
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, exe)
	if err := os.WriteFile(systemdUnit, []byte(unit), 0o644); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "enable", "--now", "aarvion-guard").Run()
}

func installLaunchd(exe string) error {
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array><string>%s</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
`, launchdLabel, exe)
	if err := os.WriteFile(launchdPlist, []byte(plist), 0o644); err != nil {
		return err
	}
	return exec.Command("launchctl", "load", launchdPlist).Run()
}
