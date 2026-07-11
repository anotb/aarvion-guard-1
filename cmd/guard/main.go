package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/approve"
	"github.com/aarvion-ai/aarvion-guard/internal/ca"
	"github.com/aarvion-ai/aarvion-guard/internal/config"
	"github.com/aarvion-ai/aarvion-guard/internal/console"
	"github.com/aarvion-ai/aarvion-guard/internal/control"
	"github.com/aarvion-ai/aarvion-guard/internal/cpsync"
	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/govern"
	"github.com/aarvion-ai/aarvion-guard/internal/heartbeat"
	"github.com/aarvion-ai/aarvion-guard/internal/intercept"
	"github.com/aarvion-ai/aarvion-guard/internal/mitm"
	"github.com/aarvion-ai/aarvion-guard/internal/opa"
	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
	"github.com/aarvion-ai/aarvion-guard/internal/packs"
	"github.com/aarvion-ai/aarvion-guard/internal/pair"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
	"github.com/aarvion-ai/aarvion-guard/internal/proxy"
	"github.com/aarvion-ai/aarvion-guard/internal/ratelimit"
	"github.com/aarvion-ai/aarvion-guard/internal/sinks"
	"github.com/aarvion-ai/aarvion-guard/internal/svc"
	"github.com/aarvion-ai/aarvion-guard/internal/tproxy"
	"github.com/aarvion-ai/aarvion-guard/internal/trust"
	"github.com/aarvion-ai/aarvion-guard/internal/wiring"
)

func caCertPath() string { return filepath.Join(config.CADir(), "ca.crt") }

// version is overridden at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const (
	defaultAPIURL    = "https://api.aarvion.ai"
	defaultProxyAddr = "127.0.0.1:8899"
	defaultOPAAddr   = "127.0.0.1:8181"
)

// defaultEssentialHosts stay reachable when OPA is down (fail-closed-with-
// essential), so a policy-engine hiccup degrades the assistant instead of
// killing its brain. It covers the direct model endpoints (including
// chatgpt.com, which a real OpenClaw drives over OAuth) plus the common
// provider suffixes, where an entry beginning with "." matches by host suffix.
// Override per-install via config's essential_hosts.
var defaultEssentialHosts = []string{
	"api.anthropic.com",
	"api.openai.com",
	"chatgpt.com",
	"generativelanguage.googleapis.com",
	".openai.azure.com",
	".bedrock-runtime.amazonaws.com",
	".aiplatform.googleapis.com",
}

// essentialHosts returns the effective essential list: the config override when
// set, else the built-in defaults.
func essentialHosts(cfg *config.Config) []string {
	if len(cfg.EssentialHosts) > 0 {
		return cfg.EssentialHosts
	}
	return defaultEssentialHosts
}

// buildLimiter constructs the egress rate limiter from config, or nil when it's
// disabled. A nil limiter is threaded into the proxy/tproxy Deps unchanged, so
// "rate_limit off" is exactly the pre-feature behavior with zero overhead.
func buildLimiter(cfg *config.Config) *ratelimit.Limiter {
	rl := cfg.RateLimit
	if !rl.Enabled {
		return nil
	}
	return ratelimit.New(rl.PerMinute, time.Minute, rl.PerHost)
}

// buildAllowlist constructs the default-deny egress gate from config. An off or
// empty mode yields a zero-value Allowlist (gating disabled), which the mitm
// Decide path treats exactly as the pre-feature behavior. Host matching reuses
// mitm.Essentials so "."-suffix entries work like essential_hosts.
func buildAllowlist(cfg *config.Config) mitm.Allowlist {
	al := cfg.Allowlist
	if al.Mode == "" || al.Mode == mitm.AllowlistOff {
		return mitm.Allowlist{}
	}
	return mitm.Allowlist{Mode: al.Mode, Hosts: mitm.Essentials(al.Hosts)}
}

// buildControl constructs the file-driven emergency-lever controller (kill-switch
// + break-glass) from config, or nil when control is disabled. A nil controller
// threads into the proxy/tproxy Deps unchanged, so "control off" is exactly the
// pre-feature behavior with zero overhead. The freeze/break-glass file paths
// default to the well-known locations under the aarvion dir when unset, so an
// operator can `touch ~/.aarvion/freeze` without editing the config.
func buildControl(cfg *config.Config) *control.Controller {
	c := cfg.Control
	if !c.Enabled {
		return nil
	}
	freeze := c.FreezeFile
	if freeze == "" {
		freeze = config.FreezePath()
	}
	breakGlass := c.BreakGlassFile
	if breakGlass == "" {
		breakGlass = config.BreakGlassPath()
	}
	window := time.Duration(c.BreakGlassMinutes) * time.Minute
	poll := time.Duration(c.PollEverySeconds) * time.Second
	return control.New(freeze, breakGlass, window, poll)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "onboard":
		cmdOnboard(os.Args[2:])
	case "run":
		cmdRun()
	case "dashboard":
		cmdDashboard(os.Args[2:])
	case "exec":
		cmdExec(os.Args[2:])
	case "service":
		cmdService(os.Args[2:])
	case "update":
		cmdUpdate()
	case "repair":
		cmdRepair()
	case "status":
		cmdStatus()
	case "uninstall":
		cmdUninstall()
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `aarvion-guard — govern your local OpenClaw

usage:
  aarvion-guard onboard <pairing-code>    # one-command: pair + guard + plugin + govern OpenClaw
  aarvion-guard init <pairing-code> [--api URL] [--device NAME] [--transparent]
  aarvion-guard run                       # start the guard (root for --transparent)
  aarvion-guard dashboard                 # open the local governance console in your browser
  aarvion-guard exec -- <cmd...>          # run OpenClaw inside the governed group
  aarvion-guard service install|uninstall # run the guard as a background service
  aarvion-guard update                    # swap in a new binary, keep the pairing
  aarvion-guard repair                    # unstick egress after a hard crash
  aarvion-guard status
  aarvion-guard uninstall
  aarvion-guard version`)
}

// guardCmd is how the user invokes this binary (e.g. "npx @aarvionai/guard"),
// passed in by the npm launcher so the printed next-steps are copy-pasteable.
// Falls back to the binary name when the binary is run directly.
func guardCmd() string {
	if c := os.Getenv("AARVION_GUARD_CMD"); c != "" {
		return c
	}
	return "aarvion-guard"
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	apiURL := fs.String("api", defaultAPIURL, "Aarvion backend base URL")
	device := fs.String("device", "", "device name for this guard")
	transparent := fs.Bool("transparent", false, "bypass-proof kernel interception (Linux; needs root at run)")
	noInspect := fs.Bool("no-inspect", false, "govern HTTPS at host level only (no MITM, no CA trust)")

	positional := parseInterspersed(fs, args)
	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "error: pairing code required")
		os.Exit(2)
	}
	code := positional[0]

	if config.Exists() {
		fmt.Fprintln(os.Stderr, "error: already initialized; run `aarvion-guard uninstall` first")
		os.Exit(1)
	}

	mode := config.ModeForward
	if *transparent {
		if runtime.GOOS == "linux" {
			mode = config.ModeTransparent
		} else {
			fmt.Println("! transparent mode is Linux-only today (macOS needs a system extension).")
			fmt.Println("  Falling back to forward-proxy mode.")
		}
	}

	fmt.Println("pairing with Aarvion...")
	creds, err := pair.Claim(context.Background(), *apiURL, code, *device)
	if err != nil {
		fatal(err)
	}

	cfg := &config.Config{
		Tenant:          creds.Tenant,
		EntityID:        creds.EntityID,
		CPUrl:           creds.CPUrl,
		EnrollmentToken: creds.EnrollmentToken,
		SigningSecret:   creds.SigningSecret,
		BundleURL:       creds.BundleURL,
		DPID:            creds.EntityID + "-" + shortID(),
		Mode:            mode,
		ProxyAddr:       defaultProxyAddr,
		TransparentAddr: config.DefaultTransparentAddr,
		GuardGroup:      config.DefaultGuardGroup,
		OPAAddr:         defaultOPAAddr,
		Inspect:         !*noInspect,
		// Loopback governance console on by default: safe (127.0.0.1 + token gate)
		// and the primary way an operator authors tighten-only local overlay rules.
		Console: config.Console{Enabled: true},
	}
	if err := cfg.Save(); err != nil {
		fatal(err)
	}
	if err := opa.RenderConfig(cfg); err != nil {
		fatal(err)
	}

	fmt.Printf("\npaired as entity %s (tenant %s), mode=%s\n", cfg.EntityID, cfg.Tenant, cfg.Mode)

	if cfg.Mode == config.ModeTransparent {
		fmt.Println("next:")
		fmt.Printf("  1. sudo %s run\n", guardCmd())
		fmt.Println("     # installs the redirect + policy engine")
		fmt.Printf("  2. %s exec -- <start OpenClaw>\n", guardCmd())
		fmt.Printf("     # runs it inside group %q\n", cfg.GuardGroup)
		return
	}

	caEnv := ""
	if cfg.Inspect {
		if _, err := ca.EnsureCA(config.CADir()); err != nil {
			fatal(err)
		}
		caEnv = caCertPath()
		fmt.Println("trusting the guard CA (may prompt for your password)...")
		if err := trust.Install(caEnv); err != nil {
			fmt.Printf("! could not trust the guard CA: %v\n", err)
			fmt.Printf("  run it yourself, then `%s run`:\n    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", guardCmd(), caEnv)
			fmt.Println("  or re-init with --no-inspect for host-level governance only.")
		} else {
			fmt.Println("installed guard CA into the system trust store")
		}
	}

	envPath := wiring.ServiceEnvPath(cfg.OpenClawHome)
	if envPath == "" {
		fmt.Println("! OpenClaw install not found under ~/.openclaw — proxy env not wired.")
		fmt.Printf("  Set HTTPS_PROXY=http://%s manually, then run `%s run`.\n", cfg.ProxyAddr, guardCmd())
	} else {
		if err := wiring.InjectProxy(envPath, "http://"+cfg.ProxyAddr, caEnv); err != nil {
			fatal(err)
		}
		fmt.Printf("wired OpenClaw egress → guard (%s)\n", envPath)
	}
	if err := svc.Install(); err != nil {
		fmt.Printf("! could not install the background service: %v\n", err)
		fmt.Printf("  start it in the foreground instead: %s run\n", guardCmd())
	} else {
		fmt.Println("guard is running in the background (starts at login, restarts on crash)")
	}
	fmt.Println("last step - restart OpenClaw so it picks up the proxy:")
	if runtime.GOOS == "darwin" {
		fmt.Println("  launchctl kickstart -k gui/$(id -u)/ai.openclaw.gateway")
	}
}

// cmdOnboard is the one-command path (`npx @aarvionai/guard onboard <code>`): it
// pairs, provisions the govern PDP socket, starts the guard service, installs +
// enables the OpenClaw plugin, writes the plugin's env, and restarts the gateway.
// Re-running is safe: an existing pairing is reused and every step is idempotent.
func cmdOnboard(args []string) {
	fs := flag.NewFlagSet("onboard", flag.ExitOnError)
	apiURL := fs.String("api", defaultAPIURL, "Aarvion backend base URL")
	device := fs.String("device", "", "device name for this guard")
	noInspect := fs.Bool("no-inspect", false, "govern HTTPS at host level only (no MITM, no CA trust)")
	tools := fs.String("tools", "actions", "governed tool set: actions|all|exec")
	failMode := fs.String("fail-mode", "closed", "verdict when the guard is unreachable: closed|open")
	pluginSpec := fs.String("plugin", "@aarvion/openclaw-guard", "OpenClaw plugin package spec or local path")
	link := fs.Bool("link", false, "install the plugin from a local path with --link (dev)")
	noPlugin := fs.Bool("no-plugin", false, "skip installing the OpenClaw plugin")

	positional := parseInterspersed(fs, args)

	// Pair, or reuse an existing pairing (idempotent re-onboard).
	var cfg *config.Config
	if config.Exists() {
		c, err := config.Load()
		if err != nil {
			fatal(err)
		}
		cfg = c
		fmt.Printf("already paired as entity %s — re-onboarding\n", cfg.EntityID)
	} else {
		if len(positional) < 1 {
			fmt.Fprintln(os.Stderr, "error: pairing code required (get one from your Aarvion dashboard)")
			os.Exit(2)
		}
		fmt.Println("pairing with Aarvion...")
		creds, err := pair.Claim(context.Background(), *apiURL, positional[0], *device)
		if err != nil {
			fatal(err)
		}
		cfg = &config.Config{
			Tenant:          creds.Tenant,
			EntityID:        creds.EntityID,
			CPUrl:           creds.CPUrl,
			EnrollmentToken: creds.EnrollmentToken,
			SigningSecret:   creds.SigningSecret,
			BundleURL:       creds.BundleURL,
			DPID:            creds.EntityID + "-" + shortID(),
			Mode:            config.ModeForward,
			ProxyAddr:       defaultProxyAddr,
			TransparentAddr: config.DefaultTransparentAddr,
			GuardGroup:      config.DefaultGuardGroup,
			OPAAddr:         defaultOPAAddr,
			Inspect:         !*noInspect,
			Console:         config.Console{Enabled: true},
		}
	}
	// Ensure the loopback console is on even when reusing an existing pairing, so an
	// upgrade lights up the dashboard + overlay editor without a re-pair.
	if !cfg.Console.Enabled {
		cfg.Console.Enabled = true
	}

	// Provision the govern PDP socket so the plugin has an endpoint to call.
	if cfg.Govern.Socket.Path == "" {
		cfg.Govern.Socket.Path = filepath.Join(config.Dir(), "govern.sock")
	}
	if cfg.Govern.Socket.Token == "" {
		cfg.Govern.Socket.Token = randomSecret()
	}
	cfg.Govern.Socket.PeerUID = onboardPeerUID()
	if cfg.Govern.FailMode == nil {
		cfg.Govern.FailMode = map[string]string{}
	}
	for _, surface := range []string{"exec", "tool", "egress", "send", "mcp", "response"} {
		if cfg.Govern.FailMode[surface] == "" {
			cfg.Govern.FailMode[surface] = *failMode
		}
	}
	if err := cfg.Save(); err != nil {
		fatal(err)
	}
	if err := opa.RenderConfig(cfg); err != nil {
		fatal(err)
	}
	fmt.Printf("\npaired as entity %s (tenant %s); govern socket → %s\n", cfg.EntityID, cfg.Tenant, cfg.Govern.Socket.Path)

	// Trust the guard CA (inspect mode only). Non-fatal.
	caEnv := ""
	if cfg.Inspect {
		if _, err := ca.EnsureCA(config.CADir()); err != nil {
			fatal(err)
		}
		caEnv = caCertPath()
		if err := trust.Install(caEnv); err != nil {
			fmt.Printf("! could not trust the guard CA: %v (continuing; HTTPS bodies won't be inspected)\n", err)
		} else {
			fmt.Println("trusted the guard CA")
		}
	}

	// Wire OpenClaw's env: egress proxy + the OPENCLAW_GUARD_* the plugin reads.
	envPath := wiring.ServiceEnvPath(cfg.OpenClawHome)
	openclawPresent := envPath != ""
	if !openclawPresent {
		fmt.Println("! OpenClaw not found under ~/.openclaw — skipping plugin + gateway wiring.")
		fmt.Printf("  Install OpenClaw, then re-run `%s onboard`.\n", guardCmd())
	} else {
		if err := wiring.InjectProxy(envPath, "http://"+cfg.ProxyAddr, caEnv); err != nil {
			fmt.Printf("! could not wire egress proxy: %v\n", err)
		}
		if err := wiring.InjectGuardEnv(envPath, cfg.Govern.Socket.Path, cfg.Govern.Socket.Token, *failMode, *tools); err != nil {
			fmt.Printf("! could not write guard env: %v\n", err)
		} else {
			fmt.Printf("wired OpenClaw → guard (%s)\n", envPath)
		}
	}

	// Install + start the guard service (this is what opens the PDP socket).
	if err := svc.Install(); err != nil {
		fmt.Printf("! could not install the guard service: %v\n  start it yourself: %s run\n", err, guardCmd())
	} else {
		fmt.Println("guard service running (starts at login, restarts on crash)")
	}

	// Install + enable the OpenClaw plugin (the PEP).
	switch {
	case *noPlugin:
		fmt.Println("skipped the OpenClaw plugin (--no-plugin)")
	case !openclawPresent:
		// already messaged above
	default:
		if _, err := exec.LookPath("openclaw"); err != nil {
			fmt.Println("! `openclaw` not on PATH — install the plugin yourself:")
			fmt.Printf("    openclaw plugins install %s && openclaw plugins enable aarvion-guard\n", *pluginSpec)
		} else {
			installArgs := []string{"plugins", "install", *pluginSpec}
			if *link {
				installArgs = append(installArgs, "--link")
			}
			runOpenclaw(installArgs...)
			runOpenclaw("plugins", "enable", "aarvion-guard")
		}
	}

	// Restart the gateway so it re-reads the env + loads the plugin.
	if openclawPresent {
		restartOpenClawGateway()
	}

	fmt.Println("\n✓ governance is live — the next tool your agent runs is checked by the guard.")
	fmt.Println("  see decisions and edit policy in your Aarvion dashboard.")
}

// randomSecret returns a 32-byte hex secret for the local govern socket token.
func randomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// onboardPeerUID is the uid the OpenClaw process runs as, which the govern PDP
// requires the connecting peer to match. Under sudo, prefer the invoking user.
func onboardPeerUID() uint32 {
	if s := os.Getenv("SUDO_UID"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			return uint32(n)
		}
	}
	return uint32(os.Getuid())
}

// runOpenclaw shells out to the openclaw CLI, streaming output and tolerating
// "already installed/enabled" so onboard stays idempotent.
func runOpenclaw(args ...string) {
	cmd := exec.Command("openclaw", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("! openclaw %s: %v (safe to ignore if already installed/enabled)\n", strings.Join(args, " "), err)
	}
}

// restartOpenClawGateway restarts OpenClaw so it picks up the new env + plugin.
func restartOpenClawGateway() {
	if runtime.GOOS != "darwin" {
		fmt.Println("restart your OpenClaw gateway to pick up the changes.")
		return
	}
	uid := strconv.Itoa(os.Getuid())
	if err := exec.Command("launchctl", "kickstart", "-k", "gui/"+uid+"/ai.openclaw.gateway").Run(); err != nil {
		fmt.Println("! could not restart the OpenClaw gateway; do it manually:")
		fmt.Printf("    launchctl kickstart -k gui/%s/ai.openclaw.gateway\n", uid)
		return
	}
	fmt.Println("restarted the OpenClaw gateway")
}

// loadOverlay opens the tighten-only local overlay store, tolerating a missing
// file (an empty store). A hard load error (malformed JSON) is logged and
// disables the overlay rather than blocking guard startup.
func loadOverlay() *overlay.Store {
	st, err := overlay.Load(config.OverlayPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[overlay] disabled: %v\n", err)
		return nil
	}
	return st
}

// applyPacks compiles the operator's policy packs (~/.aarvion/packs.json) into
// tighten-only overlay rules and merges them into the shared overlay store BEFORE
// the govern server starts, so pack guardrails enforce from boot. A missing
// packs.json is a no-op (the overlay is left exactly as loaded). Any
// load/compile/replace error is logged and non-fatal — a bad pack file must not
// stop the guard.
func applyPacks(ov *overlay.Store) {
	if ov == nil {
		return
	}
	if _, err := os.Stat(config.PacksPath()); err != nil {
		return // no packs.json → leave the overlay as-is
	}
	ps, err := packs.Load(config.PacksPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[packs] disabled: %v\n", err)
		return
	}
	if err := mergePacks(ov, ps.Set()); err != nil {
		fmt.Fprintf(os.Stderr, "[packs] not applied: %v\n", err)
	}
}

// mergePacks compiles a pack Set into tighten-only overlay rules and merges them
// into the shared overlay store, preserving hand-authored rules: only prior
// "pack:"-prefixed rules are replaced, so re-applying is idempotent (no
// duplicate-id validation failure). It is the single merge path shared by
// boot-time applyPacks and the console's OnPacksChanged callback, so a live pack
// edit recompiles exactly as boot does. A nil store is a no-op.
func mergePacks(ov *overlay.Store, set packs.Set) error {
	if ov == nil {
		return nil
	}
	compiled := packs.CompileOverlay(set)
	var merged []overlay.Rule
	for _, r := range ov.Rules() {
		if !strings.HasPrefix(r.ID, "pack:") {
			merged = append(merged, r) // keep hand-authored rules
		}
	}
	merged = append(merged, compiled...)
	if err := ov.Replace(merged); err != nil {
		return err
	}
	fmt.Printf("applied %d pack rules to the local overlay\n", len(compiled))
	return nil
}

// reloadOverlay re-reads overlay.json on a ticker so out-of-band edits (a hand
// edit, or a future cloud pull) are picked up without a restart. Console edits
// already update the shared in-memory store; this only covers external writers.
func reloadOverlay(ctx context.Context, ov *overlay.Store) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := ov.Reload(); err != nil {
				fmt.Fprintf(os.Stderr, "[overlay] reload: %v\n", err)
			}
		}
	}
}

// consoleDeps are the optional, opt-in surfaces cmdRun wires into the console:
// the operator's pack store (Packs board + promote target), the approvals inbox
// (Manager, nil when the approver is off), the learn-mode behaviour profile, and
// the recompile-on-pack-change callback. Each is nil-safe: a nil field degrades
// the corresponding console panel gracefully.
type consoleDeps struct {
	packs          *packs.Store
	approvals      console.ApprovalsAPI
	behaviour      console.BehaviourAPI
	onPacksChanged func(packs.Set) error
}

// startConsole serves the loopback governance console (live feed + tighten-only
// overlay editor + Packs/Learning/Approvals) when enabled. It mints a fresh
// bearer token per run, writes it 0600 so `dashboard` can open the browser
// pre-authed, and wires the shared overlay store, a control-plane sync adapter,
// and the opt-in consoleDeps. Loopback bind + token gate means only the same
// local user can reach it. No-op when console is disabled.
func startConsole(ctx context.Context, cfg *config.Config, ov *overlay.Store, deps consoleDeps) {
	if !cfg.Console.Enabled {
		return
	}
	addr := cfg.Console.Addr
	if addr == "" {
		addr = config.DefaultConsoleAddr
	}
	token := randomSecret()
	if err := os.WriteFile(config.ConsoleTokenPath(), []byte(token), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "[console] disabled: cannot write token: %v\n", err)
		return
	}
	var cp console.CP
	if cfg.CPUrl != "" {
		cp = consoleCP{cpsync.New(cfg.CPUrl, cfg.Tenant, cfg.EntityID, cfg.EnrollmentToken)}
	}
	srv := console.New(console.Config{
		Addr:           addr,
		Token:          token,
		FeedPath:       cfg.Observability.AuditJSONLPath,
		Entity:         cfg.EntityID,
		Tenant:         cfg.Tenant,
		Overlay:        ov,
		CP:             cp,
		Packs:          deps.packs,
		Approvals:      deps.approvals,
		Behaviour:      deps.behaviour,
		OnPacksChanged: deps.onPacksChanged,
	})
	go func() {
		if err := srv.ListenAndServe(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[console] %v\n", err)
		}
	}()
	fmt.Printf("governance console on http://%s (run `%s dashboard` to open)\n", addr, guardCmd())
}

// consoleCP adapts a *cpsync.Client to the console.CP interface. The two Status
// types are structurally identical but nominally distinct across packages, so the
// console keeps its own dependency-free contract and main bridges the two.
type consoleCP struct{ c *cpsync.Client }

func (a consoleCP) Status(ctx context.Context) (console.SyncStatus, error) {
	s, err := a.c.Status(ctx)
	return console.SyncStatus{State: s.State, Pending: s.Pending}, err
}

func (a consoleCP) PushOverlay(ctx context.Context, rules []overlay.Rule) error {
	return a.c.PushOverlay(ctx, rules)
}

// behaviourAPI adapts a *sinks.Behaviour to the console.BehaviourAPI interface
// while guarding the typed-nil trap: a nil *Behaviour must stay a nil interface
// (not a non-nil interface wrapping a nil pointer, which would panic when the
// console calls Profile). Returns nil for a nil observer so the Learning panel
// degrades to an empty profile.
func behaviourAPI(b *sinks.Behaviour) console.BehaviourAPI {
	if b == nil {
		return nil
	}
	return b
}

// buildApprover constructs the human-in-the-loop approver from config, or nil
// when approve is disabled (the default), in which case an `ask` verdict behaves
// exactly as today. When enabled it builds a pending Store (mirrored under
// ~/.aarvion/pending for crash visibility) and, when Telegram creds are present,
// a Telegram notifier whose long-poll loop resolves button taps back into the
// store. A Reap ticker denies expired pendings (fail-safe). The returned Manager
// satisfies both govern.Approver (PDP) and the console approvals inbox.
func buildApprover(ctx context.Context, cfg *config.Config) *approve.Manager {
	if !cfg.Approve.Enabled {
		return nil
	}

	store := approve.NewStoreWithMirror(config.PendingDir())

	var tg *approve.Telegram
	tgCfg := cfg.Approve.Telegram
	if tgCfg.BotToken != "" && tgCfg.ChatID != "" {
		tg = approve.NewTelegram(tgCfg.BotToken, tgCfg.ChatID, "")
		// Long-poll for owner taps; each tap resolves the matching pending. Runs for
		// the process lifetime, backing off on transport errors.
		go tg.Poll(ctx, store.Resolve, store.Status)
		fmt.Println("approvals: Telegram notifications active")
	} else {
		fmt.Println("approvals: console inbox only (no Telegram creds configured)")
	}

	// A pending that no human answers must fail safe to deny; the reaper enforces
	// the TTL on a ticker. Poll faster than the TTL so expiry is timely.
	ttl := time.Duration(cfg.Approve.TimeoutSeconds) * time.Second
	go reapApprovals(ctx, store)

	return approve.NewManager(store, tg, ttl)
}

// reapApprovals runs the approver's TTL reaper on a ticker until ctx is
// cancelled: any pending past its Created+TTL is resolved to deny (fail-safe).
func reapApprovals(ctx context.Context, store *approve.Store) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			store.Reap(now)
		}
	}
}

// cmdDashboard opens the local governance console in the default browser using
// the per-run bearer token the running guard wrote. It starts nothing; the guard
// (`run`/`service`) serves the console.
func cmdDashboard(_ []string) {
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}
	if !cfg.Console.Enabled {
		fmt.Fprintln(os.Stderr, "the governance console is disabled (set console.enabled in guard.json, then restart the guard)")
		os.Exit(1)
	}
	tok, err := os.ReadFile(config.ConsoleTokenPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "console not running — start the guard first (%s run, or %s service install)\n", guardCmd(), guardCmd())
		os.Exit(1)
	}
	addr := cfg.Console.Addr
	if addr == "" {
		addr = config.DefaultConsoleAddr
	}
	url := fmt.Sprintf("http://%s/?t=%s", addr, strings.TrimSpace(string(tok)))
	fmt.Printf("opening the governance console: %s\n", url)
	if err := openURL(url); err != nil {
		fmt.Printf("could not open a browser automatically — paste this in yours:\n  %s\n", url)
	}
}

// openURL opens a URL in the platform's default browser (best-effort, detached).
func openURL(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func cmdRun() {
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Tighten-only local overlay, shared by every decision path (proxy, transparent,
	// PDP) and the console editor, so a rule authored in the UI takes effect
	// in-process immediately. loadOverlay tolerates a missing file (empty store); a
	// background reloader also picks up out-of-band edits to overlay.json.
	ov := loadOverlay()
	// The operator's policy-pack store, shared by the boot-time compile and the
	// console's Packs board + learn-mode promote, so a live edit and a boot compile
	// go through the SAME store and merge path. A load error (malformed JSON) leaves
	// packsStore nil; the console then falls back to the built-in catalog.
	packsStore, err := packs.Load(config.PacksPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[packs] disabled: %v\n", err)
		packsStore = nil
	}
	// Compile the operator's policy packs into the overlay BEFORE the govern server
	// starts, so pack guardrails enforce from boot. No-op when packs.json is absent.
	applyPacks(ov)
	if ov != nil {
		go reloadOverlay(ctx, ov)
	}

	// When the console is enabled but no audit sink is configured, default one so the
	// console's live feed has a decision log to tail. Additive: the JSONL sink is the
	// feed source, so this must be set before attachSinks builds the sinks.
	if cfg.Console.Enabled && cfg.Observability.AuditJSONLPath == "" {
		cfg.Observability.AuditJSONLPath = config.DecisionsLogPath()
	}

	if _, err := opa.EnsureBinary(ctx); err != nil {
		fatal(fmt.Errorf("policy engine: %w", err))
	}

	sup := opa.New(cfg.OPAAddr)
	go func() {
		if err := sup.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[opa] %v\n", err)
			stop()
		}
	}()

	fmt.Println("waiting for policy engine...")
	if err := sup.WaitHealthy(ctx, 30*time.Second); err != nil {
		fatal(err)
	}

	pol := policy.New(cfg.OPAAddr)
	rec := decisions.New(cfg.CPUrl, cfg.Tenant, cfg.EntityID, cfg.EnrollmentToken, cfg.DPID, config.ChainPath())
	hb := heartbeat.New(cfg.CPUrl, cfg.Tenant, cfg.EntityID, cfg.EnrollmentToken, cfg.DPID, cfg.Mode, rec)

	// Observability sinks run ALONGSIDE the CP push, fed from the same decision
	// stream, so they work in every inspect mode. Each is optional (started only
	// when its config field is set); closeSinks flushes them on shutdown.
	closeSinks := attachSinks(ctx, cfg, rec)
	defer closeSinks()

	// Always-on learn-mode behaviour observer: it records what each agent actually
	// does per {principal,surface,verb} so observe-mode packs and the propose step
	// have real usage to reason about. Low overhead (in-memory tally, disk write off
	// the hot path). Built before the console + PDP so both can share it.
	behaviour := sinks.NewBehaviour(config.BehaviourProfilePath(), 0)
	if behaviour != nil {
		go behaviour.Run(ctx)
		defer func() { _ = behaviour.Close() }()
	}

	// Optional human-in-the-loop approver behind an `ask` verdict: a pending store,
	// an optional Telegram notifier, and the Manager that bridges both the PDP
	// (govern.Approver) and the console inbox (Approvals). nil when approve is
	// disabled, which keeps today's behaviour (ask returns to the PEP, no pending).
	approver := buildApprover(ctx, cfg)

	// Loopback governance console: live decision feed + tighten-only overlay editor,
	// the Packs board, the Learning panel, and the Approvals inbox. Started once,
	// independent of proxy mode. Wiring the approver + behaviour + packs store lights
	// up those panels; a live pack edit recompiles via mergePacks (same as boot).
	deps := consoleDeps{
		packs:          packsStore,
		behaviour:      behaviourAPI(behaviour),
		onPacksChanged: func(set packs.Set) error { return mergePacks(ov, set) },
	}
	if approver != nil {
		deps.approvals = approver
	}
	startConsole(ctx, cfg, ov, deps)

	// Optional egress rate limiter: an in-memory, per-host ceiling checked before
	// OPA. nil when rate_limit is disabled, which preserves the prior behavior.
	limiter := buildLimiter(cfg)
	if limiter != nil {
		fmt.Printf("egress rate limit active (%d/min per host, %d host overrides)\n", cfg.RateLimit.PerMinute, len(cfg.RateLimit.PerHost))
	}

	// Optional default-deny egress allowlist: a novel host is denied (enforce) or
	// allowed-but-flagged (observe) before OPA. A zero-value allowlist (off/empty
	// mode) disables gating and preserves the prior behavior.
	allowlist := buildAllowlist(cfg)
	if allowlist.Mode != "" {
		fmt.Printf("egress allowlist active (mode=%s, %d hosts)\n", allowlist.Mode, len(cfg.Allowlist.Hosts))
	}

	// Optional emergency levers (kill-switch + break-glass) driven by touching two
	// files, polled on a ticker. nil when control is disabled, which preserves the
	// prior behavior. Its poller runs alongside the proxy for the process lifetime.
	ctrl := buildControl(cfg)
	if ctrl != nil {
		go ctrl.Run(ctx)
		freezePath := cfg.Control.FreezeFile
		if freezePath == "" {
			freezePath = config.FreezePath()
		}
		breakGlassPath := cfg.Control.BreakGlassFile
		if breakGlassPath == "" {
			breakGlassPath = config.BreakGlassPath()
		}
		fmt.Printf("emergency control active (freeze=%s, break_glass=%s)\n", freezePath, breakGlassPath)
	}

	go rec.RunPush(ctx, 10*time.Second)
	go hb.Run(ctx, 15*time.Second)

	// The runtime PDP is optional: only start it when a socket is configured.
	// It shares the policy client + recorder with the proxy, so both governance
	// paths write to the same OPA and decision chain.
	if cfg.Govern.Socket.Path != "" {
		gcfg := govern.Config{
			SocketPath: cfg.Govern.Socket.Path,
			Token:      cfg.Govern.Socket.Token,
			PeerUID:    cfg.Govern.Socket.PeerUID,
			FailMode:   cfg.Govern.FailMode,
			Essential:  mitm.Essentials(essentialHosts(cfg)),
			Overlay:    ov,
			EntityID:   cfg.EntityID,
		}
		// Only set the interface when we actually built an observer, so a nil
		// *Behaviour never becomes a non-nil typed-nil interface (which would
		// panic on the decision path). NewBehaviour doesn't return nil today; this
		// keeps it correct if that ever changes.
		if behaviour != nil {
			gcfg.Observer = behaviour
		}
		// Wire the approver so an `ask` verdict opens a pending (notified over
		// Telegram, resolvable in the console). nil-guarded to avoid a typed-nil
		// interface: a nil *approve.Manager must not become a non-nil Approver.
		if approver != nil {
			gcfg.Approver = approver
		}
		gsrv := govern.New(gcfg, pol, rec)
		go func() {
			if err := gsrv.ListenAndServe(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "[govern] %v\n", err)
			}
		}()
		fmt.Printf("govern PDP listening on %s (peer_uid=%d)\n", cfg.Govern.Socket.Path, cfg.Govern.Socket.PeerUID)
	}

	if cfg.Mode == config.ModeTransparent {
		runTransparent(ctx, cfg, pol, rec, limiter, allowlist, ctrl, ov)
	} else {
		var authority *ca.CA
		if cfg.Inspect {
			a, err := ca.EnsureCA(config.CADir())
			if err != nil {
				fatal(err)
			}
			authority = a
		}
		srv := proxy.New(cfg.ProxyAddr, authority, pol, rec, essentialHosts(cfg), cfg.PassthroughHosts, cfg.Inspect, limiter, allowlist, ctrl, ov)
		fmt.Printf("guard listening on http://%s (mode=forward, inspect=%t, entity=%s)\n", cfg.ProxyAddr, cfg.Inspect, cfg.EntityID)
		if err := srv.ListenAndServe(ctx); err != nil {
			fatal(err)
		}
	}
	fmt.Println("guard stopped")
}

func runTransparent(ctx context.Context, cfg *config.Config, pol *policy.Client, rec *decisions.Recorder, limiter *ratelimit.Limiter, allowlist mitm.Allowlist, ctrl *control.Controller, ov *overlay.Store) {
	gid, err := ensureGroup(cfg.GuardGroup)
	if err != nil {
		fatal(fmt.Errorf("group %q: %w (run with sudo)", cfg.GuardGroup, err))
	}
	authority, err := ca.EnsureCA(config.CADir())
	if err != nil {
		fatal(err)
	}
	if err := trust.Install(caCertPath()); err != nil {
		fmt.Printf("! could not trust the guard CA: %v\n", err)
	}

	backend := intercept.New()
	// Clear any rules orphaned by a prior hard crash before installing fresh
	// ones, so we never stack a stale redirect that black-holes egress.
	_ = backend.Remove()
	if err := backend.Install(intercept.Params{GID: gid, TransparentPort: portOf(cfg.TransparentAddr)}); err != nil {
		fatal(fmt.Errorf("install redirect: %w", err))
	}
	// Fail-safe: always tear the kernel redirect down so a stop can't leave
	// OpenClaw's egress black-holed.
	defer func() { _ = backend.Remove() }()

	srv := tproxy.New(cfg.TransparentAddr, authority, pol, rec, essentialHosts(cfg), intercept.OriginalDst, limiter, allowlist, ctrl, ov)
	fmt.Printf("guard intercepting on %s (mode=transparent, group=%s, entity=%s)\n", cfg.TransparentAddr, cfg.GuardGroup, cfg.EntityID)
	if err := srv.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[tproxy] %v\n", err)
	}
}

// attachSinks builds the configured observability sinks, wires them into the
// Recorder as a single fanout, and starts the metrics server (sharing ctx for
// shutdown). It returns a cleanup func that flushes/closes the buffered sinks -
// call it on shutdown so the JSONL audit copy and any queued deny webhooks
// drain. Each output is independent and optional; a config with none set leaves
// the Recorder's sink nil (the no-op fast path).
func attachSinks(ctx context.Context, cfg *config.Config, rec *decisions.Recorder) func() {
	var closers []func()
	cleanup := func() {
		for _, c := range closers {
			c()
		}
	}

	obs := cfg.Observability
	var members []decisions.Sink

	if obs.AuditJSONLPath != "" {
		js, err := sinks.NewJSONL(obs.AuditJSONLPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[sinks] audit jsonl disabled: %v\n", err)
		} else {
			members = append(members, js)
			closers = append(closers, func() { _ = js.Close() })
			fmt.Printf("audit sink writing decisions to %s\n", obs.AuditJSONLPath)
		}
	}

	if obs.DenyWebhookURL != "" {
		wh := sinks.NewWebhook(obs.DenyWebhookURL)
		members = append(members, wh)
		closers = append(closers, wh.Close)
		fmt.Printf("deny webhook posting to %s\n", obs.DenyWebhookURL)
	}

	// Learn-mode observer: joins the SAME fanout as the other sinks (so one
	// SetSink still drives JSONL + webhook + metrics + learn), tallies distinct
	// egress hosts, and writes a promotable proposed-allowlist file. Its ticker
	// shares ctx; closeSinks (below) closes it for the final write.
	if cfg.Learn.Enabled {
		path := cfg.Learn.ProposalPath
		if path == "" {
			path = config.ProposalPath()
		}
		ls := sinks.NewLearn(path, time.Duration(cfg.Learn.WriteEverySeconds)*time.Second)
		members = append(members, ls)
		closers = append(closers, func() { _ = ls.Close() })
		go ls.Run(ctx)
		fmt.Printf("learn observer proposing allowlist to %s\n", path)
	}

	if m := sinks.NewMulti(members...); m.Len() > 0 {
		rec.SetSink(m)
	}

	// Per-host request + estimated-spend meter feeding the /metrics endpoint.
	// Built only when a metrics addr is configured (nothing would read it
	// otherwise). It rides the Recorder's meter hook (pre-collapse), NOT the sink
	// fanout, so repeated identical allows are counted in full for rate/spend.
	var hostMeter *sinks.HostMeter
	if obs.MetricsAddr != "" {
		hostMeter = sinks.NewHostMeter(obs.SpendPerRequest, obs.MaxMeteredHosts)
		rec.SetMeter(hostMeter.Count)
	}

	if obs.MetricsAddr != "" {
		ms := sinks.NewMetrics(obs.MetricsAddr, rec, hostMeter)
		go func() {
			if err := ms.Serve(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "[metrics] %v\n", err)
			}
		}()
		fmt.Printf("metrics endpoint on http://%s/metrics (per-host spend/rate series)\n", obs.MetricsAddr)
	}

	return cleanup
}

func cmdExec(args []string) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: aarvion-guard exec -- <cmd...>")
		os.Exit(2)
	}
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}
	grp, err := user.LookupGroup(cfg.GuardGroup)
	if err != nil {
		fatal(fmt.Errorf("group %q not found; run `sudo aarvion-guard run` first: %w", cfg.GuardGroup, err))
	}
	gid, _ := strconv.Atoi(grp.Gid)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cred := &syscall.Credential{Gid: uint32(gid), Groups: []uint32{uint32(gid)}}
	if uid := os.Getenv("SUDO_UID"); uid != "" {
		if u, err := strconv.Atoi(uid); err == nil {
			cred.Uid = uint32(u)
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	if err := cmd.Run(); err != nil {
		fatal(err)
	}
}

func cmdService(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: aarvion-guard service install|uninstall")
		os.Exit(2)
	}
	switch args[0] {
	case "install":
		if err := svc.Install(); err != nil {
			fatal(err)
		}
		fmt.Println("guard installed as a boot service")
	case "uninstall":
		if err := svc.Uninstall(); err != nil {
			fatal(err)
		}
		fmt.Println("guard boot service removed")
	default:
		fmt.Fprintln(os.Stderr, "usage: aarvion-guard service install|uninstall")
		os.Exit(2)
	}
}

// cmdRepair unsticks OpenClaw's egress after a hard crash left a redirect or
// proxy env behind, without dropping the pairing.
func cmdRepair() {
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}
	if cfg.Mode == config.ModeTransparent {
		if err := intercept.New().Remove(); err != nil {
			fatal(fmt.Errorf("remove redirect (run with sudo): %w", err))
		}
		fmt.Println("cleared kernel redirect - egress restored")
		return
	}
	if envPath := wiring.ServiceEnvPath(cfg.OpenClawHome); envPath != "" {
		if err := wiring.Restore(envPath); err != nil {
			fatal(err)
		}
	}
	fmt.Println("restored OpenClaw egress - restart OpenClaw, then `aarvion-guard run`")
}

func cmdStatus() {
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}
	fmt.Printf("entity:  %s\n", cfg.EntityID)
	fmt.Printf("tenant:  %s\n", cfg.Tenant)
	fmt.Printf("mode:    %s\n", cfg.Mode)
	fmt.Printf("proxy:   http://%s\n", cfg.ProxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if policy.New(cfg.OPAAddr).Healthy(ctx) {
		fmt.Println("opa:     healthy")
	} else {
		fmt.Println("opa:     not running (start with `aarvion-guard run`)")
	}
}

func cmdUninstall() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "nothing to uninstall")
		return
	}
	_ = svc.Uninstall()
	if cfg.Inspect {
		if err := trust.Remove(caCertPath()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not remove guard CA trust: %v\n", err)
		}
	}
	if cfg.Mode == config.ModeTransparent {
		if err := intercept.New().Remove(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not remove redirect (run with sudo): %v\n", err)
		} else {
			fmt.Println("removed kernel redirect")
		}
	} else if envPath := wiring.ServiceEnvPath(cfg.OpenClawHome); envPath != "" {
		if err := wiring.Restore(envPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not restore OpenClaw env: %v\n", err)
		} else {
			fmt.Println("restored OpenClaw egress (restart OpenClaw to drop the proxy)")
		}
	}
	_ = os.RemoveAll(config.CADir())
	_ = os.Remove(config.OPAConfigPath())
	if err := os.Remove(config.Path()); err != nil {
		fatal(err)
	}
	fmt.Println("guard uninstalled (entity kept in dashboard; delete it there to fully remove)")
}

// cmdUpdate swaps in a newer binary without re-pairing. The launcher has already
// downloaded and is running the new version, so we just re-point the background
// service at this binary and restart it; the pairing, CA and config on disk are
// left untouched.
func cmdUpdate() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not initialized; run `init <pairing-code>` first")
		os.Exit(1)
	}
	if err := svc.Install(); err != nil {
		fmt.Printf("! could not restart the background service: %v\n", err)
		fmt.Printf("  the new binary is in place; run `%s run` to start it in the foreground.\n", guardCmd())
		os.Exit(1)
	}
	fmt.Printf("updated to %s and restarted in the background (entity %s)\n", version, cfg.EntityID)
	fmt.Println("no re-pairing needed. Restart OpenClaw if it was mid-session.")
}

// parseInterspersed lets flags appear before or after positional args, so
// `init <code> --api <url>` works the same as `init --api <url> <code>`
// (Go's flag package otherwise stops parsing at the first positional).
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return positional
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func ensureGroup(name string) (int, error) {
	if g, err := user.LookupGroup(name); err == nil {
		return strconv.Atoi(g.Gid)
	}
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("group %q not found and auto-create is Linux-only", name)
	}
	if err := exec.Command("groupadd", "-f", name).Run(); err != nil {
		return 0, err
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func shortID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
