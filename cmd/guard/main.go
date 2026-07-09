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
	"syscall"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/ca"
	"github.com/aarvion-ai/aarvion-guard/internal/config"
	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/govern"
	"github.com/aarvion-ai/aarvion-guard/internal/heartbeat"
	"github.com/aarvion-ai/aarvion-guard/internal/intercept"
	"github.com/aarvion-ai/aarvion-guard/internal/mitm"
	"github.com/aarvion-ai/aarvion-guard/internal/opa"
	"github.com/aarvion-ai/aarvion-guard/internal/pair"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
	"github.com/aarvion-ai/aarvion-guard/internal/proxy"
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

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "run":
		cmdRun()
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
  aarvion-guard init <pairing-code> [--api URL] [--device NAME] [--transparent]
  aarvion-guard run                       # start the guard (root for --transparent)
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

func cmdRun() {
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	go rec.RunPush(ctx, 10*time.Second)
	go hb.Run(ctx, 15*time.Second)

	// The runtime PDP is optional: only start it when a socket is configured.
	// It shares the policy client + recorder with the proxy, so both governance
	// paths write to the same OPA and decision chain.
	if cfg.Govern.Socket.Path != "" {
		gsrv := govern.New(govern.Config{
			SocketPath: cfg.Govern.Socket.Path,
			Token:      cfg.Govern.Socket.Token,
			PeerUID:    cfg.Govern.Socket.PeerUID,
			FailMode:   cfg.Govern.FailMode,
			Essential:  mitm.Essentials(essentialHosts(cfg)),
		}, pol, rec)
		go func() {
			if err := gsrv.ListenAndServe(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "[govern] %v\n", err)
			}
		}()
		fmt.Printf("govern PDP listening on %s (peer_uid=%d)\n", cfg.Govern.Socket.Path, cfg.Govern.Socket.PeerUID)
	}

	if cfg.Mode == config.ModeTransparent {
		runTransparent(ctx, cfg, pol, rec)
	} else {
		var authority *ca.CA
		if cfg.Inspect {
			a, err := ca.EnsureCA(config.CADir())
			if err != nil {
				fatal(err)
			}
			authority = a
		}
		srv := proxy.New(cfg.ProxyAddr, authority, pol, rec, essentialHosts(cfg), cfg.PassthroughHosts, cfg.Inspect)
		fmt.Printf("guard listening on http://%s (mode=forward, inspect=%t, entity=%s)\n", cfg.ProxyAddr, cfg.Inspect, cfg.EntityID)
		if err := srv.ListenAndServe(ctx); err != nil {
			fatal(err)
		}
	}
	fmt.Println("guard stopped")
}

func runTransparent(ctx context.Context, cfg *config.Config, pol *policy.Client, rec *decisions.Recorder) {
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

	srv := tproxy.New(cfg.TransparentAddr, authority, pol, rec, essentialHosts(cfg), intercept.OriginalDst)
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

	if m := sinks.NewMulti(members...); m.Len() > 0 {
		rec.SetSink(m)
	}

	if obs.MetricsAddr != "" {
		ms := sinks.NewMetrics(obs.MetricsAddr, rec)
		go func() {
			if err := ms.Serve(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "[metrics] %v\n", err)
			}
		}()
		fmt.Printf("metrics endpoint on http://%s/metrics\n", obs.MetricsAddr)
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
