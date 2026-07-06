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
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/ca"
	"github.com/aarvion-ai/aarvion-guard/internal/config"
	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/heartbeat"
	"github.com/aarvion-ai/aarvion-guard/internal/intercept"
	"github.com/aarvion-ai/aarvion-guard/internal/opa"
	"github.com/aarvion-ai/aarvion-guard/internal/pair"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
	"github.com/aarvion-ai/aarvion-guard/internal/proxy"
	"github.com/aarvion-ai/aarvion-guard/internal/svc"
	"github.com/aarvion-ai/aarvion-guard/internal/tproxy"
	"github.com/aarvion-ai/aarvion-guard/internal/wiring"
)

// version is overridden at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const (
	defaultAPIURL    = "https://api.aarvion.ai"
	defaultProxyAddr = "127.0.0.1:8899"
	defaultOPAAddr   = "127.0.0.1:8181"
)

// essentialHosts stay reachable when OPA is down (fail-closed-with-essential),
// so a policy-engine hiccup degrades the assistant instead of killing it.
var essentialHosts = []string{"api.anthropic.com", "api.openai.com"}

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
  aarvion-guard service install|uninstall # run the guard on boot (root)
  aarvion-guard repair                    # unstick egress after a hard crash
  aarvion-guard status
  aarvion-guard uninstall
  aarvion-guard version`)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	apiURL := fs.String("api", defaultAPIURL, "Aarvion backend base URL")
	device := fs.String("device", "", "device name for this guard")
	transparent := fs.Bool("transparent", false, "bypass-proof kernel interception (Linux; needs root at run)")

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
		fmt.Println("  1. sudo aarvion-guard run                       # installs the redirect + policy engine")
		fmt.Printf("  2. aarvion-guard exec -- <start OpenClaw>        # runs it inside group %q\n", cfg.GuardGroup)
		return
	}

	envPath := wiring.ServiceEnvPath(cfg.OpenClawHome)
	if envPath == "" {
		fmt.Println("! OpenClaw install not found under ~/.openclaw — proxy env not wired.")
		fmt.Printf("  Set HTTPS_PROXY=http://%s manually, then run `aarvion-guard run`.\n", cfg.ProxyAddr)
	} else {
		if err := wiring.InjectProxy(envPath, "http://"+cfg.ProxyAddr); err != nil {
			fatal(err)
		}
		fmt.Printf("wired OpenClaw egress → guard (%s)\n", envPath)
	}
	fmt.Println("next:")
	fmt.Println("  1. aarvion-guard run          # start the guard + policy engine")
	fmt.Println("  2. restart OpenClaw           # so it picks up the proxy env")
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
	rec := decisions.New(cfg.CPUrl, cfg.Tenant, cfg.EntityID, cfg.EnrollmentToken, cfg.DPID)
	hb := heartbeat.New(cfg.CPUrl, cfg.Tenant, cfg.EntityID, cfg.EnrollmentToken, cfg.DPID, cfg.Mode, rec)

	go rec.RunPush(ctx, 10*time.Second)
	go hb.Run(ctx, 15*time.Second)

	if cfg.Mode == config.ModeTransparent {
		runTransparent(ctx, cfg, pol, rec)
	} else {
		srv := proxy.New(cfg.ProxyAddr, pol, rec, essentialHosts)
		fmt.Printf("guard listening on http://%s (mode=forward, entity=%s)\n", cfg.ProxyAddr, cfg.EntityID)
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

	srv := tproxy.New(cfg.TransparentAddr, authority, pol, rec, essentialHosts, intercept.OriginalDst)
	fmt.Printf("guard intercepting on %s (mode=transparent, group=%s, entity=%s)\n", cfg.TransparentAddr, cfg.GuardGroup, cfg.EntityID)
	if err := srv.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[tproxy] %v\n", err)
	}
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
	if cfg.Mode == config.ModeTransparent {
		if err := intercept.New().Remove(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not remove redirect (run with sudo): %v\n", err)
		} else {
			fmt.Println("removed kernel redirect")
		}
		_ = os.RemoveAll(config.CADir())
	} else if envPath := wiring.ServiceEnvPath(cfg.OpenClawHome); envPath != "" {
		if err := wiring.Restore(envPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not restore OpenClaw env: %v\n", err)
		} else {
			fmt.Println("restored OpenClaw egress (restart OpenClaw to drop the proxy)")
		}
	}
	_ = os.Remove(config.OPAConfigPath())
	if err := os.Remove(config.Path()); err != nil {
		fatal(err)
	}
	fmt.Println("guard uninstalled (entity kept in dashboard; delete it there to fully remove)")
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
