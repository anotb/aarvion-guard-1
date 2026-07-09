package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Config is the guard's single source of truth, written once at `init` from
// the pairing result and read by `run`. Holds the enrollment secrets, so the
// file is always 0600.
type Config struct {
	Tenant          string `json:"tenant"`
	EntityID        string `json:"entity_id"`
	CPUrl           string `json:"cp_url"`
	EnrollmentToken string `json:"enrollment_token"`
	SigningSecret   string `json:"signing_secret"`
	BundleURL       string `json:"bundle_url"`

	DPID             string   `json:"dp_id"`
	Mode             string   `json:"mode"`
	ProxyAddr        string   `json:"proxy_addr"`
	TransparentAddr  string   `json:"transparent_addr"`
	GuardGroup       string   `json:"guard_group"`
	OPAAddr          string   `json:"opa_addr"`
	OpenClawHome     string   `json:"openclaw_home"`
	PassthroughHosts []string `json:"passthrough_hosts,omitempty"`
	EssentialHosts   []string `json:"essential_hosts,omitempty"`
	Inspect          bool     `json:"inspect"`

	Govern        Govern        `json:"govern,omitempty"`
	Observability Observability `json:"observability,omitempty"`
	RateLimit     RateLimit     `json:"rate_limit,omitempty"`
	Allowlist     Allowlist     `json:"allowlist,omitempty"`
	Learn         Learn         `json:"learn,omitempty"`
}

// Learn configures the learn-mode observer: it watches real egress and writes a
// *proposed allowlist* of every distinct destination host it saw, so an operator
// reviews-and-promotes into allowlist.hosts instead of hand-authoring. It's the
// onboarding unlock for default-deny. When Enabled is false (or the struct is
// absent) no observer is built and there is zero overhead.
//
//   - ProposalPath: where the 0600 JSON proposal is written (defaults to
//     ~/.aarvion/proposed-allowlist.json when empty).
//   - WriteEverySeconds: how often the proposal is rewritten (defaults to 30s
//     when unset/non-positive). A final write always happens on shutdown.
type Learn struct {
	Enabled           bool   `json:"enabled"`
	ProposalPath      string `json:"proposal_path,omitempty"`
	WriteEverySeconds int    `json:"write_every_seconds,omitempty"`
}

// Allowlist configures the default-deny egress gate: only approved (or
// essential) hosts may be reached; a novel host is denied in enforce mode, or
// allowed-but-flagged in observe mode so an operator can see what enforcement
// would block before switching it on. Mode is one of off|observe|enforce; an
// empty/off mode (or an absent struct) disables gating with zero behavior
// change. Hosts entries match like essential_hosts: a plain entry is an exact
// host, a "."-prefixed entry matches that domain and all its subdomains.
type Allowlist struct {
	Mode  string   `json:"mode,omitempty"`
	Hosts []string `json:"hosts,omitempty"`
}

// RateLimit configures the in-guard, per-destination-host egress rate ceiling
// evaluated in memory before OPA. It's a runaway guardrail: a looping agent
// hammering one host is denied once it crosses the ceiling, rather than running
// up a bill or earning a rate-ban. It keys on host, so it works host-level and
// thus in no-inspect mode too. When Enabled is false (or the struct is absent)
// no limiter is built and there is zero overhead.
//
//   - PerMinute: default per-host ceiling per 60s window.
//   - PerHost:   overrides PerMinute for named hosts (0 disables the limit for
//     that host).
type RateLimit struct {
	Enabled   bool           `json:"enabled"`
	PerMinute int            `json:"per_minute,omitempty"`
	PerHost   map[string]int `json:"per_host,omitempty"`
}

// Observability configures pluggable, config-driven outputs that run ALONGSIDE
// the CP push, fed from the same decision stream. Each output is optional and
// only starts when its field is set:
//   - AuditJSONLPath: on-box append-only JSONL forensic copy of every decision.
//   - MetricsAddr: addr for a tiny Prometheus /metrics HTTP endpoint.
//   - DenyWebhookURL: URL to POST a small JSON payload to on each deny.
type Observability struct {
	AuditJSONLPath string `json:"audit_jsonl_path,omitempty"`
	MetricsAddr    string `json:"metrics_addr,omitempty"`
	DenyWebhookURL string `json:"deny_webhook_url,omitempty"`
}

// Govern configures the local Policy Decision Point: a Unix-socket server the
// OpenClaw runtime calls (as a PEP) to approve each action before it runs. When
// Socket.Path is empty the PDP is simply not started.
type Govern struct {
	Socket                GovernSocket      `json:"socket"`
	FailMode              map[string]string `json:"fail_mode,omitempty"`
	AllowCacheTTLMs       int               `json:"allow_cache_ttl_ms,omitempty"`
	RateLimitPerCallerQPS int               `json:"rate_limit_per_caller_qps,omitempty"`
}

// GovernSocket is the PDP listener: a filesystem socket, a bearer token the PEP
// must present, and the uid the connecting peer must run as.
type GovernSocket struct {
	Path    string `json:"path"`
	Token   string `json:"token"`
	PeerUID uint32 `json:"peer_uid"`
}

const (
	ModeForward     = "forward"
	ModeTransparent = "transparent"

	DefaultGuardGroup      = "aarvionguard"
	DefaultTransparentAddr = ":8898"
)

func CADir() string { return filepath.Join(Dir(), "ca") }

func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".aarvion"
	}
	return filepath.Join(home, ".aarvion")
}

func Path() string { return filepath.Join(Dir(), "guard.json") }

func OPAConfigPath() string { return filepath.Join(Dir(), "opa-config.yaml") }

// ChainPath persists the decision hash-chain cursor so it survives restarts.
func ChainPath() string { return filepath.Join(Dir(), "chain.json") }

// ProposalPath is the default location for the learn observer's proposed
// allowlist, used when learn.proposal_path is unset.
func ProposalPath() string { return filepath.Join(Dir(), "proposed-allowlist.json") }

func Load() (*Config, error) {
	raw, err := os.ReadFile(Path())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.EntityID == "" || c.EnrollmentToken == "" {
		return nil, errors.New("config is incomplete; re-run `aarvion-guard init`")
	}
	return &c, nil
}

func (c *Config) Save() error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(Path(), raw, 0o600)
}

func Exists() bool {
	_, err := os.Stat(Path())
	return err == nil
}
