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
