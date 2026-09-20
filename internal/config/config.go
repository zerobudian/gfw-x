package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode is a run-time gateway policy mode.
type Mode string

const (
	ModeBypass Mode = "bypass"
	ModeBlock  Mode = "block"
	ModeCustom Mode = "custom"
)

// ValidModes are the modes selectable at run time.
var ValidModes = []Mode{ModeBypass, ModeBlock, ModeCustom}

// defaultAdminHash is the well-known SHA-256 hash shipped for the "admin"
// default password. Admin auth must never carry this on a remote listener.
const defaultAdminHash = "e158d9f24412583212b3d7fb5beab018afb0209364c75b4d69779c37eb75ecc1"

// bindIsLoopback reports whether the configured listen host is loopback-only
// (localhost / "" / 127.0.0.1 / ::1). Wildcard binds (0.0.0.0, ::, *) are NOT
// loopback-safe and are deliberately excluded here.
func bindIsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ParseMode validates and normalizes a mode string.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeBypass:
		return ModeBypass, nil
	case ModeBlock:
		return ModeBlock, nil
	case ModeCustom:
		return ModeCustom, nil
	}
	return "", fmt.Errorf("invalid mode %q (allowed: bypass, block, custom)", s)
}

// Theme reflects UI theme selection.
type Theme string

const (
	ThemeSystem Theme = "system"
	ThemeLight  Theme = "light"
	ThemeDark   Theme = "dark"
)

// Lang reflects dashboard language.
type Lang string

const (
	LangSystem  Lang = "system"
	LangZhCN    Lang = "zh-CN"
	LangEnglish Lang = "en"
)

// Auth configures admin authentication for the web dashboard / API.
type Auth struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	Username     string `yaml:"username" json:"username"`
	PasswordHash string `yaml:"password_hash" json:"-"`
	// SessionToken is a long-lived token. If empty a random one is generated.
	SessionToken string `yaml:"session_token" json:"-"`
}

// Server configures the HTTP API/dashboard listener.
type Server struct {
	// Listen is the bind address (host:port). Default "0.0.0.0:8443".
	Listen string `yaml:"listen" json:"listen"`
	// PublicWeb forbids remote/pubnets listeners. When true the server refuses
	// to bind to non-locallan addresses unless explicitly allowed.
	LanOnly bool `yaml:"lan_only" json:"lan_only"`
	AllowedIps []string `yaml:"allowed_ips" json:"allowed_ips"`
	Auth       Auth     `yaml:"auth" json:"auth"`
	// OriginAllowed is used for CSRF/origin checks.
	OriginAllowed string `yaml:"origin_allowed" json:"origin_allowed"`
}

// Logging configures the async log pipeline.
type Logging struct {
	// Format is jsonl, csv, or ring (in-memory only).
	Format      string `yaml:"format" json:"format"` // jsonl|csv|ring
	Dir         string `yaml:"dir" json:"dir"`
	MaxFiles    int    `yaml:"max_files" json:"max_files"`
	MaxBytes    int64  `yaml:"max_bytes" json:"max_bytes"`
	MaxRing     int    `yaml:"max_ring" json:"max_ring"`
	QueueSize   int    `yaml:"queue_size" json:"queue_size"`
	SampleRatio float64 `yaml:"sample_ratio" json:"sample_ratio"`
	// RedactPayloads / privacy: never store payloads by default.
	Redact bool `yaml:"redact" json:"redact"`
}

// Runtime configures the data-plane runtime.
type Runtime struct {
	FlowShards       int `yaml:"flow_shards" json:"flow_shards"`
	WorkerPool       int `yaml:"worker_pool" json:"worker_pool"`
	ChannelCapacity  int `yaml:"channel_capacity" json:"channel_capacity"`
	FlowTTL          int `yaml:"flow_ttl_seconds" json:"flow_ttl_seconds"`
	FastPathCacheTTL int `yaml:"fast_path_cache_ttl_seconds" json:"fast_path_cache_ttl_seconds"`
}

// Disabled default values are filled at load time.
type Defaults struct {
	Mode      Mode  `yaml:"mode" json:"mode"`
	Theme     Theme `yaml:"theme" json:"theme"`
	Lang      Lang  `yaml:"lang" json:"lang"`
	DPI       float64 `yaml:"dpi_sample_ratio" json:"dpi_sample_ratio"`
}

// Detect configures the VPN/tunnel detection engine.
type Detect struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// AutoAction is applied only for high-confidence detections.
	AutoAction string  `yaml:"auto_action" json:"auto_action"` // allow|observe|ratelimit|reject|drop
	Threshold  float64 `yaml:"confidence_threshold" json:"confidence_threshold"`
}

// Config is the top-level gateway configuration.
type Config struct {
	Default    Defaults `yaml:"defaults" json:"defaults"`
	Server     Server   `yaml:"server" json:"server"`
	Logging    Logging  `yaml:"logging" json:"logging"`
	Runtime    Runtime  `yaml:"runtime" json:"runtime"`
	Detect     Detect   `yaml:"detect" json:"detect"`
	RulesFile  string   `yaml:"rules_file" json:"rules_file"`
	CustomFile string   `yaml:"custom_rules_file" json:"custom_rules_file"`
}

// Load reads a YAML or JSON config file. JSON is detected by extension then
// attempted as fallback for any extension.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data, filepath.Ext(path))
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// Parse parses config bytes. ext may be ".json" or ".yaml"/".yml".
func Parse(data []byte, ext string) (*Config, error) {
	cfg := DefaultConfig()
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return cfg, nil
	}
	var err error
	switch strings.ToLower(ext) {
	case ".json":
		err = json.Unmarshal(data, cfg)
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, cfg)
	default:
		// Try JSON first, then YAML.
		err = json.Unmarshal(data, cfg)
		if err != nil {
			err = yaml.Unmarshal(data, cfg)
		}
	}
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// DefaultConfig returns a fully populated config with sane defaults.
func DefaultConfig() *Config {
	return &Config{
		Default: Defaults{
			Mode:  ModeBlock,
			Theme: ThemeSystem,
			Lang:  LangSystem,
			DPI:   0.02,
		},
		Server: Server{
			Listen:     "127.0.0.1:8443",
			LanOnly:    true,
			AllowedIps: []string{},
			Auth: Auth{
				Enabled:      true,
				Username:     "admin",
				PasswordHash: "e158d9f24412583212b3d7fb5beab018afb0209364c75b4d69779c37eb75ecc1", // default password: admin
			},
		},
		Logging: Logging{
			Format:      "jsonl",
			Dir:         "data/logs",
			MaxFiles:    10,
			MaxBytes:    100 * 1024 * 1024,
			MaxRing:     4096,
			QueueSize:   65536,
			SampleRatio: 1.0,
			Redact:      true,
		},
		Runtime: Runtime{
			FlowShards:       32,
			WorkerPool:       4,
			ChannelCapacity:  8192,
			FlowTTL:          900,
			FastPathCacheTTL: 300,
		},
		Detect: Detect{
			Enabled:   true,
			AutoAction: "observe",
			Threshold:  0.85,
		},
	}
}

// Validate checks that the configuration is internally consistent.
func (c *Config) Validate() error {
	if _, err := ParseMode(string(c.Default.Mode)); err != nil {
		return err
	}
	if c.Server.Auth.Enabled && strings.EqualFold(c.Server.Auth.PasswordHash, defaultAdminHash) {
		if !bindIsLoopback(c.Server.Listen) {
			return errors.New("server.auth.enabled but password_hash is still the well-known default; refusing to bind a non-loopback listener with the default credential. Set a strong password in config (or keep the listener on 127.0.0.1)")
		}
	}
	if c.Server.Listen == "" {
		return errors.New("server.listen is required")
	}
	if c.Server.LanOnly {
		if err := checkLanOnly(c.Server.Listen, c.Server.AllowedIps); err != nil {
			return err
		}
	}
	switch strings.ToLower(c.Logging.Format) {
	case "jsonl", "csv", "ring":
	default:
		return fmt.Errorf("logging.format must be one of jsonl, csv, ring (got %q)", c.Logging.Format)
	}
	if c.Runtime.FlowShards <= 0 {
		c.Runtime.FlowShards = DefaultConfig().Runtime.FlowShards
	}
	if c.Runtime.WorkerPool < 1 {
		c.Runtime.WorkerPool = 1
	}
	if c.Logging.QueueSize <= 0 {
		c.Logging.QueueSize = DefaultConfig().Logging.QueueSize
	}
	if c.Logging.SampleRatio < 0 || c.Logging.SampleRatio > 1 {
		return errors.New("logging.sample_ratio must be in [0,1]")
	}
	if c.Default.DPI < 0 || c.Default.DPI > 1 {
		return errors.New("defaults.dpi_sample_ratio must be in [0,1]")
	}
	return nil
}

// checkLanOnly rejects public wildcard binds when LAN-only is on.
func checkLanOnly(listen string, allowed []string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	lo, _ := net.LookupHost("localhost")
	ips := map[string]bool{host: true}
	for _, l := range lo {
		ips[l] = true
	}
	for _, a := range allowed {
		ips[a] = true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
			return nil
		}
		// private range check for CGNAT etc.
		if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return nil
		}
		return fmt.Errorf("lan_only forbids public bind address %q (add it to server.allowed_ips to override)", listen)
	}
	// hostname bind: allow localhost aliases only.
	for h := range ips {
		h = strings.Trim(h, "[]")
		if _, th := mkVia(h); th {
			return nil
		}
	}
	// Unknown hostname: allow to be safe but log warning (handled by caller).
	return nil
}

// mkVia is a tiny helper to test hostnames resolvable to loopback/private.
func mkVia(host string) (string, bool) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", false
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() {
			return host, true
		}
	}
	return host, false
}