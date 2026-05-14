// Package config loads, validates, and resolves TOML configuration.
// SDD §5.2 + §7.
package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

// expandKeyPath resolves a user-supplied key_path:
//   - "" → unchanged (validation is the caller's job)
//   - "~/foo" or "~\foo" → $HOME/foo
//   - relative path → joined with configDir (the directory holding config.toml)
//   - absolute path → unchanged
func expandKeyPath(p, configDir string) string {
	if p == "" {
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
		return p
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(configDir, p)
}

// tagRe validates tag strings: ^[a-z0-9_-]+$
var tagRe = regexp.MustCompile(`^[a-z0-9_-]+$`)

// serverNameRe validates server name keys: ^[a-z0-9][a-z0-9_-]*$, length 1-64
var serverNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

const maxConfigFileBytes = 4 * 1024 * 1024

// rawConfig mirrors the on-disk TOML structure before key normalisation.
type rawConfig struct {
	Settings Settings                `toml:"settings"`
	Servers  map[string]ServerConfig `toml:"servers"`
}

// applySettingsDefaults fills in zero-valued Settings fields with SDD defaults.
func applySettingsDefaults(s *Settings) {
	if s.DefaultTimeoutMs == 0 {
		s.DefaultTimeoutMs = 120_000
	}
	if s.MaxTimeoutMs == 0 {
		s.MaxTimeoutMs = 1_800_000
	}
	if s.OutputMaxBytes == 0 {
		s.OutputMaxBytes = 65_536
	}
	if s.SftpProgressThresholdBytes == 0 {
		s.SftpProgressThresholdBytes = 10 * 1024 * 1024
	}
	if s.SessionIdleSeconds == 0 {
		s.SessionIdleSeconds = 3_600
	}
	if s.MaxSessions == 0 {
		s.MaxSessions = 16
	}
	if s.ConnIdleSeconds == 0 {
		s.ConnIdleSeconds = 600
	}
	if s.AuditRetentionDays == 0 {
		s.AuditRetentionDays = 90
	}
	// Boolean defaults (zero = false in Go).
	// AllowInlineCredentials default = true
	// We cannot tell "not set" from "set to false" with plain struct decode,
	// so we rely on the rawDefaults approach below.
}

// boolDefault is used to apply bool defaults because Go's zero-value for bool
// is false, making it impossible to distinguish "unset" from "set to false"
// without a custom decoder. We store the raw TOML in rawConfig and let the
// caller pass the decoded Settings; we patch booleans using the presence
// detection trick via toml.Primitive is not available here, so instead we
// decode into a wrapper that has *bool pointers.
type rawSettings struct {
	AllowConfigPlaintextPassword *bool    `toml:"allow_config_plaintext_password"`
	AllowInlineCredentials       *bool    `toml:"allow_inline_credentials"`
	DefaultTimeoutMs             *int     `toml:"default_timeout_ms"`
	MaxTimeoutMs                 *int     `toml:"max_timeout_ms"`
	OutputMaxBytes               *int     `toml:"output_max_bytes"`
	SftpProgressThresholdBytes   *int     `toml:"sftp_progress_threshold_bytes"`
	SessionIdleSeconds           *int     `toml:"session_idle_seconds"`
	MaxSessions                  *int     `toml:"max_sessions"`
	ConnIdleSeconds              *int     `toml:"conn_idle_seconds"`
	AuditRetentionDays           *int     `toml:"audit_retention_days"`
	AuditRecordOutput            *bool    `toml:"audit_record_output"`
	AuditOutputMaxBytes          *int     `toml:"audit_output_max_bytes"`
	WeakAlgorithmsOptIn          []string `toml:"weak_algorithms_opt_in"`
}

type rawTopLevel struct {
	Settings rawSettings             `toml:"settings"`
	Servers  map[string]ServerConfig `toml:"servers"`
}

func boolVal(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func intVal(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

// Load reads, validates and returns Config. SDD §5.2.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	if len(data) > maxConfigFileBytes {
		return nil, fmt.Errorf("config: %q exceeds %d byte limit", path, maxConfigFileBytes)
	}

	var raw rawTopLevel
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("config: parse %q: unknown key %q", path, undecoded[0].String())
	}

	// Build Settings with proper defaults.
	rs := raw.Settings
	settings := Settings{
		AllowConfigPlaintextPassword: boolVal(rs.AllowConfigPlaintextPassword, false),
		AllowInlineCredentials:       boolVal(rs.AllowInlineCredentials, true),
		DefaultTimeoutMs:             intVal(rs.DefaultTimeoutMs, 120_000),
		MaxTimeoutMs:                 intVal(rs.MaxTimeoutMs, 1_800_000),
		OutputMaxBytes:               intVal(rs.OutputMaxBytes, 65_536),
		SftpProgressThresholdBytes:   intVal(rs.SftpProgressThresholdBytes, 10*1024*1024),
		SessionIdleSeconds:           intVal(rs.SessionIdleSeconds, 3_600),
		MaxSessions:                  intVal(rs.MaxSessions, 16),
		ConnIdleSeconds:              intVal(rs.ConnIdleSeconds, 600),
		AuditRetentionDays:           intVal(rs.AuditRetentionDays, 90),
		AuditRecordOutput:            boolVal(rs.AuditRecordOutput, true),
		AuditOutputMaxBytes:          intVal(rs.AuditOutputMaxBytes, 32*1024),
		WeakAlgorithmsOptIn:          rs.WeakAlgorithmsOptIn,
	}

	// configDir is the directory of the loaded config file; relative paths
	// in key_path are resolved against it so users don't have to repeat the
	// repo path in every entry.
	absPath, _ := filepath.Abs(path)
	configDir := filepath.Dir(absPath)

	// Normalise server map keys to lowercase. ProxyJump references are
	// also lowercased for symmetry, so that `proxy_jump = "Bastion"` matches
	// `[servers.bastion]` regardless of case in the TOML source.
	servers := make(map[string]ServerConfig, len(raw.Servers))
	for k, v := range raw.Servers {
		lk := strings.ToLower(k)
		v.Name = lk
		v.ProxyJump = strings.ToLower(v.ProxyJump)
		v.KeyPath = expandKeyPath(v.KeyPath, configDir)
		servers[lk] = v
	}

	cfg := &Config{
		Settings: settings,
		Servers:  servers,
		Path:     path,
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate applies all SDD §7.3 validation rules and collects errors.
func validate(cfg *Config) error {
	var errs []string

	if cfg.Settings.DefaultTimeoutMs <= 0 {
		errs = append(errs, "settings.default_timeout_ms must be positive")
	}
	if cfg.Settings.MaxTimeoutMs <= 0 {
		errs = append(errs, "settings.max_timeout_ms must be positive")
	}
	if cfg.Settings.OutputMaxBytes <= 0 {
		errs = append(errs, "settings.output_max_bytes must be positive")
	}
	if cfg.Settings.SftpProgressThresholdBytes <= 0 {
		errs = append(errs, "settings.sftp_progress_threshold_bytes must be positive")
	}
	if cfg.Settings.SessionIdleSeconds <= 0 {
		errs = append(errs, "settings.session_idle_seconds must be positive")
	}
	if cfg.Settings.MaxSessions <= 0 {
		errs = append(errs, "settings.max_sessions must be positive")
	}
	if cfg.Settings.ConnIdleSeconds <= 0 {
		errs = append(errs, "settings.conn_idle_seconds must be positive")
	}
	if cfg.Settings.AuditRetentionDays <= 0 {
		errs = append(errs, "settings.audit_retention_days must be positive")
	}

	for name, srv := range cfg.Servers {
		// Rule 13: server name matches ^[a-z0-9][a-z0-9_-]*$, length 1-64.
		if len(name) == 0 || len(name) > 64 || !serverNameRe.MatchString(name) {
			errs = append(errs, fmt.Sprintf("server %q: name must match ^[a-z0-9][a-z0-9_-]*$ and be 1-64 chars", name))
		}

		// Rule 1: host non-empty.
		if srv.Host == "" {
			errs = append(errs, fmt.Sprintf("server %q: host is required", name))
		}

		// Rule 2: user non-empty.
		if srv.User == "" {
			errs = append(errs, fmt.Sprintf("server %q: user is required", name))
		}

		// Rule 14: port in [1, 65535] when non-zero (zero means unset → will default to 22 at connect time).
		if srv.Port != 0 && (srv.Port < 1 || srv.Port > 65535) {
			errs = append(errs, fmt.Sprintf("server %q: port %d out of range [1,65535]", name, srv.Port))
		}

		// Rule 3: auth must be agent/key/password.
		switch srv.Auth {
		case "agent", "key", "password":
			// ok
		default:
			errs = append(errs, fmt.Sprintf("server %q: auth must be one of agent/key/password, got %q", name, srv.Auth))
		}

		// Rule 5: auth=key requires key_path.
		if srv.Auth == "key" && srv.KeyPath == "" {
			errs = append(errs, fmt.Sprintf("server %q: auth=key requires key_path", name))
		}

		// Rule 4: auth=agent forbids key_path, key_passphrase, and password.
		if srv.Auth == "agent" {
			if srv.KeyPath != "" {
				errs = append(errs, fmt.Sprintf("server %q: auth=agent must not set key_path", name))
			}
			if !srv.KeyPassphrase.IsZero() {
				errs = append(errs, fmt.Sprintf("server %q: auth=agent must not set key_passphrase", name))
			}
			if !srv.Password.IsZero() {
				errs = append(errs, fmt.Sprintf("server %q: auth=agent must not set password", name))
			}
		}

		// Rule 6: auth=password requires password and forbids key_path / key_passphrase.
		if srv.Auth == "password" {
			if srv.Password.IsZero() {
				errs = append(errs, fmt.Sprintf("server %q: auth=password requires password", name))
			}
			if srv.KeyPath != "" {
				errs = append(errs, fmt.Sprintf("server %q: auth=password must not set key_path", name))
			}
			if !srv.KeyPassphrase.IsZero() {
				errs = append(errs, fmt.Sprintf("server %q: auth=password must not set key_passphrase", name))
			}
		}

		// Rule 5 (extension): auth=key forbids password.
		if srv.Auth == "key" && !srv.Password.IsZero() {
			errs = append(errs, fmt.Sprintf("server %q: auth=key must not set password", name))
		}

		// Rules 7+8: plaintext check for password and key_passphrase.
		if !srv.Password.IsZero() && isPlaintext(srv.Password) {
			if !cfg.Settings.AllowConfigPlaintextPassword {
				errs = append(errs, fmt.Sprintf("server %q: password is plaintext but PLAINTEXT_PASSWORD_DISABLED (set allow_config_plaintext_password=true to permit)", name))
			}
		}
		if !srv.KeyPassphrase.IsZero() && isPlaintext(srv.KeyPassphrase) {
			if !cfg.Settings.AllowConfigPlaintextPassword {
				errs = append(errs, fmt.Sprintf("server %q: key_passphrase is plaintext but PLAINTEXT_PASSWORD_DISABLED (set allow_config_plaintext_password=true to permit)", name))
			}
		}

		// Rule 12: tags match ^[a-z0-9_-]+$.
		for _, tag := range srv.Tags {
			if !tagRe.MatchString(tag) {
				errs = append(errs, fmt.Sprintf("server %q: tag %q must match ^[a-z0-9_-]+$", name, tag))
			}
		}

		// Rule 11: allowed_paths must be absolute, clean (no .., no double slash),
		// and must not contain trailing slash (except root "/").
		for _, p := range srv.AllowedPaths {
			if !strings.HasPrefix(p, "/") {
				errs = append(errs, fmt.Sprintf("server %q: allowed_paths entry %q must be an absolute path", name, p))
				continue
			}
			// Reject paths containing ".." components.
			if strings.Contains(p, "..") {
				errs = append(errs, fmt.Sprintf("server %q: allowed_paths entry %q must not contain '..'", name, p))
				continue
			}
			// Reject paths that are not clean (catches double slashes, trailing slash, etc.).
			if cleaned := path.Clean(p); cleaned != p {
				errs = append(errs, fmt.Sprintf("server %q: allowed_paths entry %q is not clean (expected %q)", name, p, cleaned))
			}
		}
	}

	// Rule 9: proxy_jump references must resolve.
	for name, srv := range cfg.Servers {
		if srv.ProxyJump == "" {
			continue
		}
		if _, ok := cfg.Servers[srv.ProxyJump]; !ok {
			errs = append(errs, fmt.Sprintf("server %q: proxy_jump %q is not a defined server", name, srv.ProxyJump))
		}
	}

	// Rule 10: no cycles in proxy_jump graph (DFS three-color).
	if cycleErr := detectProxyJumpCycles(cfg.Servers); cycleErr != "" {
		errs = append(errs, cycleErr)
	}

	if len(errs) > 0 {
		return fmt.Errorf("config: validation errors:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// isPlaintext reports whether a CredRef is plaintext (CredRefPlaintext).
func isPlaintext(r CredRef) bool {
	return r.Kind == CredRefPlaintext
}

// detectProxyJumpCycles uses DFS three-color to find cycles in proxy_jump graph.
// Returns an error string, or "" if no cycle found.
func detectProxyJumpCycles(servers map[string]ServerConfig) string {
	const (
		white = 0 // unvisited
		gray  = 1 // in-stack
		black = 2 // done
	)
	color := make(map[string]int, len(servers))

	var dfs func(name string) string
	dfs = func(name string) string {
		if color[name] == gray {
			return fmt.Sprintf("proxy_jump cycle detected involving server %q", name)
		}
		if color[name] == black {
			return ""
		}
		color[name] = gray
		srv, ok := servers[name]
		if ok && srv.ProxyJump != "" {
			if msg := dfs(srv.ProxyJump); msg != "" {
				return msg
			}
		}
		color[name] = black
		return ""
	}

	for name := range servers {
		if color[name] == white {
			if msg := dfs(name); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// DefaultPath returns the OS-appropriate config file path. SDD §7.1.
func DefaultPath() string {
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		return appdata + `\ssh-mcp\config.toml`
	default:
		// macOS and Linux: prefer XDG_CONFIG_HOME, fall back to ~/.config
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg == "" {
			home, _ := os.UserHomeDir()
			xdg = home + "/.config"
		}
		return xdg + "/ssh-mcp/config.toml"
	}
}

// PrintPlaintextWarning emits a stderr warning when any server has a plaintext
// credential and AllowConfigPlaintextPassword is true. SDD §7.2.
func (c *Config) PrintPlaintextWarning() {
	if !c.Settings.AllowConfigPlaintextPassword {
		return
	}
	for _, srv := range c.Servers {
		if isPlaintext(srv.Password) || isPlaintext(srv.KeyPassphrase) {
			fmt.Fprintln(os.Stderr, "WARNING: one or more servers use a plaintext password in config — consider migrating to keychain: references")
			return
		}
	}
}

// ParseCredRef parses a credential reference string. SDD §7.4.
//
//   - "keychain:<service>:<account>" → CredRefKeychain
//   - "env:VAR_NAME"                 → CredRefEnv
//   - "plaintext:<value>"            → CredRefPlaintext
//   - "<bareword>"                   → CredRefPlaintext (Value=s)
//   - ""                             → zero CredRef + nil error
func ParseCredRef(s string) (CredRef, error) {
	if s == "" {
		return CredRef{}, nil
	}

	ref := CredRef{Raw: s}

	switch {
	case strings.HasPrefix(s, "keychain:"):
		rest := s[len("keychain:"):]
		// expect <service>:<account>
		idx := strings.Index(rest, ":")
		if idx < 0 {
			return CredRef{}, fmt.Errorf("config: invalid keychain CredRef %q: expected keychain:<service>:<account>", s)
		}
		ref.Kind = CredRefKeychain
		ref.Service = rest[:idx]
		ref.Account = rest[idx+1:]

	case strings.HasPrefix(s, "env:"):
		name := s[len("env:"):]
		if name == "" {
			return CredRef{}, fmt.Errorf("config: invalid env CredRef %q: env var name is empty", s)
		}
		ref.Kind = CredRefEnv
		ref.EnvVar = name

	case strings.HasPrefix(s, "plaintext:"):
		ref.Kind = CredRefPlaintext
		ref.Value = s[len("plaintext:"):]

	default:
		// bareword → implicit plaintext
		ref.Kind = CredRefPlaintext
		ref.Value = s
	}

	return ref, nil
}

// UnmarshalText lets TOML decode CredRef fields automatically.
func (c *CredRef) UnmarshalText(text []byte) error {
	ref, err := ParseCredRef(string(text))
	if err != nil {
		return err
	}
	*c = ref
	return nil
}
