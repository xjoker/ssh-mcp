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

// (rawConfig + applySettingsDefaults were removed once the rawTopLevel +
// rawSettings approach below took over: defaults are now applied
// inline in Load via boolVal / intVal, which correctly distinguish
// "field absent from TOML" from "field present and set to zero/false".)
//
// boolDefault rationale: Go's zero-value for bool is false, making it
// impossible to distinguish "unset" from "set to false" without a
// custom decoder. We decode the file into a wrapper that has *bool
// pointers (rawSettings); a nil pointer means absent.
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
	Proxies  map[string]ProxyConfig  `toml:"proxies"`
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
		// Case-folding two distinct TOML tables onto one key would silently
		// drop one of them (map iteration order decides which) — fail loudly.
		if _, dup := servers[lk]; dup {
			return nil, fmt.Errorf("config: servers %q: duplicate name after case-folding (server names are case-insensitive)", lk)
		}
		v.Name = lk
		v.ProxyJump = strings.ToLower(v.ProxyJump)
		v.KeyPath = expandKeyPath(v.KeyPath, configDir)
		servers[lk] = v
	}

	// Normalise proxy map keys to lowercase and set Name field.
	proxies := make(map[string]ProxyConfig, len(raw.Proxies))
	for k, v := range raw.Proxies {
		lk := strings.ToLower(k)
		if _, dup := proxies[lk]; dup {
			return nil, fmt.Errorf("config: proxies %q: duplicate name after case-folding (proxy names are case-insensitive)", lk)
		}
		v.Name = lk
		v.Server = strings.ToLower(v.Server)
		proxies[lk] = v
	}

	cfg := &Config{
		Settings: settings,
		Servers:  servers,
		Proxies:  proxies,
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

	// Proxy-chain rules.
	errs = append(errs, validateProxies(cfg)...)
	errs = append(errs, validateProxyChainRefs(cfg)...)

	// Proxy-chain cycle detection (extends proxy_jump graph).
	if cycleErr := detectProxyChainCycles(cfg); cycleErr != "" {
		errs = append(errs, cycleErr)
	}

	if len(errs) > 0 {
		return fmt.Errorf("config: validation errors:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

const maxProxyChainLength = 8

// validateProxies validates each ProxyConfig entry.
func validateProxies(cfg *Config) []string {
	var errs []string
	for name, p := range cfg.Proxies {
		// Name format: same rules as server names.
		if len(name) == 0 || len(name) > 64 || !serverNameRe.MatchString(name) {
			errs = append(errs, fmt.Sprintf("proxy %q: name must match ^[a-z0-9][a-z0-9_-]*$ and be 1-64 chars", name))
		}

		// Type must be one of the allowed values.
		switch p.Type {
		case "http", "https", "socks5", "ssh":
			// ok
		default:
			errs = append(errs, fmt.Sprintf("proxy %q: type must be one of http/https/socks5/ssh, got %q", name, p.Type))
			// Skip further checks; type-specific rules would be misleading.
			continue
		}

		// InsecureSkipVerify is only valid for type=https.
		if p.InsecureSkipVerify && p.Type != "https" {
			errs = append(errs, fmt.Sprintf("proxy %q: insecure_skip_verify is only valid for type=https", name))
		}

		switch p.Type {
		case "http", "https", "socks5":
			// Host required, Port required (1–65535).
			if p.Host == "" {
				errs = append(errs, fmt.Sprintf("proxy %q: host is required for type=%s", name, p.Type))
			}
			if p.Port < 1 || p.Port > 65535 {
				errs = append(errs, fmt.Sprintf("proxy %q: port %d out of range [1,65535]", name, p.Port))
			}
			// ssh-only fields must be absent.
			if p.Server != "" {
				errs = append(errs, fmt.Sprintf("proxy %q: server field is only valid for type=ssh", name))
			}
			if p.Auth != "" {
				errs = append(errs, fmt.Sprintf("proxy %q: auth field is only valid for type=ssh", name))
			}
			if p.KeyPath != "" {
				errs = append(errs, fmt.Sprintf("proxy %q: key_path field is only valid for type=ssh", name))
			}
			// Password without User is an error; User without Password is fine.
			if !p.Password.IsZero() && p.User == "" {
				errs = append(errs, fmt.Sprintf("proxy %q: password requires user to be set", name))
			}
			// Plaintext gate.
			if !p.Password.IsZero() && isPlaintext(p.Password) && !cfg.Settings.AllowConfigPlaintextPassword {
				errs = append(errs, fmt.Sprintf("proxy %q: password is plaintext but PLAINTEXT_PASSWORD_DISABLED (set allow_config_plaintext_password=true to permit)", name))
			}

		case "ssh":
			serverSet := p.Server != ""
			directSet := p.Host != "" || p.Port != 0 || p.User != "" || p.Auth != "" || p.KeyPath != "" || !p.Password.IsZero()

			if serverSet && directSet {
				errs = append(errs, fmt.Sprintf("proxy %q: cannot set both server and host/port/user/auth/key_path/password for type=ssh", name))
				break
			}
			if !serverSet && !directSet {
				errs = append(errs, fmt.Sprintf("proxy %q: type=ssh requires either server or host+port+user+auth", name))
				break
			}

			if serverSet {
				// Reference mode: server must exist in cfg.Servers.
				if _, ok := cfg.Servers[p.Server]; !ok {
					errs = append(errs, fmt.Sprintf("proxy %q: server %q is not a defined server", name, p.Server))
				}
			} else {
				// Direct mode: host, port, user, auth all required.
				if p.Host == "" {
					errs = append(errs, fmt.Sprintf("proxy %q: host is required for type=ssh direct mode", name))
				}
				if p.Port < 1 || p.Port > 65535 {
					errs = append(errs, fmt.Sprintf("proxy %q: port %d out of range [1,65535]", name, p.Port))
				}
				if p.User == "" {
					errs = append(errs, fmt.Sprintf("proxy %q: user is required for type=ssh direct mode", name))
				}
				switch p.Auth {
				case "agent", "key", "password":
					// ok
				default:
					errs = append(errs, fmt.Sprintf("proxy %q: auth must be one of agent/key/password for type=ssh, got %q", name, p.Auth))
				}
				if p.Auth == "key" && p.KeyPath == "" {
					errs = append(errs, fmt.Sprintf("proxy %q: auth=key requires key_path", name))
				}
				if p.Auth == "password" && p.Password.IsZero() {
					errs = append(errs, fmt.Sprintf("proxy %q: auth=password requires password", name))
				}
				// Plaintext gate.
				if !p.Password.IsZero() && isPlaintext(p.Password) && !cfg.Settings.AllowConfigPlaintextPassword {
					errs = append(errs, fmt.Sprintf("proxy %q: password is plaintext but PLAINTEXT_PASSWORD_DISABLED (set allow_config_plaintext_password=true to permit)", name))
				}
			}
		}
	}
	return errs
}

// validateProxyChainRefs validates ServerConfig.ProxyChain fields.
func validateProxyChainRefs(cfg *Config) []string {
	var errs []string
	for srvName, srv := range cfg.Servers {
		if len(srv.ProxyChain) == 0 {
			continue
		}
		// proxy_chain and proxy_jump are mutually exclusive.
		if srv.ProxyJump != "" {
			errs = append(errs, fmt.Sprintf("server %q: proxy_chain and proxy_jump are mutually exclusive", srvName))
		}
		// Length cap.
		if len(srv.ProxyChain) > maxProxyChainLength {
			errs = append(errs, fmt.Sprintf("server %q: proxy_chain length %d exceeds maximum of %d", srvName, len(srv.ProxyChain), maxProxyChainLength))
		}
		// Each name must exist in cfg.Proxies, and must not repeat.
		seen := make(map[string]bool, len(srv.ProxyChain))
		for _, proxyName := range srv.ProxyChain {
			if _, ok := cfg.Proxies[proxyName]; !ok {
				errs = append(errs, fmt.Sprintf("server %q: proxy_chain references unknown proxy %q", srvName, proxyName))
			}
			if seen[proxyName] {
				errs = append(errs, fmt.Sprintf("server %q: proxy_chain contains duplicate proxy name %q", srvName, proxyName))
			}
			seen[proxyName] = true
		}
	}
	return errs
}

// detectProxyChainCycles detects cycles that span proxy_jump edges and
// proxy_chain ssh-Server edges combined.
//
// It treats the graph as:
//
//	server A → server B  when A.ProxyJump == B.Name
//	server A → server B  when A.ProxyChain contains proxy P where P.Type=="ssh" && P.Server==B.Name
//
// Returns an error string, or "" if no cycle found.
func detectProxyChainCycles(cfg *Config) string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(cfg.Servers))

	// Build adjacency: server → []server it tunnels through.
	adj := make(map[string][]string, len(cfg.Servers))
	for name, srv := range cfg.Servers {
		var targets []string
		if srv.ProxyJump != "" {
			targets = append(targets, srv.ProxyJump)
		}
		for _, proxyName := range srv.ProxyChain {
			p, ok := cfg.Proxies[proxyName]
			if !ok {
				continue // already reported as unknown ref
			}
			if p.Type == "ssh" && p.Server != "" {
				targets = append(targets, p.Server)
			}
		}
		if len(targets) > 0 {
			adj[name] = targets
		}
	}

	var dfs func(name string) string
	dfs = func(name string) string {
		if color[name] == gray {
			return fmt.Sprintf("proxy cycle detected involving server %q", name)
		}
		if color[name] == black {
			return ""
		}
		color[name] = gray
		for _, target := range adj[name] {
			if msg := dfs(target); msg != "" {
				return msg
			}
		}
		color[name] = black
		return ""
	}

	for name := range cfg.Servers {
		if color[name] == white {
			if msg := dfs(name); msg != "" {
				return msg
			}
		}
	}
	return ""
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
