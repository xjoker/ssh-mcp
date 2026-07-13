// Package config loads, validates, and resolves TOML configuration.
// SDD §5.2 + §7.
//
// Types are defined here; implementations live in config.go.
package config

// Settings holds global configuration options. SDD §5.2.
type Settings struct {
	AllowConfigPlaintextPassword bool `toml:"allow_config_plaintext_password"`
	AllowInlineCredentials       bool `toml:"allow_inline_credentials"`
	DefaultTimeoutMs             int  `toml:"default_timeout_ms"`
	MaxTimeoutMs                 int  `toml:"max_timeout_ms"`
	OutputMaxBytes               int  `toml:"output_max_bytes"`
	SftpProgressThresholdBytes   int  `toml:"sftp_progress_threshold_bytes"`
	SessionIdleSeconds           int  `toml:"session_idle_seconds"`
	MaxSessions                  int  `toml:"max_sessions"`
	ConnIdleSeconds              int  `toml:"conn_idle_seconds"`
	AuditRetentionDays           int  `toml:"audit_retention_days"`
	// AuditRecordOutput controls whether stdout/stderr of executed commands
	// is written to audit log entries. Default true. Disable to keep audit
	// payloads minimal (metadata only).
	AuditRecordOutput bool `toml:"audit_record_output"`
	// AuditOutputMaxBytes caps the per-entry size (in bytes) of each of
	// stdout and stderr in the audit log. Larger outputs are truncated
	// with a trailing "\n…[truncated, N bytes total]" marker. Default
	// 32 KiB.
	AuditOutputMaxBytes int      `toml:"audit_output_max_bytes"`
	WeakAlgorithmsOptIn []string `toml:"weak_algorithms_opt_in"`
	// UploadLocalAllowedPaths gates the sftp_upload tool (SDD design
	// docs/design/sftp-upload-tool.md §3.1): absolute local filesystem path
	// prefixes an AI is allowed to read from disk and stream to a remote
	// server. Fail-closed default: empty, meaning sftp_upload is registered
	// but every call returns UPLOAD_DISABLED until an operator hand-edits
	// config.toml to opt in (this list cannot be populated via any MCP
	// tool). Same Rule 11 validation as ServerConfig.AllowedPaths (absolute,
	// no "..", clean).
	UploadLocalAllowedPaths []string `toml:"upload_local_allowed_paths"`
}

// CredRef is a parsed credential reference. See SDD §5.2 / §7.4.
//
// String forms:
//
//	keychain:<service>:<account>
//	env:VAR_NAME
//	plaintext:<value>
//	<bareword>            (= plaintext:<bareword>)
type CredRef struct {
	Kind    CredRefKind
	Service string // keychain only
	Account string // keychain only
	EnvVar  string // env only
	Value   string // plaintext only — MUST never be logged
	Raw     string // original string form, useful for error messages
}

// CredRefKind identifies the type of a CredRef.
type CredRefKind int

const (
	CredRefNone CredRefKind = iota
	CredRefKeychain
	CredRefEnv
	CredRefPlaintext
)

// IsZero reports whether the CredRef is the zero value (i.e. not set).
func (c CredRef) IsZero() bool { return c.Kind == CredRefNone }

// ServerConfig holds per-server configuration. SDD §5.2.
type ServerConfig struct {
	Name          string
	Host          string  `toml:"host"`
	Port          int     `toml:"port"`
	User          string  `toml:"user"`
	Auth          string  `toml:"auth"`
	KeyPath       string  `toml:"key_path"`
	KeyPassphrase CredRef `toml:"key_passphrase"`
	Password      CredRef `toml:"password"`
	DefaultDir    string  `toml:"default_dir"`
	Description   string  `toml:"description"`
	ProxyJump     string  `toml:"proxy_jump"`
	// ProxyChain lists named proxy entries (from [proxies.<name>] tables) that
	// form an ordered tunnel chain to reach this server. Mutually exclusive with
	// ProxyJump. SDD §12.4-bis (proxy chain).
	ProxyChain   []string `toml:"proxy_chain"`
	AllowedPaths []string `toml:"allowed_paths"`
	Tags         []string `toml:"tags"`

	// Mode is the per-server command policy mode: "" / "unrestricted"
	// (default, no filtering — identical to pre-policy behaviour),
	// "readonly" (built-in conservative observation allowlist + user
	// AllowPatterns, hard-denies shell metacharacters), or "restricted"
	// (command must match AllowPatterns and not DenyPatterns; empty
	// AllowPatterns denies everything). See docs/design/command-policy.md
	// and internal/safety.CompilePolicy, which is the engine that
	// interprets these fields — config only validates their shape.
	Mode string `toml:"mode"`
	// AllowPatterns / DenyPatterns are Go regexp (RE2) source strings
	// evaluated by internal/safety.CompilePolicy. Only meaningful when
	// Mode is "readonly" or "restricted"; validate() rejects them
	// otherwise (orphan patterns are a config error, not silently
	// ignored).
	AllowPatterns []string `toml:"allow_patterns"`
	DenyPatterns  []string `toml:"deny_patterns"`

	// AcceptNewHost is a runtime-only field (not deserialised from TOML) that
	// lets the SSH pool accept an unknown host key on first contact for this
	// specific server. It is populated by ssh_quick_setup / session_start
	// inline registrations to honour their accept_new_host argument.
	//
	// Static config entries always leave this false; trust grants for static
	// servers go through `ssh-mcp trust <name>` which writes the key
	// to known_hosts in advance. Setting accept_new_host in config.toml has
	// no effect because the toml:"-" tag prevents deserialisation.
	AcceptNewHost bool `toml:"-"`
}

// ProxyConfig represents a named entry from the [proxies.<name>] TOML table.
// ProxyConfigs are referenced from ServerConfig.ProxyChain by name.
// SDD §12.4-bis (proxy chain).
type ProxyConfig struct {
	Name     string  // populated from TOML key, lower-cased
	Type     string  `toml:"type"`     // "http" | "https" | "socks5" | "ssh"
	Host     string  `toml:"host"`     // http/https/socks5: required. ssh: required unless Server is set.
	Port     int     `toml:"port"`     // http/https/socks5/ssh direct: required
	User     string  `toml:"user"`     // optional auth username (http Basic, socks5, ssh ad-hoc)
	Password CredRef `toml:"password"` // optional auth secret; same CredRef rules as ServerConfig.Password
	// SSH proxy specifics:
	Server  string `toml:"server"`   // alternative to Host/Port/User/Auth: name of [servers.<name>] to use as SSH proxy
	Auth    string `toml:"auth"`     // "agent" | "key" | "password" — for ssh type with direct Host (not via Server)
	KeyPath string `toml:"key_path"` // for ssh type with auth=key
	// HTTPS-specific (type="https"):
	InsecureSkipVerify bool `toml:"insecure_skip_verify"` // disable cert verification (dev only)
}

// Config is the top-level configuration object. SDD §5.2.
type Config struct {
	Settings Settings
	Servers  map[string]ServerConfig
	Proxies  map[string]ProxyConfig // keyed by lower-cased proxy name
	Path     string                 // file path the config was loaded from
}

// MarshalText implements encoding.TextMarshaler so that BurntSushi/toml can
// encode CredRef values back to their original string representation.
// The Raw field preserves the original form (e.g. "keychain:svc:acct",
// "env:VAR", "plaintext:val", or a bareword).
func (c CredRef) MarshalText() ([]byte, error) {
	return []byte(c.Raw), nil
}
