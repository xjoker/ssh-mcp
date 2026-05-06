// Package config loads, validates, and resolves TOML configuration.
// SDD §5.2 + §7.
//
// Types are defined here; implementations live in config.go.
package config

// Settings holds global configuration options. SDD §5.2.
type Settings struct {
	AllowConfigPlaintextPassword bool     `toml:"allow_config_plaintext_password"`
	AllowInlineCredentials       bool     `toml:"allow_inline_credentials"`
	DefaultTimeoutMs             int      `toml:"default_timeout_ms"`
	MaxTimeoutMs                 int      `toml:"max_timeout_ms"`
	OutputMaxBytes               int      `toml:"output_max_bytes"`
	SftpProgressThresholdBytes   int      `toml:"sftp_progress_threshold_bytes"`
	SessionIdleSeconds           int      `toml:"session_idle_seconds"`
	MaxSessions                  int      `toml:"max_sessions"`
	ConnIdleSeconds              int      `toml:"conn_idle_seconds"`
	AuditRetentionDays           int      `toml:"audit_retention_days"`
	WeakAlgorithmsOptIn          []string `toml:"weak_algorithms_opt_in"`
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
	CredRefNone      CredRefKind = iota
	CredRefKeychain
	CredRefEnv
	CredRefPlaintext
)

// IsZero reports whether the CredRef is the zero value (i.e. not set).
func (c CredRef) IsZero() bool { return c.Kind == CredRefNone }

// ServerConfig holds per-server configuration. SDD §5.2.
type ServerConfig struct {
	Name          string
	Host          string   `toml:"host"`
	Port          int      `toml:"port"`
	User          string   `toml:"user"`
	Auth          string   `toml:"auth"`
	KeyPath       string   `toml:"key_path"`
	KeyPassphrase CredRef  `toml:"key_passphrase"`
	Password      CredRef  `toml:"password"`
	DefaultDir    string   `toml:"default_dir"`
	Description   string   `toml:"description"`
	ProxyJump     string   `toml:"proxy_jump"`
	AllowedPaths  []string `toml:"allowed_paths"`
	Tags          []string `toml:"tags"`

	// AcceptNewHost is a runtime-only field (not deserialised from TOML) that
	// lets the SSH pool accept an unknown host key on first contact for this
	// specific server. It is populated by ssh_quick_setup / session_start
	// inline registrations to honour their accept_new_host argument.
	//
	// Static config entries always leave this false; trust grants for static
	// servers go through `mcp-ssh-bridge trust <name>` which writes the key
	// to known_hosts in advance. Setting accept_new_host in config.toml has
	// no effect because the toml:"-" tag prevents deserialisation.
	AcceptNewHost bool `toml:"-"`
}

// Config is the top-level configuration object. SDD §5.2.
type Config struct {
	Settings Settings
	Servers  map[string]ServerConfig
	Path     string // file path the config was loaded from
}

// MarshalText implements encoding.TextMarshaler so that BurntSushi/toml can
// encode CredRef values back to their original string representation.
// The Raw field preserves the original form (e.g. "keychain:svc:acct",
// "env:VAR", "plaintext:val", or a bareword).
func (c CredRef) MarshalText() ([]byte, error) {
	return []byte(c.Raw), nil
}
