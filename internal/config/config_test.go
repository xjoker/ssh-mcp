package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
)

// ---- helpers ----------------------------------------------------------------

// writeToml writes content to a temp file and returns its path.
func writeToml(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("writeToml: %v", err)
	}
	return p
}

// mustLoad loads config and fails the test on error.
func mustLoad(t *testing.T, content string) *config.Config {
	t.Helper()
	cfg, err := config.Load(writeToml(t, content))
	if err != nil {
		t.Fatalf("mustLoad: unexpected error: %v", err)
	}
	return cfg
}

// mustFail loads config and expects an error whose message contains substr.
func mustFail(t *testing.T, content, substr string) {
	t.Helper()
	_, err := config.Load(writeToml(t, content))
	if err == nil {
		t.Fatalf("mustFail: expected error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("mustFail: expected error containing %q, got: %v", substr, err)
	}
}

// ---- ParseCredRef -----------------------------------------------------------

func TestParseCredRef_Empty(t *testing.T) {
	ref, err := config.ParseCredRef("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ref.IsZero() {
		t.Errorf("expected zero CredRef for empty string, got %+v", ref)
	}
	if ref.Raw != "" {
		t.Errorf("Raw should be empty for empty input, got %q", ref.Raw)
	}
}

func TestParseCredRef_Keychain(t *testing.T) {
	ref, err := config.ParseCredRef("keychain:mcp-ssh-bridge:prod-db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Kind != config.CredRefKeychain {
		t.Errorf("expected CredRefKeychain, got %v", ref.Kind)
	}
	if ref.Service != "mcp-ssh-bridge" {
		t.Errorf("Service = %q, want %q", ref.Service, "mcp-ssh-bridge")
	}
	if ref.Account != "prod-db" {
		t.Errorf("Account = %q, want %q", ref.Account, "prod-db")
	}
	if ref.Raw != "keychain:mcp-ssh-bridge:prod-db" {
		t.Errorf("Raw = %q", ref.Raw)
	}
}

func TestParseCredRef_Keychain_MissingAccount(t *testing.T) {
	_, err := config.ParseCredRef("keychain:mcp-ssh-bridge")
	if err == nil {
		t.Fatal("expected error for keychain with missing account, got nil")
	}
}

func TestParseCredRef_Env(t *testing.T) {
	ref, err := config.ParseCredRef("env:MY_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Kind != config.CredRefEnv {
		t.Errorf("expected CredRefEnv, got %v", ref.Kind)
	}
	if ref.EnvVar != "MY_SECRET" {
		t.Errorf("EnvVar = %q, want %q", ref.EnvVar, "MY_SECRET")
	}
	if ref.Raw != "env:MY_SECRET" {
		t.Errorf("Raw = %q", ref.Raw)
	}
}

func TestParseCredRef_Env_EmptyName(t *testing.T) {
	_, err := config.ParseCredRef("env:")
	if err == nil {
		t.Fatal("expected error for env: with empty name, got nil")
	}
}

func TestParseCredRef_Plaintext(t *testing.T) {
	ref, err := config.ParseCredRef("plaintext:s3cr3t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Kind != config.CredRefPlaintext {
		t.Errorf("expected CredRefPlaintext, got %v", ref.Kind)
	}
	if ref.Value != "s3cr3t" {
		t.Errorf("Value = %q, want %q", ref.Value, "s3cr3t")
	}
	if ref.Raw != "plaintext:s3cr3t" {
		t.Errorf("Raw = %q", ref.Raw)
	}
}

func TestParseCredRef_Bareword(t *testing.T) {
	ref, err := config.ParseCredRef("abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Kind != config.CredRefPlaintext {
		t.Errorf("expected CredRefPlaintext for bareword, got %v", ref.Kind)
	}
	if ref.Value != "abc123" {
		t.Errorf("Value = %q, want %q", ref.Value, "abc123")
	}
	if ref.Raw != "abc123" {
		t.Errorf("Raw = %q", ref.Raw)
	}
}

func TestParseCredRef_Bareword_WithColon_UnknownPrefix(t *testing.T) {
	// A string with a colon but no matching prefix is treated as a bareword
	// (i.e. plaintext), not an error.
	ref, err := config.ParseCredRef("foo:bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Kind != config.CredRefPlaintext {
		t.Errorf("expected CredRefPlaintext for unknown-prefix string, got %v", ref.Kind)
	}
	if ref.Value != "foo:bar" {
		t.Errorf("Value = %q, want %q", ref.Value, "foo:bar")
	}
}

// ---- Load: valid config -----------------------------------------------------

const minimalAgent = `
[settings]

[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
`

func TestLoad_Minimal_Agent(t *testing.T) {
	cfg := mustLoad(t, minimalAgent)
	if _, ok := cfg.Servers["myserver"]; !ok {
		t.Fatal("expected server 'myserver'")
	}
	srv := cfg.Servers["myserver"]
	if srv.Host != "example.com" {
		t.Errorf("Host = %q", srv.Host)
	}
	if srv.Auth != "agent" {
		t.Errorf("Auth = %q", srv.Auth)
	}
}

func TestLoad_Settings_Defaults(t *testing.T) {
	cfg := mustLoad(t, minimalAgent)
	s := cfg.Settings
	if s.DefaultTimeoutMs != 120_000 {
		t.Errorf("DefaultTimeoutMs = %d", s.DefaultTimeoutMs)
	}
	if s.MaxTimeoutMs != 1_800_000 {
		t.Errorf("MaxTimeoutMs = %d", s.MaxTimeoutMs)
	}
	if s.OutputMaxBytes != 65_536 {
		t.Errorf("OutputMaxBytes = %d", s.OutputMaxBytes)
	}
	if s.SftpProgressThresholdBytes != 10*1024*1024 {
		t.Errorf("SftpProgressThresholdBytes = %d", s.SftpProgressThresholdBytes)
	}
	if s.SessionIdleSeconds != 3600 {
		t.Errorf("SessionIdleSeconds = %d", s.SessionIdleSeconds)
	}
	if s.ConnIdleSeconds != 600 {
		t.Errorf("ConnIdleSeconds = %d", s.ConnIdleSeconds)
	}
	if s.AuditRetentionDays != 90 {
		t.Errorf("AuditRetentionDays = %d", s.AuditRetentionDays)
	}
	if !s.AllowInlineCredentials {
		t.Error("AllowInlineCredentials default should be true")
	}
	if !s.AllowQuickSetup {
		t.Error("AllowQuickSetup default should be true")
	}
	if s.AllowConfigPlaintextPassword {
		t.Error("AllowConfigPlaintextPassword default should be false")
	}
}

// ---- Load: missing required fields ------------------------------------------

func TestLoad_MissingHost(t *testing.T) {
	mustFail(t, `
[servers.myserver]
user = "deploy"
auth = "agent"
`, "host is required")
}

func TestLoad_MissingUser(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
auth = "agent"
`, "user is required")
}

func TestLoad_Auth_Key_MissingKeyPath(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "key"
`, "key_path")
}

// ---- Load: plaintext password -----------------------------------------------

func TestLoad_Plaintext_FlagFalse_Error(t *testing.T) {
	mustFail(t, `
[settings]
allow_config_plaintext_password = false

[servers.myserver]
host     = "example.com"
user     = "root"
auth     = "password"
password = "plaintext:s3cr3t"
`, "PLAINTEXT_PASSWORD_DISABLED")
}

func TestLoad_Plaintext_FlagTrue_OK(t *testing.T) {
	cfg := mustLoad(t, `
[settings]
allow_config_plaintext_password = true

[servers.myserver]
host     = "example.com"
user     = "root"
auth     = "password"
password = "plaintext:s3cr3t"
`)
	srv := cfg.Servers["myserver"]
	if srv.Password.Kind != config.CredRefPlaintext {
		t.Errorf("expected CredRefPlaintext, got %v", srv.Password.Kind)
	}
	if srv.Password.Value != "s3cr3t" {
		t.Errorf("Value = %q", srv.Password.Value)
	}
}

func TestLoad_BarewordPassword_FlagFalse_Error(t *testing.T) {
	// bareword is implicit plaintext, should also trigger PLAINTEXT_PASSWORD_DISABLED
	mustFail(t, `
[settings]
allow_config_plaintext_password = false

[servers.myserver]
host     = "example.com"
user     = "root"
auth     = "password"
password = "abc123"
`, "PLAINTEXT_PASSWORD_DISABLED")
}

// ---- Load: proxy_jump -------------------------------------------------------

func TestLoad_ProxyJump_UnknownServer(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host       = "example.com"
user       = "deploy"
auth       = "agent"
proxy_jump = "nonexistent"
`, "nonexistent")
}

func TestLoad_ProxyJump_Cycle(t *testing.T) {
	// Use all-lowercase names so lowercase-normalisation does not interfere.
	mustFail(t, `
[servers.server-a]
host       = "a.example.com"
user       = "deploy"
auth       = "agent"
proxy_jump = "server-b"

[servers.server-b]
host       = "b.example.com"
user       = "deploy"
auth       = "agent"
proxy_jump = "server-a"
`, "cycle")
}

// ---- Load: tags validation --------------------------------------------------

func TestLoad_Tag_InvalidUppercase(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
tags = ["Prod"]
`, "tag")
}

func TestLoad_Tag_InvalidSpace(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
tags = ["my tag"]
`, "tag")
}

// ---- Load: allowed_paths ----------------------------------------------------

func TestLoad_AllowedPaths_Relative_Error(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host          = "example.com"
user          = "deploy"
auth          = "agent"
allowed_paths = ["relative/path"]
`, "allowed_paths")
}

func TestLoad_AllowedPaths_Absolute_OK(t *testing.T) {
	cfg := mustLoad(t, `
[servers.myserver]
host          = "example.com"
user          = "deploy"
auth          = "agent"
allowed_paths = ["/var/www", "/tmp"]
`)
	srv := cfg.Servers["myserver"]
	if len(srv.AllowedPaths) != 2 {
		t.Errorf("expected 2 allowed_paths, got %d", len(srv.AllowedPaths))
	}
}

// ---- Load: server name lowercase --------------------------------------------

func TestLoad_ServerName_Lowercase(t *testing.T) {
	cfg := mustLoad(t, `
[servers.PROD-WEB]
host = "example.com"
user = "deploy"
auth = "agent"
`)
	if _, ok := cfg.Servers["prod-web"]; !ok {
		t.Errorf("expected key 'prod-web', got keys: %v", serverKeys(cfg))
	}
	if _, ok := cfg.Servers["PROD-WEB"]; ok {
		t.Error("expected original uppercase key to be gone after lowercasing")
	}
}

func serverKeys(cfg *config.Config) []string {
	keys := make([]string, 0, len(cfg.Servers))
	for k := range cfg.Servers {
		keys = append(keys, k)
	}
	return keys
}

// ---- Load: key auth with keychain passphrase --------------------------------

func TestLoad_KeyAuth_KeychainPassphrase(t *testing.T) {
	cfg := mustLoad(t, `
[servers.myserver]
host           = "example.com"
user           = "deploy"
auth           = "key"
key_path       = "~/.ssh/id_ed25519"
key_passphrase = "keychain:mcp-ssh-bridge:myserver"
`)
	srv := cfg.Servers["myserver"]
	if srv.KeyPassphrase.Kind != config.CredRefKeychain {
		t.Errorf("KeyPassphrase.Kind = %v, want CredRefKeychain", srv.KeyPassphrase.Kind)
	}
}

// ---- DefaultPath ------------------------------------------------------------

func TestDefaultPath_NonEmpty(t *testing.T) {
	p := config.DefaultPath()
	if p == "" {
		t.Fatal("DefaultPath() returned empty string")
	}
	if runtime.GOOS == "windows" {
		if !strings.Contains(p, "mcp-ssh-bridge") {
			t.Errorf("DefaultPath on Windows missing expected component: %q", p)
		}
	} else {
		if !strings.Contains(p, "mcp-ssh-bridge/config.toml") {
			t.Errorf("DefaultPath missing expected suffix: %q", p)
		}
	}
}

func TestLoad_KeyPathRelativeResolvedAgainstConfigDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[servers.web]
host = "h"
user = "u"
auth = "key"
key_path = "keys/id_ed25519"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "keys/id_ed25519")
	if got := cfg.Servers["web"].KeyPath; got != want {
		t.Errorf("key_path: got %q, want %q", got, want)
	}
}

func TestLoad_KeyPathAbsolutePreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	abs := filepath.Join(t.TempDir(), "abs/key")
	body := `
[servers.web]
host = "h"
user = "u"
auth = "key"
key_path = ` + fmt.Sprintf("%q", abs) + `
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Servers["web"].KeyPath; got != abs {
		t.Errorf("key_path: got %q, want %q (absolute should be preserved)", got, abs)
	}
}

// ---- Load: auth=agent field restrictions (SDD §7.3 rule 4) -----------------

func TestValidate_AuthAgentRejectsKeyPath(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host     = "example.com"
user     = "deploy"
auth     = "agent"
key_path = "~/.ssh/id_ed25519"
`, "auth=agent must not set key_path")
}

func TestValidate_AuthAgentRejectsKeyPassphrase(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host           = "example.com"
user           = "deploy"
auth           = "agent"
key_passphrase = "keychain:mcp-ssh-bridge:myserver"
`, "auth=agent must not set key_passphrase")
}

func TestValidate_AuthAgentRejectsPassword(t *testing.T) {
	mustFail(t, `
[settings]
allow_config_plaintext_password = true

[servers.myserver]
host     = "example.com"
user     = "deploy"
auth     = "agent"
password = "plaintext:secret"
`, "auth=agent must not set password")
}

func TestValidate_AuthAgentNoExtraCredsOK(t *testing.T) {
	mustLoad(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
`)
}

// ---- Load: auth=password field restrictions (SDD §7.3 rule 6) --------------

func TestValidate_AuthPasswordRequiresPassword(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "password"
`, "auth=password requires password")
}

func TestValidate_AuthPasswordRejectsKeyPath(t *testing.T) {
	mustFail(t, `
[settings]
allow_config_plaintext_password = true

[servers.myserver]
host     = "example.com"
user     = "deploy"
auth     = "password"
password = "plaintext:secret"
key_path = "~/.ssh/id_ed25519"
`, "auth=password must not set key_path")
}

func TestValidate_AuthPasswordRejectsKeyPassphrase(t *testing.T) {
	mustFail(t, `
[settings]
allow_config_plaintext_password = true

[servers.myserver]
host           = "example.com"
user           = "deploy"
auth           = "password"
password       = "plaintext:secret"
key_passphrase = "keychain:mcp-ssh-bridge:myserver"
`, "auth=password must not set key_passphrase")
}

func TestValidate_AuthPasswordWithKeychainOK(t *testing.T) {
	cfg := mustLoad(t, `
[servers.myserver]
host     = "example.com"
user     = "deploy"
auth     = "password"
password = "keychain:mcp-ssh-bridge:myserver"
`)
	srv := cfg.Servers["myserver"]
	if srv.Password.Kind != config.CredRefKeychain {
		t.Errorf("Password.Kind = %v, want CredRefKeychain", srv.Password.Kind)
	}
}

// ---- Load: auth=key field restrictions (SDD §7.3 rule 5 extension) ---------

func TestValidate_AuthKeyRejectsPassword(t *testing.T) {
	mustFail(t, `
[settings]
allow_config_plaintext_password = true

[servers.myserver]
host     = "example.com"
user     = "deploy"
auth     = "key"
key_path = "~/.ssh/id_ed25519"
password = "plaintext:secret"
`, "auth=key must not set password")
}

// ---- Load: allowed_paths clean validation (SDD §7.3 rule 11) ---------------

func TestValidate_AllowedPathsRejectsDoubleSlash(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host          = "example.com"
user          = "deploy"
auth          = "agent"
allowed_paths = ["/var//log"]
`, "is not clean")
}

func TestValidate_AllowedPathsRejectsDotDot(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host          = "example.com"
user          = "deploy"
auth          = "agent"
allowed_paths = ["/var/../etc"]
`, "must not contain '..'")
}

func TestValidate_AllowedPathsRejectsTrailingSlash(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host          = "example.com"
user          = "deploy"
auth          = "agent"
allowed_paths = ["/var/log/"]
`, "is not clean")
}

func TestValidate_AllowedPathsCleanOK(t *testing.T) {
	cfg := mustLoad(t, `
[servers.myserver]
host          = "example.com"
user          = "deploy"
auth          = "agent"
allowed_paths = ["/var/log", "/tmp", "/"]
`)
	srv := cfg.Servers["myserver"]
	if len(srv.AllowedPaths) != 3 {
		t.Errorf("expected 3 allowed_paths, got %d", len(srv.AllowedPaths))
	}
}

func TestLoad_KeyPathTildeExpanded(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[servers.web]
host = "h"
user = "u"
auth = "key"
key_path = "~/.ssh/id_ed25519"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".ssh/id_ed25519")
	if got := cfg.Servers["web"].KeyPath; got != want {
		t.Errorf("key_path: got %q, want %q", got, want)
	}
}
