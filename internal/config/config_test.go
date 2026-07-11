package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xjoker/ssh-mcp/internal/config"
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
	ref, err := config.ParseCredRef("keychain:ssh-mcp:prod-db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Kind != config.CredRefKeychain {
		t.Errorf("expected CredRefKeychain, got %v", ref.Kind)
	}
	if ref.Service != "ssh-mcp" {
		t.Errorf("Service = %q, want %q", ref.Service, "ssh-mcp")
	}
	if ref.Account != "prod-db" {
		t.Errorf("Account = %q, want %q", ref.Account, "prod-db")
	}
	if ref.Raw != "keychain:ssh-mcp:prod-db" {
		t.Errorf("Raw = %q", ref.Raw)
	}
}

func TestParseCredRef_Keychain_MissingAccount(t *testing.T) {
	_, err := config.ParseCredRef("keychain:ssh-mcp")
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
key_passphrase = "keychain:ssh-mcp:myserver"
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
		if !strings.Contains(p, "ssh-mcp") {
			t.Errorf("DefaultPath on Windows missing expected component: %q", p)
		}
	} else {
		if !strings.Contains(p, "ssh-mcp/config.toml") {
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
key_passphrase = "keychain:ssh-mcp:myserver"
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
key_passphrase = "keychain:ssh-mcp:myserver"
`, "auth=password must not set key_passphrase")
}

func TestValidate_AuthPasswordWithKeychainOK(t *testing.T) {
	cfg := mustLoad(t, `
[servers.myserver]
host     = "example.com"
user     = "deploy"
auth     = "password"
password = "keychain:ssh-mcp:myserver"
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

// TestServerConfig_AcceptNewHostRejectedFromToml verifies that config drift is
// explicit: accept_new_host is runtime-only and must not be silently ignored.
func TestServerConfig_AcceptNewHostRejectedFromToml(t *testing.T) {
	mustFail(t, `
	[servers.myserver]
	host           = "example.com"
	user           = "deploy"
	auth           = "agent"
	accept_new_host = true
	`, "unknown key")
}

func TestLoad_RejectsUnknownSettingsKey(t *testing.T) {
	mustFail(t, `
	[settings]
	not_a_real_setting = true

	[servers.myserver]
	host = "example.com"
	user = "deploy"
	auth = "agent"
	`, "unknown key")
}

func TestLoad_RejectsNegativeAuditRetention(t *testing.T) {
	mustFail(t, `
	[settings]
	audit_retention_days = -1

	[servers.myserver]
	host = "example.com"
	user = "deploy"
	auth = "agent"
	`, "audit_retention_days")
}

func TestLoad_RejectsOversizedConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	tooLarge := strings.Repeat("#", 4*1024*1024+1)
	if err := os.WriteFile(path, []byte(tooLarge), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected oversized config to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

// ---- proxy chain: valid configs ------------------------------------------------

// TestLoad_Proxy_HTTP parses a valid [proxies.http-corp] entry.
func TestLoad_Proxy_HTTP(t *testing.T) {
	cfg := mustLoad(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"

[proxies.http-corp]
type = "http"
host = "proxy.corp.example.com"
port = 3128
user = "proxyuser"
password = "keychain:ssh-mcp:proxy-corp"
`)
	p, ok := cfg.Proxies["http-corp"]
	if !ok {
		t.Fatal("expected proxy 'http-corp'")
	}
	if p.Type != "http" {
		t.Errorf("Type = %q, want 'http'", p.Type)
	}
	if p.Host != "proxy.corp.example.com" {
		t.Errorf("Host = %q", p.Host)
	}
	if p.Port != 3128 {
		t.Errorf("Port = %d, want 3128", p.Port)
	}
	if p.Name != "http-corp" {
		t.Errorf("Name = %q, want 'http-corp'", p.Name)
	}
	if p.Password.Kind != config.CredRefKeychain {
		t.Errorf("Password.Kind = %v, want CredRefKeychain", p.Password.Kind)
	}
}

// TestLoad_Proxy_Socks5 parses a valid [proxies.socks-tor] entry.
func TestLoad_Proxy_Socks5(t *testing.T) {
	cfg := mustLoad(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"

[proxies.socks-tor]
type = "socks5"
host = "127.0.0.1"
port = 9050
`)
	p, ok := cfg.Proxies["socks-tor"]
	if !ok {
		t.Fatal("expected proxy 'socks-tor'")
	}
	if p.Type != "socks5" {
		t.Errorf("Type = %q, want 'socks5'", p.Type)
	}
	if p.Port != 9050 {
		t.Errorf("Port = %d, want 9050", p.Port)
	}
}

// TestLoad_Proxy_SSH_ViaServer parses a valid [proxies.ssh-bastion] that
// references a [servers.<name>] entry.
func TestLoad_Proxy_SSH_ViaServer(t *testing.T) {
	cfg := mustLoad(t, `
[servers.bastion]
host = "bastion.example.com"
user = "deploy"
auth = "agent"

[servers.target]
host = "target.internal"
user = "admin"
auth = "agent"
proxy_chain = ["ssh-bastion"]

[proxies.ssh-bastion]
type   = "ssh"
server = "bastion"
`)
	p, ok := cfg.Proxies["ssh-bastion"]
	if !ok {
		t.Fatal("expected proxy 'ssh-bastion'")
	}
	if p.Type != "ssh" {
		t.Errorf("Type = %q, want 'ssh'", p.Type)
	}
	if p.Server != "bastion" {
		t.Errorf("Server = %q, want 'bastion'", p.Server)
	}
	srv := cfg.Servers["target"]
	if len(srv.ProxyChain) != 1 || srv.ProxyChain[0] != "ssh-bastion" {
		t.Errorf("ProxyChain = %v, want [ssh-bastion]", srv.ProxyChain)
	}
}

// TestLoad_Proxy_SSH_Direct parses a valid [proxies.ssh-direct] with explicit
// host/port/user/auth credentials (not referencing a server entry).
func TestLoad_Proxy_SSH_Direct(t *testing.T) {
	cfg := mustLoad(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
proxy_chain = ["ssh-direct"]

[proxies.ssh-direct]
type     = "ssh"
host     = "jump.example.com"
port     = 22
user     = "jumpuser"
auth     = "agent"
`)
	p, ok := cfg.Proxies["ssh-direct"]
	if !ok {
		t.Fatal("expected proxy 'ssh-direct'")
	}
	if p.Host != "jump.example.com" {
		t.Errorf("Host = %q", p.Host)
	}
	if p.Auth != "agent" {
		t.Errorf("Auth = %q", p.Auth)
	}
}

// TestLoad_Server_ProxyChain_Parsed verifies proxy_chain parses into slice.
func TestLoad_Server_ProxyChain_Parsed(t *testing.T) {
	cfg := mustLoad(t, `
[proxies.a]
type = "http"
host = "proxy-a.example.com"
port = 3128

[proxies.b]
type = "socks5"
host = "proxy-b.example.com"
port = 1080

[servers.myserver]
host        = "example.com"
user        = "deploy"
auth        = "agent"
proxy_chain = ["a", "b"]
`)
	srv := cfg.Servers["myserver"]
	if len(srv.ProxyChain) != 2 {
		t.Fatalf("ProxyChain length = %d, want 2", len(srv.ProxyChain))
	}
	if srv.ProxyChain[0] != "a" || srv.ProxyChain[1] != "b" {
		t.Errorf("ProxyChain = %v, want [a b]", srv.ProxyChain)
	}
}

// ---- proxy chain: error cases --------------------------------------------------

// TestLoad_Proxy_UnknownType rejects an unknown proxy type.
func TestLoad_Proxy_UnknownType(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"

[proxies.bad]
type = "ftp"
host = "proxy.example.com"
port = 21
`, "type must be one of http/https/socks5/ssh")
}

// TestLoad_Proxy_HTTP_MissingHost rejects http proxy without host.
func TestLoad_Proxy_HTTP_MissingHost(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"

[proxies.bad]
type = "http"
port = 3128
`, "host is required")
}

// TestLoad_Proxy_Socks5_MissingPort rejects socks5 proxy without port.
func TestLoad_Proxy_Socks5_MissingPort(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"

[proxies.bad]
type = "socks5"
host = "127.0.0.1"
`, "port 0 out of range")
}

// TestLoad_Proxy_SSH_BothServerAndHost rejects ssh proxy with both server and host.
func TestLoad_Proxy_SSH_BothServerAndHost(t *testing.T) {
	mustFail(t, `
[servers.bastion]
host = "bastion.example.com"
user = "deploy"
auth = "agent"

[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"

[proxies.bad]
type   = "ssh"
server = "bastion"
host   = "other.example.com"
port   = 22
user   = "u"
auth   = "agent"
`, "cannot set both server and host")
}

// TestLoad_Proxy_SSH_ServerNotFound rejects ssh proxy where Server doesn't exist.
func TestLoad_Proxy_SSH_ServerNotFound(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"

[proxies.bad]
type   = "ssh"
server = "nonexistent-server"
`, "is not a defined server")
}

// TestLoad_Proxy_InsecureSkipVerify_WrongType rejects insecure_skip_verify on socks5.
func TestLoad_Proxy_InsecureSkipVerify_WrongType(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"

[proxies.bad]
type                 = "socks5"
host                 = "127.0.0.1"
port                 = 1080
insecure_skip_verify = true
`, "insecure_skip_verify is only valid for type=https")
}

// TestLoad_ProxyChain_UnknownProxy rejects proxy_chain referencing undefined proxy.
func TestLoad_ProxyChain_UnknownProxy(t *testing.T) {
	mustFail(t, `
[servers.myserver]
host        = "example.com"
user        = "deploy"
auth        = "agent"
proxy_chain = ["undefined-proxy"]
`, "unknown proxy")
}

// TestLoad_ProxyChain_AndProxyJump_Mutually_Exclusive rejects both fields set.
func TestLoad_ProxyChain_AndProxyJump_Mutually_Exclusive(t *testing.T) {
	mustFail(t, `
[servers.bastion]
host = "bastion.example.com"
user = "deploy"
auth = "agent"

[proxies.myproxy]
type = "http"
host = "proxy.example.com"
port = 3128

[servers.target]
host        = "target.example.com"
user        = "admin"
auth        = "agent"
proxy_jump  = "bastion"
proxy_chain = ["myproxy"]
`, "proxy_chain and proxy_jump are mutually exclusive")
}

// TestLoad_ProxyChain_CycleViaSSHServer rejects cycles where proxy.ssh.server
// creates an edge back to an ancestor server.
func TestLoad_ProxyChain_CycleViaSSHServer(t *testing.T) {
	// server-a's proxy_chain contains proxy-a which SSHs into server-b,
	// but server-b's proxy_chain contains proxy-b which SSHs into server-a.
	mustFail(t, `
[servers.server-a]
host        = "a.example.com"
user        = "deploy"
auth        = "agent"
proxy_chain = ["proxy-a"]

[servers.server-b]
host        = "b.example.com"
user        = "deploy"
auth        = "agent"
proxy_chain = ["proxy-b"]

[proxies.proxy-a]
type   = "ssh"
server = "server-b"

[proxies.proxy-b]
type   = "ssh"
server = "server-a"
`, "cycle")
}

// TestLoad_ProxyChain_TooLong rejects a chain longer than 8 entries.
func TestLoad_ProxyChain_TooLong(t *testing.T) {
	// Build 9 proxy entries and reference them from a server.
	proxyDefs := ""
	proxyNames := ""
	for i := 0; i < 9; i++ {
		proxyDefs += fmt.Sprintf(`
[proxies.p%d]
type = "http"
host = "proxy%d.example.com"
port = 3128
`, i, i)
		if i > 0 {
			proxyNames += ", "
		}
		proxyNames += fmt.Sprintf(`"p%d"`, i)
	}
	content := `
[servers.myserver]
host        = "example.com"
user        = "deploy"
auth        = "agent"
proxy_chain = [` + proxyNames + `]
` + proxyDefs
	mustFail(t, content, "exceeds maximum")
}

// TestLoad_ProxyChain_DuplicateName rejects duplicate proxy names in a chain.
func TestLoad_ProxyChain_DuplicateName(t *testing.T) {
	mustFail(t, `
[proxies.myproxy]
type = "http"
host = "proxy.example.com"
port = 3128

[servers.myserver]
host        = "example.com"
user        = "deploy"
auth        = "agent"
proxy_chain = ["myproxy", "myproxy"]
`, "duplicate proxy name")
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

func TestHasServerBlock(t *testing.T) {
	content := []byte(`# [servers.example]
[settings]
# nothing

  [servers.web1]   # primary
host = "h"
`)
	cases := []struct {
		name string
		want bool
	}{
		{"example", false}, // commented out
		{"web1", true},     // indented, trailing comment
		{"web", false},     // prefix of web1
		{"web12", false},   // superstring
	}
	for _, c := range cases {
		if got := config.HasServerBlock(content, c.name); got != c.want {
			t.Errorf("HasServerBlock(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestLoad_CaseFoldDuplicateServerRejected: [servers.WEB] + [servers.web]
// case-fold to the same key; loading must fail instead of silently keeping
// whichever the map iteration happened to visit last.
func TestLoad_CaseFoldDuplicateServerRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	content := `
[servers.web]
host = "h1"
user = "u"
auth = "agent"

[servers.WEB]
host = "h2"
user = "u"
auth = "agent"
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err == nil {
		t.Fatal("want duplicate-after-case-folding error, got nil")
	}
}

// ---- Load: settings.upload_local_allowed_paths (sftp_upload, SDD design
// docs/design/sftp-upload-tool.md §3.1) -------------------------------------

// TestLoad_UploadLocalAllowedPaths_DefaultEmpty: absent from TOML → empty
// slice, which is the fail-closed default that makes sftp_upload return
// UPLOAD_DISABLED until an operator opts in by hand-editing config.toml.
func TestLoad_UploadLocalAllowedPaths_DefaultEmpty(t *testing.T) {
	cfg := mustLoad(t, `
[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
`)
	if len(cfg.Settings.UploadLocalAllowedPaths) != 0 {
		t.Errorf("expected empty default, got %v", cfg.Settings.UploadLocalAllowedPaths)
	}
}

func TestLoad_UploadLocalAllowedPaths_Absolute_OK(t *testing.T) {
	cfg := mustLoad(t, `
[settings]
upload_local_allowed_paths = ["/Users/deploy/uploads", "/srv/staging"]

[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
`)
	if len(cfg.Settings.UploadLocalAllowedPaths) != 2 {
		t.Errorf("expected 2 upload_local_allowed_paths, got %d", len(cfg.Settings.UploadLocalAllowedPaths))
	}
}

func TestLoad_UploadLocalAllowedPaths_Relative_Error(t *testing.T) {
	mustFail(t, `
[settings]
upload_local_allowed_paths = ["relative/path"]

[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
`, "upload_local_allowed_paths")
}

func TestLoad_UploadLocalAllowedPaths_DotDot_Error(t *testing.T) {
	mustFail(t, `
[settings]
upload_local_allowed_paths = ["/srv/../etc"]

[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
`, "must not contain '..'")
}

func TestLoad_UploadLocalAllowedPaths_NotClean_Error(t *testing.T) {
	mustFail(t, `
[settings]
upload_local_allowed_paths = ["/srv/uploads/"]

[servers.myserver]
host = "example.com"
user = "deploy"
auth = "agent"
`, "is not clean")
}
