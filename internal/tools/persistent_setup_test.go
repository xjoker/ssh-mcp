package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xjoker/ssh-mcp/internal/auth"
	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/ssh"
)

// makePersistentDeps prepares a writable temp dir with an empty config path
// and returns Deps + the resolved config path. The caller decides whether to
// pre-populate the file (default: nonexistent so the handler creates it).
func makePersistentDeps(t *testing.T, allowPlaintext bool) (*Deps, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	cfg := &config.Config{
		Path:    cfgPath,
		Servers: map[string]config.ServerConfig{},
		Settings: config.Settings{
			AllowConfigPlaintextPassword: allowPlaintext,
			DefaultTimeoutMs:             120_000,
			MaxTimeoutMs:                 1_800_000,
			OutputMaxBytes:               65_536,
			SftpProgressThresholdBytes:   10 * 1024 * 1024,
			SessionIdleSeconds:           3600,
			MaxSessions:                  16,
			ConnIdleSeconds:              600,
			AuditRetentionDays:           90,
		},
	}
	pool := ssh.NewPool(cfg, nil)
	deps := &Deps{
		Cfg:            cfg,
		Pool:           pool,
		AllowPlaintext: allowPlaintext,
	}
	return deps, cfgPath
}

func TestPersistentSetup_AgentAuth_Success(t *testing.T) {
	deps, cfgPath := makePersistentDeps(t, false)

	args := json.RawMessage(`{
		"name": "prod-web",
		"host": "1.2.3.4",
		"user": "admin",
		"auth": "agent",
		"description": "production web server"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}

	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), "[servers.prod-web]") {
		t.Fatalf("config missing [servers.prod-web] block; got:\n%s", body)
	}
	if !strings.Contains(string(body), `auth = "agent"`) {
		t.Errorf("auth=agent not written; got:\n%s", body)
	}

	// Validate by reload.
	if _, err := config.Load(cfgPath); err != nil {
		t.Errorf("written config does not validate: %v", err)
	}

	// Session-live: temp-server entry should exist on the pool.
	if _, ok := deps.Pool.LookupTempServer("prod-web"); !ok {
		t.Errorf("expected pool.LookupTempServer to find prod-web")
	}
}

// TestPersistentSetup_PasswordPlaintextExplicit_Disabled_Refuses verifies that
// explicit password_storage="plaintext" requires the plaintext gate.
func TestPersistentSetup_PasswordPlaintextExplicit_Disabled_Refuses(t *testing.T) {
	deps, cfgPath := makePersistentDeps(t, false)

	args := json.RawMessage(`{
		"name": "db1",
		"host": "10.0.0.1",
		"user": "root",
		"auth": "password",
		"password": "secret",
		"password_storage": "plaintext"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error when allow_config_plaintext_password=false and password_storage=plaintext")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Errorf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
	if !strings.Contains(resp.Error.Hint, "allow_config_plaintext_password") {
		t.Errorf("expected hint to mention allow_config_plaintext_password, got %q", resp.Error.Hint)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Errorf("config file should not exist after refusal, stat err=%v", err)
	}
}

// TestPersistentSetup_PasswordPlaintextExplicit_Enabled_Persists verifies that
// password_storage="plaintext" + gate=true writes the literal password to disk.
func TestPersistentSetup_PasswordPlaintextExplicit_Enabled_Persists(t *testing.T) {
	deps, cfgPath := makePersistentDeps(t, true)

	preexisting := `[settings]
allow_config_plaintext_password = true
`
	if err := os.WriteFile(cfgPath, []byte(preexisting), 0o600); err != nil {
		t.Fatal(err)
	}

	args := json.RawMessage(`{
		"name": "db1",
		"host": "10.0.0.1",
		"user": "root",
		"auth": "password",
		"password": "s3cret-pw!",
		"password_storage": "plaintext"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}

	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), `password = "s3cret-pw!"`) {
		t.Errorf("plaintext password not written; got:\n%s", body)
	}
	if _, err := config.Load(cfgPath); err != nil {
		t.Errorf("written config does not validate: %v", err)
	}
}

// TestPersistentSetup_PasswordKeychainDefault_Persists verifies that with the
// default (omitted) password_storage and no plaintext gate, the secret lands
// in the OS keychain and the TOML stores only a reference. Skipped when the
// keychain backend is unavailable (e.g. headless Linux CI).
func TestPersistentSetup_PasswordKeychainDefault_Persists(t *testing.T) {
	// Probe keychain availability — match the strategy used by cli_migrate_test.go.
	if err := auth.SetKeychain("ssh-mcp", "ssh-password:_probe-persistent", []byte("x")); err != nil {
		t.Skipf("keychain unavailable on this host: %v", err)
	}
	defer func() {
		_ = auth.DeleteKeychain("ssh-mcp", "ssh-password:_probe-persistent")
		_ = auth.DeleteKeychain("ssh-mcp", "ssh-password:db-kc")
	}()

	// Note: gate=false intentionally — keychain path must not require it.
	deps, cfgPath := makePersistentDeps(t, false)

	args := json.RawMessage(`{
		"name": "db-kc",
		"host": "10.0.0.2",
		"user": "root",
		"auth": "password",
		"password": "k3ych@in-pw"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}

	body, _ := os.ReadFile(cfgPath)
	wantRef := `password = "keychain:ssh-mcp:ssh-password:db-kc"`
	if !strings.Contains(string(body), wantRef) {
		t.Errorf("expected keychain reference in config; got:\n%s", body)
	}
	// Literal password must NOT appear on disk.
	if strings.Contains(string(body), "k3ych@in-pw") {
		t.Errorf("plaintext password leaked to disk; got:\n%s", body)
	}
	if _, err := config.Load(cfgPath); err != nil {
		t.Errorf("written config does not validate: %v", err)
	}

	// Keychain entry should be readable.
	ref := config.CredRef{Kind: config.CredRefKeychain, Service: "ssh-mcp", Account: "ssh-password:db-kc"}
	sec, err := auth.Resolve(context.Background(), ref, false)
	if err != nil {
		t.Fatalf("auth.Resolve on stored ref: %v", err)
	}
	defer sec.Close()
	if got := string(sec.Bytes()); got != "k3ych@in-pw" {
		t.Errorf("keychain content mismatch: got %q want %q", got, "k3ych@in-pw")
	}
}

// TestPersistentSetup_StorageWithoutSecret_Refuses verifies that supplying
// password_storage without a corresponding secret returns a validation error
// so the caller notices the contradiction.
func TestPersistentSetup_StorageWithoutSecret_Refuses(t *testing.T) {
	deps, _ := makePersistentDeps(t, false)

	args := json.RawMessage(`{
		"name": "n2",
		"host": "1.2.3.4",
		"user": "x",
		"auth": "agent",
		"password_storage": "keychain"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error: password_storage requires a password / key_passphrase")
	}
}

// TestPersistentSetup_InvalidStorageValue_Refuses verifies the enum.
func TestPersistentSetup_InvalidStorageValue_Refuses(t *testing.T) {
	deps, _ := makePersistentDeps(t, true)

	args := json.RawMessage(`{
		"name": "n3",
		"host": "1.2.3.4",
		"user": "x",
		"auth": "password",
		"password": "pw",
		"password_storage": "vault"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error for unknown password_storage value")
	}
}

func TestPersistentSetup_NameCollision_Refuses(t *testing.T) {
	deps, cfgPath := makePersistentDeps(t, false)

	// Pre-populate with an existing entry.
	existing := `[settings]
default_timeout_ms = 120000

[servers.prod-web]
host = "old.example.com"
port = 22
user = "old"
auth = "agent"
`
	if err := os.WriteFile(cfgPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	args := json.RawMessage(`{
		"name": "prod-web",
		"host": "new.example.com",
		"user": "new",
		"auth": "agent"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error on name collision")
	}
	if resp.Error.Code != envelope.CodeInvalidArgument {
		t.Errorf("expected INVALID_ARGUMENT, got %s", resp.Error.Code)
	}

	// File must be unchanged.
	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), `host = "old.example.com"`) {
		t.Errorf("file modified despite refusal:\n%s", body)
	}
}

func TestPersistentSetup_InvalidName_Refuses(t *testing.T) {
	deps, _ := makePersistentDeps(t, false)

	args := json.RawMessage(`{
		"name": "BAD-NAME",
		"host": "1.2.3.4",
		"user": "x",
		"auth": "agent"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error for invalid name")
	}
	if resp.Error.Code != envelope.CodeInvalidArgument {
		t.Errorf("expected INVALID_ARGUMENT, got %s", resp.Error.Code)
	}
}

func TestPersistentSetup_KeyAuth_RequiresKeyPath(t *testing.T) {
	deps, _ := makePersistentDeps(t, false)

	args := json.RawMessage(`{
		"name": "k1",
		"host": "1.2.3.4",
		"user": "x",
		"auth": "key"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error when auth=key without key_path")
	}
}

func TestPersistentSetup_KeyAuth_WithKeyPath_Persists(t *testing.T) {
	deps, cfgPath := makePersistentDeps(t, false)

	args := json.RawMessage(`{
		"name": "k1",
		"host": "1.2.3.4",
		"user": "x",
		"auth": "key",
		"key_path": "/home/user/.ssh/id_ed25519"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}

	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), `key_path = "/home/user/.ssh/id_ed25519"`) {
		t.Errorf("key_path not written; got:\n%s", body)
	}
}

func TestPersistentSetup_AgentForbidsCredentials(t *testing.T) {
	deps, _ := makePersistentDeps(t, true)

	args := json.RawMessage(`{
		"name": "n1",
		"host": "1.2.3.4",
		"user": "x",
		"auth": "agent",
		"password": "pw"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error: auth=agent must not set password")
	}
}

func TestPersistentSetup_BadProxyJump_RestoresOriginal(t *testing.T) {
	deps, cfgPath := makePersistentDeps(t, false)

	original := `[settings]
default_timeout_ms = 120000
`
	if err := os.WriteFile(cfgPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	// proxy_jump references nonexistent server → validate() fails.
	args := json.RawMessage(`{
		"name": "n1",
		"host": "1.2.3.4",
		"user": "x",
		"auth": "agent",
		"proxy_jump": "nonexistent"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error: dangling proxy_jump")
	}

	body, _ := os.ReadFile(cfgPath)
	if string(body) != original {
		t.Errorf("file should be unchanged on validation failure; got:\n%s", body)
	}
	// Also: no leftover .tmp file.
	tmp := cfgPath + ".persistent-setup.tmp"
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("temp file should be cleaned up, stat err=%v", err)
	}
}

func TestPersistentSetup_TagsAndDefaultDir(t *testing.T) {
	deps, cfgPath := makePersistentDeps(t, false)

	args := json.RawMessage(`{
		"name": "n1",
		"host": "1.2.3.4",
		"user": "x",
		"auth": "agent",
		"tags": ["prod", "web-tier"],
		"default_dir": "/srv/app"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}

	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), `tags = ["prod", "web-tier"]`) {
		t.Errorf("tags not written correctly; got:\n%s", body)
	}
	if !strings.Contains(string(body), `default_dir = "/srv/app"`) {
		t.Errorf("default_dir not written; got:\n%s", body)
	}
}

func TestPersistentSetup_BadTag_Refuses(t *testing.T) {
	deps, _ := makePersistentDeps(t, false)

	args := json.RawMessage(`{
		"name": "n1",
		"host": "1.2.3.4",
		"user": "x",
		"auth": "agent",
		"tags": ["BAD TAG"]
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error for invalid tag")
	}
}

func TestPersistentSetup_AppendsToExistingFile(t *testing.T) {
	deps, cfgPath := makePersistentDeps(t, false)

	original := `[settings]
default_timeout_ms = 120000

[servers.bastion]
host = "bastion.example.com"
port = 22
user = "jump"
auth = "agent"
`
	if err := os.WriteFile(cfgPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	args := json.RawMessage(`{
		"name": "target",
		"host": "10.0.0.5",
		"user": "deploy",
		"auth": "agent",
		"proxy_jump": "bastion"
	}`)
	resp := handleSSHPersistentSetup(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}

	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), "[servers.bastion]") {
		t.Errorf("original [servers.bastion] block lost:\n%s", body)
	}
	if !strings.Contains(string(body), "[servers.target]") {
		t.Errorf("new [servers.target] not appended:\n%s", body)
	}
	if !strings.Contains(string(body), `proxy_jump = "bastion"`) {
		t.Errorf("proxy_jump not written:\n%s", body)
	}
}
