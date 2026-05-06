package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xjoker/ssh-mcp/internal/auth"
)

// --------------------------------------------------------------------------
// S-15: stdout MUST NOT contain passwords
// --------------------------------------------------------------------------

// TestMigrateLegacyNoPasswordInStdout verifies that migrate-from-legacy never
// prints the raw password to stdout, even when it successfully processes the
// entry (S-15). The keychain call will fail in CI (no keychain backend), but
// the password must not appear in stdout regardless.
func TestMigrateLegacyNoPasswordInStdout(t *testing.T) {
	const markerPassword = "s3cr3t-MARKER-pw-do-not-print"

	// Write a temporary .env file with a plaintext password.
	envContent := strings.Join([]string{
		"SSH_HOST=test.example.com",
		"SSH_USER=admin",
		"SSH_PORT=22",
		"SSH_AUTH=password",
		"SSH_PASSWORD=" + markerPassword,
	}, "\n")

	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "test.env")
	if err := os.WriteFile(envFile, []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Point config to a temp path so we don't touch a real config.
	cfgPath := filepath.Join(tmpDir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	// Capture stdout.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	// Run — may return non-zero if keychain is unavailable; that is acceptable.
	migrateLegacyCmd([]string{envFile})

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if strings.Contains(out, markerPassword) {
		t.Fatalf("S-15 violation: stdout contains the plaintext password marker.\nstdout:\n%s", out)
	}
}

// TestMigratePasswordsNoPasswordInStdout verifies the migrate-passwords
// subcommand does not emit plaintext passwords to stdout (S-15).
func TestMigratePasswordsNoPasswordInStdout(t *testing.T) {
	const markerPassword = "s3cr3t-MIG-PW-MARKER"

	// Write a minimal config.toml with a plaintext password.
	cfgContent := `[settings]
allow_config_plaintext_password = true

[servers.myserver]
host = "10.0.0.1"
user = "ubuntu"
auth = "password"
password = "` + markerPassword + `"
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	// Capture stdout.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	// Run — may return non-zero if keychain is unavailable.
	migratePasswordsCmd(nil)

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if strings.Contains(out, markerPassword) {
		t.Fatalf("S-15 violation: stdout contains plaintext password marker.\nstdout:\n%s", out)
	}
}

// --------------------------------------------------------------------------
// parseLegacyEnv
// --------------------------------------------------------------------------

// TestParseLegacyEnvBasic checks that a simple .env file is parsed correctly.
func TestParseLegacyEnvBasic(t *testing.T) {
	content := "SSH_HOST=myhost.example.com\nSSH_USER=alice\nSSH_PORT=2222\nSSH_AUTH=agent\n"
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "basic.env")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	entries, err := parseLegacyEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.host != "myhost.example.com" {
		t.Errorf("host = %q, want myhost.example.com", e.host)
	}
	if e.user != "alice" {
		t.Errorf("user = %q, want alice", e.user)
	}
	if e.port != 2222 {
		t.Errorf("port = %d, want 2222", e.port)
	}
	if e.auth != "agent" {
		t.Errorf("auth = %q, want agent", e.auth)
	}
}

// TestParseLegacyEnvAutoDetectKeyAuth verifies that key_path present → auth=key.
func TestParseLegacyEnvAutoDetectKeyAuth(t *testing.T) {
	content := "SSH_HOST=keyhost\nSSH_USER=bob\nSSH_KEY_PATH=/home/bob/.ssh/id_rsa\n"
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "key.env")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	entries, err := parseLegacyEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least 1 entry")
	}
	if entries[0].auth != "key" {
		t.Errorf("auth = %q, want key", entries[0].auth)
	}
	if entries[0].keyPath != "/home/bob/.ssh/id_rsa" {
		t.Errorf("keyPath = %q", entries[0].keyPath)
	}
}

// TestParseLegacyEnvMissingHost verifies that entries without SSH_HOST are skipped.
func TestParseLegacyEnvMissingHost(t *testing.T) {
	content := "SSH_USER=nobody\n"
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nohost.env")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	entries, err := parseLegacyEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries for missing host, got %d", len(entries))
	}
}

// --------------------------------------------------------------------------
// migratePasswordsCmd — config rewrite path
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// M01: parseLegacyEnv name validation
// --------------------------------------------------------------------------

// TestMigrate_LegacyEnvSkipsInvalidName verifies that parseLegacyEnv skips
// entries whose SSH_NAME produces an invalid server name (e.g. contains '/'),
// and that the warning is emitted to stderr.
func TestMigrate_LegacyEnvSkipsInvalidName(t *testing.T) {
	envContent := strings.Join([]string{
		"SSH_HOST=test.example.com",
		"SSH_USER=admin",
		"SSH_PORT=22",
		"SSH_AUTH=agent",
		"SSH_NAME=evil/name", // '/' is not in ^[a-z0-9][a-z0-9_-]*$
	}, "\n")

	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "bad.env")
	if err := os.WriteFile(envFile, []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Point config to a temp path.
	cfgPath := filepath.Join(tmpDir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	_, errStr := captureOutput(func() {
		// parseLegacyEnv skips invalid entries; migrateLegacyCmd will report
		// "no server entries found" and exit non-zero, which is fine.
		migrateLegacyCmd([]string{envFile})
	})

	// The warning must mention the bad name.
	if !strings.Contains(errStr, "invalid server name") {
		t.Errorf("expected stderr to warn about invalid server name; got: %q", errStr)
	}
	if !strings.Contains(errStr, "evil") {
		t.Errorf("expected stderr to include the bad name fragment; got: %q", errStr)
	}
}

// TestMigratePasswordsStripsPlaintextPrefix verifies that an explicitly-prefixed
// "plaintext:hunter2" entry is migrated as the bare secret "hunter2", not the
// literal string "plaintext:hunter2". A previous bug stored the full prefixed
// string in the keychain, breaking authentication after migration.
func TestMigratePasswordsStripsPlaintextPrefix(t *testing.T) {
	cfgContent := `[settings]
allow_config_plaintext_password = true

[servers.myserver]
host = "10.0.0.1"
user = "ubuntu"
auth = "password"
password = "plaintext:hunter2"
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	// Probe the OS keychain. CI environments without a secret service
	// (e.g. headless Linux without dbus/libsecret) cannot exercise the
	// post-keychain rewrite path because SetKeychain fails before the
	// config is rewritten — skip rather than report a false positive.
	if err := auth.SetKeychain(keychainService(), "ssh-password:_probe", []byte("x")); err != nil {
		t.Skipf("keychain unavailable on this host: %v", err)
	}
	defer func() { _ = auth.DeleteKeychain(keychainService(), "ssh-password:_probe") }()
	defer func() { _ = auth.DeleteKeychain(keychainService(), "ssh-password:myserver") }()

	if code := migratePasswordsCmd(nil); code != 0 {
		t.Fatalf("migratePasswordsCmd exit = %d, want 0", code)
	}

	written, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	out := string(written)
	// The literal "plaintext:hunter2" must not appear anywhere — neither
	// inside the keychain (the entire point of the original fix) nor in
	// the rewritten config.
	if strings.Contains(out, "plaintext:hunter2") {
		t.Errorf("rewritten config still contains 'plaintext:hunter2': %s", out)
	}
	if !strings.Contains(out, "keychain:") {
		t.Errorf("expected 'keychain:' reference in rewritten config: %s", out)
	}
}

// TestMigratePasswordsCmdNoPlaintext verifies that when a config has no
// plaintext passwords, the command exits 0 and reports nothing to migrate.
func TestMigratePasswordsCmdNoPlaintext(t *testing.T) {
	cfgContent := `[settings]

[servers.myserver]
host = "10.0.0.1"
user = "ubuntu"
auth = "agent"
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	code := migratePasswordsCmd(nil)

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}

	if code != 0 {
		t.Fatalf("expected exit code 0 for no-plaintext config, got %d", code)
	}
	if !strings.Contains(buf.String(), "no plaintext passwords found") {
		t.Errorf("expected 'no plaintext passwords found', got: %q", buf.String())
	}
}
