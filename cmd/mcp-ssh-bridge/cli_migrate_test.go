package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
