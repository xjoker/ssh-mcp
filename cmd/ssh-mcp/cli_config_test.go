package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xjoker/ssh-mcp/internal/config"
)

// captureOutput captures stdout and stderr while running fn.
func captureOutput(fn func()) (stdout, stderr string) {
	origOut := os.Stdout
	origErr := os.Stderr

	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	os.Stdout = outW
	os.Stderr = errW

	fn()

	outW.Close()
	errW.Close()
	os.Stdout = origOut
	os.Stderr = origErr

	var outBuf, errBuf bytes.Buffer
	io.Copy(&outBuf, outR)
	io.Copy(&errBuf, errR)
	return outBuf.String(), errBuf.String()
}

// TestConfigInitCreatesFile verifies that `config init` writes a default file
// when none exists, and that the file contains expected content.
func TestConfigInitCreatesFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	code := configCmd([]string{"init"})
	if code != 0 {
		t.Fatalf("configCmd(init): expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile after init: %v", err)
	}
	if !strings.Contains(string(data), "[settings]") {
		t.Errorf("config init: expected [settings] section in output, got:\n%s", data)
	}
}

// TestConfigInitFailsIfExists verifies that `config init` returns non-zero
// and does NOT overwrite an existing config file.
func TestConfigInitFailsIfExists(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	// Create the file first.
	original := "# existing config\n"
	if err := os.WriteFile(cfgPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	_, errOut := captureOutput(func() {
		code := configCmd([]string{"init"})
		if code == 0 {
			t.Error("expected non-zero exit when file already exists")
		}
	})

	if !strings.Contains(errOut, "already exists") {
		t.Errorf("expected 'already exists' in stderr, got: %q", errOut)
	}

	// File must not be overwritten.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Errorf("config init: file was overwritten, got:\n%s", data)
	}
}

// TestConfigValidateOK verifies that `config validate` prints "Config OK" for
// a valid TOML config.
func TestConfigValidateOK(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	// Write a minimal valid config.
	validCfg := `[settings]

[servers.myhost]
host = "example.com"
user = "admin"
auth = "agent"
`
	if err := os.WriteFile(cfgPath, []byte(validCfg), 0600); err != nil {
		t.Fatal(err)
	}

	outStr, _ := captureOutput(func() {
		code := configCmd([]string{"validate"})
		if code != 0 {
			t.Errorf("expected exit 0 for valid config, got non-zero")
		}
	})

	if !strings.Contains(outStr, "Config OK") {
		t.Errorf("expected 'Config OK' in stdout, got: %q", outStr)
	}
}

// TestConfigValidateInvalidTOML verifies that `config validate` exits non-zero
// for a file with invalid TOML syntax.
func TestConfigValidateInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	// Write deliberately broken TOML.
	if err := os.WriteFile(cfgPath, []byte("[[invalid toml\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, errOut := captureOutput(func() {
		code := configCmd([]string{"validate"})
		if code == 0 {
			t.Error("expected non-zero exit for invalid TOML")
		}
	})

	if errOut == "" {
		t.Error("expected error output for invalid TOML, got empty stderr")
	}
}

// TestConfigAddServer_AppendsValidEntry exercises the happy path for the
// add-server subcommand: a fresh config gets a new [servers.<name>] block,
// the file re-validates, and a follow-up validate succeeds.
func TestConfigAddServer_AppendsValidEntry(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	const original = `# keep this operator note

[servers.existing]
# keep this server note
host = "10.0.0.9"
user = "deploy"
auth = "agent"
`
	if err := os.WriteFile(cfgPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	out, _ := captureOutput(func() {
		code := configCmd([]string{
			"add-server",
			"--name", "web1",
			"--host", "10.0.0.1",
			"--user", "deploy",
			"--auth", "agent",
			"--tags", "prod,web",
			"--description", "primary",
		})
		if code != 0 {
			t.Errorf("add-server exit = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "Added server") {
		t.Errorf("expected 'Added server' in stdout, got: %q", out)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[servers.web1]", `host = "10.0.0.1"`, `auth = "agent"`, `tags = ["prod", "web"]`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing %q in rewritten config:\n%s", want, data)
		}
	}
	for _, want := range []string{"# keep this operator note", "# keep this server note"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing preserved comment %q in config:\n%s", want, data)
		}
	}
	if code := configCmd([]string{"validate"}); code != 0 {
		t.Fatalf("validate after add-server: exit %d", code)
	}
}

func TestConfigAddServer_WritesCommandPolicy(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	if code := configCmd([]string{
		"add-server",
		"--name", "readonly",
		"--host", "10.0.0.2",
		"--user", "deploy",
		"--mode", "restricted",
		"--allow", "^uptime$",
		"--allow", "^df -h$",
		"--deny", "reboot",
	}); code != 0 {
		t.Fatalf("config add-server with policy: %d", code)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	server := cfg.Servers["readonly"]
	if server.Mode != "restricted" {
		t.Errorf("mode = %q, want restricted", server.Mode)
	}
	if got := strings.Join(server.AllowPatterns, ","); got != "^uptime$,^df -h$" {
		t.Errorf("allow_patterns = %q", got)
	}
	if got := strings.Join(server.DenyPatterns, ","); got != "reboot" {
		t.Errorf("deny_patterns = %q", got)
	}
}

// TestConfigAddServer_RejectsDuplicate verifies that an existing entry with
// the same name causes a non-zero exit and the file is left unchanged.
func TestConfigAddServer_RejectsDuplicate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	if code := configCmd([]string{"init"}); code != 0 {
		t.Fatalf("config init: %d", code)
	}
	if code := configCmd([]string{
		"add-server", "--name", "dup",
		"--host", "h", "--user", "u", "--auth", "agent",
	}); code != 0 {
		t.Fatalf("first add-server: %d", code)
	}
	before, _ := os.ReadFile(cfgPath)

	_, errOut := captureOutput(func() {
		code := configCmd([]string{
			"add-server", "--name", "dup",
			"--host", "h2", "--user", "u2", "--auth", "agent",
		})
		if code == 0 {
			t.Error("expected duplicate add-server to fail")
		}
	})
	if !strings.Contains(errOut, "already exists") {
		t.Errorf("expected duplicate error, got: %q", errOut)
	}
	after, _ := os.ReadFile(cfgPath)
	if string(before) != string(after) {
		t.Errorf("file mutated despite duplicate-rejection")
	}
}

// TestConfigAddServer_RollsBackOnInvalidConfig verifies that if the synthesised
// entry would fail validation (e.g. unknown proxy_jump target), the original
// file is preserved (atomic write + reload check).
func TestConfigAddServer_RollsBackOnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	if code := configCmd([]string{"init"}); code != 0 {
		t.Fatalf("config init: %d", code)
	}
	before, _ := os.ReadFile(cfgPath)

	_, errOut := captureOutput(func() {
		code := configCmd([]string{
			"add-server", "--name", "bad",
			"--host", "h", "--user", "u", "--auth", "agent",
			"--proxy-jump", "ghost",
		})
		if code == 0 {
			t.Error("expected validation failure to surface")
		}
	})
	if !strings.Contains(errOut, "validation failed") {
		t.Errorf("expected validation failure message, got: %q", errOut)
	}
	after, _ := os.ReadFile(cfgPath)
	if string(before) != string(after) {
		t.Errorf("file mutated despite validation failure")
	}
	// Ensure the .tmp companion was cleaned up.
	if _, err := os.Stat(cfgPath + ".tmp"); err == nil {
		t.Errorf("temp file lingered after rollback")
	}
}

// TestConfigAddServer_MissingRequired verifies fail-fast on missing flags.
func TestConfigAddServer_MissingRequired(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	_, errOut := captureOutput(func() {
		code := configCmd([]string{"add-server", "--host", "h"})
		if code == 0 {
			t.Error("expected non-zero exit when required flags missing")
		}
	})
	if !strings.Contains(errOut, "required") {
		t.Errorf("expected 'required' in error, got: %q", errOut)
	}
}

// TestConfigValidateMissingFile verifies that `config validate` exits non-zero
// when the config file does not exist.
func TestConfigValidateMissingFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nonexistent.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	code := configCmd([]string{"validate"})
	if code == 0 {
		t.Error("expected non-zero exit when config file does not exist")
	}
}

// TestConfigAddServer_NameOnlyInCommentIsNotDuplicate: the default template
// contains "# [servers.example]" — a commented-out header must not block
// adding a real server named "example".
func TestConfigAddServer_NameOnlyInCommentIsNotDuplicate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	if code := configCmd([]string{"init"}); code != 0 {
		t.Fatalf("config init: %d", code)
	}
	_, errOut := captureOutput(func() {
		code := configCmd([]string{
			"add-server", "--name", "example",
			"--host", "example.com", "--user", "u", "--auth", "agent",
		})
		if code != 0 {
			t.Errorf("add-server --name example exit = %d, want 0", code)
		}
	})
	if strings.Contains(errOut, "already exists") {
		t.Errorf("commented template header misdetected as duplicate: %q", errOut)
	}
}

// TestConfigAddServer_PrefixNameIsNotDuplicate: existing [servers.web1] must
// not block adding "web" (substring in the other direction is exercised by
// the anchored ] terminator).
func TestConfigAddServer_PrefixNameIsNotDuplicate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)

	if code := configCmd([]string{"init"}); code != 0 {
		t.Fatalf("config init: %d", code)
	}
	if code := configCmd([]string{
		"add-server", "--name", "web1",
		"--host", "h", "--user", "u", "--auth", "agent",
	}); code != 0 {
		t.Fatalf("add-server web1: %d", code)
	}
	if code := configCmd([]string{
		"add-server", "--name", "web",
		"--host", "h2", "--user", "u", "--auth", "agent",
	}); code != 0 {
		t.Errorf("add-server web after web1 exit = %d, want 0", code)
	}
}
