package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalServerConfig is a valid TOML config with one server for list/show tests.
const minimalServerConfig = `[settings]

[servers.testbox]
host = "192.0.2.1"
port = 2222
user = "alice"
auth = "agent"
description = "test server"
tags = ["dev", "lab"]
`

// serverConfigWithPassword has a server whose password uses a keychain reference.
const serverConfigWithPassword = `[settings]
allow_config_plaintext_password = false

[servers.secured]
host = "192.0.2.2"
user = "bob"
auth = "key"
key_path = "/home/bob/.ssh/id_ed25519"
password = "keychain:mcp-ssh-bridge:bob"
`

// writeConfig writes content to a temp config file and sets the env var.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_SSH_BRIDGE_CONFIG", cfgPath)
	return cfgPath
}

// TestServerListContainsName verifies that `server list` outputs the configured
// server name.
func TestServerListContainsName(t *testing.T) {
	writeConfig(t, minimalServerConfig)

	var code int
	outStr, errStr := captureOutput(func() {
		code = serverCmd([]string{"list"})
	})
	if code != 0 {
		t.Errorf("server list: expected exit 0, got non-zero; stderr: %s", errStr)
	}

	if !strings.Contains(outStr, "testbox") {
		t.Errorf("server list: expected 'testbox' in output, got:\n%s", outStr)
	}
}

// TestServerListEmpty verifies that `server list` handles an empty server map.
func TestServerListEmpty(t *testing.T) {
	writeConfig(t, "[settings]\n")

	outStr, _ := captureOutput(func() {
		code := serverCmd([]string{"list"})
		if code != 0 {
			t.Error("server list: expected exit 0 for empty config")
		}
	})

	if !strings.Contains(outStr, "No servers") {
		t.Errorf("expected 'No servers' message, got: %q", outStr)
	}
}

// TestServerShowDisplaysFields verifies that `server show` prints expected fields.
func TestServerShowDisplaysFields(t *testing.T) {
	writeConfig(t, minimalServerConfig)

	outStr, _ := captureOutput(func() {
		code := serverCmd([]string{"show", "testbox"})
		if code != 0 {
			t.Error("server show: expected exit 0")
		}
	})

	for _, want := range []string{"testbox", "192.0.2.1", "alice", "agent"} {
		if !strings.Contains(outStr, want) {
			t.Errorf("server show: expected %q in output, got:\n%s", want, outStr)
		}
	}
}

// TestServerShowNoPlaintextPassword verifies that `server show` does not print
// the plaintext value of a keychain-referenced password credential.
func TestServerShowNoPlaintextPassword(t *testing.T) {
	// Use a config with a plaintext password reference that should NEVER appear
	// in output.
	cfg := `[settings]
allow_config_plaintext_password = true

[servers.insecure]
host = "192.0.2.3"
user = "charlie"
auth = "password"
password = "plaintext:supersecretpassword"
`
	writeConfig(t, cfg)

	outStr, _ := captureOutput(func() {
		serverCmd([]string{"show", "insecure"})
	})

	if strings.Contains(outStr, "supersecretpassword") {
		t.Errorf("server show: plaintext secret value leaked into output:\n%s", outStr)
	}
	// Should mention that it's plaintext but value is hidden.
	if !strings.Contains(outStr, "hidden") && !strings.Contains(outStr, "plaintext") {
		t.Errorf("server show: expected 'plaintext' or 'hidden' label in output, got:\n%s", outStr)
	}
}

// TestServerShowNotFound verifies that `server show` exits non-zero for an
// unknown server name.
func TestServerShowNotFound(t *testing.T) {
	writeConfig(t, minimalServerConfig)

	code := serverCmd([]string{"show", "nonexistent-server-xyz"})
	if code == 0 {
		t.Error("server show: expected non-zero exit for unknown server")
	}
}

// TestServerRemoveDeletesEntry verifies that `server remove` removes the named
// server and the resulting config no longer contains it.
func TestServerRemoveDeletesEntry(t *testing.T) {
	cfgPath := writeConfig(t, minimalServerConfig)

	code := serverCmd([]string{"remove", "testbox"})
	if code != 0 {
		t.Fatalf("server remove: expected exit 0, got non-zero")
	}

	// Load the saved config and verify testbox is gone.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "testbox") {
		t.Errorf("server remove: server still present in config after removal:\n%s", data)
	}
}

// TestServerAddAddsEntry verifies that `server add` appends a new server section
// to the config file when all required flags are provided.
func TestServerAddAddsEntry(t *testing.T) {
	cfgPath := writeConfig(t, "[settings]\n")

	code := serverCmd([]string{
		"add", "newbox",
		"--host", "10.0.0.1",
		"--user", "root",
		"--auth", "agent",
		"--port", "22",
		"--path", cfgPath,
	})
	if code != 0 {
		t.Fatalf("server add: expected exit 0, got non-zero")
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{"newbox", "10.0.0.1", "root", "agent"} {
		if !strings.Contains(content, want) {
			t.Errorf("server add: expected %q in config, got:\n%s", want, content)
		}
	}
}

// TestServerTestMissingName verifies that `server test` without a name exits non-zero.
func TestServerTestMissingName(t *testing.T) {
	code := serverCmd([]string{"test"})
	if code == 0 {
		t.Error("server test: expected non-zero exit when no name provided")
	}
}

// TestServerRemoveNotFound verifies that `server remove` exits non-zero when
// the named server does not exist.
func TestServerRemoveNotFound(t *testing.T) {
	writeConfig(t, minimalServerConfig)

	code := serverCmd([]string{"remove", "no-such-server"})
	if code == 0 {
		t.Error("server remove: expected non-zero exit for unknown server")
	}
}

// --------------------------------------------------------------------------
// M01: server name validation (cliServerNameRe / validateServerName)
// --------------------------------------------------------------------------

// TestServerName_ValidateRejectsBadInput verifies that validateServerName
// rejects names that do not match ^[a-z0-9][a-z0-9_-]*$ or exceed length limits.
func TestServerName_ValidateRejectsBadInput(t *testing.T) {
	bad := []string{
		"Bad-Name",      // uppercase
		"a*b",           // special char
		"-leading",      // starts with dash
		"",              // empty
		strings.Repeat("a", 65), // > 64 chars
	}
	for _, name := range bad {
		if err := validateServerName(name); err == nil {
			t.Errorf("validateServerName(%q): expected error, got nil", name)
		}
	}
}

// TestServerName_ValidateAcceptsGoodInput verifies that validateServerName
// accepts names that match the allowed pattern.
func TestServerName_ValidateAcceptsGoodInput(t *testing.T) {
	good := []string{
		"myserver",
		"server-1",
		"server_2",
		"a",
		strings.Repeat("a", 64), // exactly 64 chars
		"my-server-01",
	}
	for _, name := range good {
		if err := validateServerName(name); err != nil {
			t.Errorf("validateServerName(%q): unexpected error: %v", name, err)
		}
	}
}

// TestServerAdd_RejectsInvalidName verifies that `server add` rejects a name
// containing an invalid character and does not write the server to the config file.
func TestServerAdd_RejectsInvalidName(t *testing.T) {
	cfgPath := writeConfig(t, "[settings]\n")

	code := serverCmd([]string{
		"add", "evil%name",
		"--host", "10.0.0.1",
		"--user", "root",
		"--auth", "agent",
		"--port", "22",
		"--path", cfgPath,
	})
	if code == 0 {
		t.Fatal("server add: expected non-zero exit for invalid server name")
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "evil") {
		t.Errorf("server add: invalid server was written to config:\n%s", data)
	}
}
