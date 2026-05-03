package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
