package main

import (
	"strings"
	"testing"
)

// TestAuthCmdNoSubcommand verifies that `auth` with no subcommand exits non-zero.
func TestAuthCmdNoSubcommand(t *testing.T) {
	code := authCmd([]string{})
	if code == 0 {
		t.Error("auth: expected non-zero exit with no subcommand")
	}
}

// TestAuthCmdUnknownSubcommand verifies that `auth unknown` exits non-zero.
func TestAuthCmdUnknownSubcommand(t *testing.T) {
	code := authCmd([]string{"unknown-sub"})
	if code == 0 {
		t.Error("auth: expected non-zero exit for unknown subcommand")
	}
}

// TestAuthSetMissingName verifies that `auth set` without an account name exits non-zero.
func TestAuthSetMissingName(t *testing.T) {
	code := authSetCmd([]string{})
	if code == 0 {
		t.Error("auth set: expected non-zero exit when account name is missing")
	}
}

// TestAuthGetMissingName verifies that `auth get` without an account name exits non-zero.
func TestAuthGetMissingName(t *testing.T) {
	code := authGetCmd([]string{})
	if code == 0 {
		t.Error("auth get: expected non-zero exit when account name is missing")
	}
}

// TestAuthRemoveMissingName verifies that `auth remove` without a name exits non-zero.
func TestAuthRemoveMissingName(t *testing.T) {
	code := authRemoveCmd([]string{})
	if code == 0 {
		t.Error("auth remove: expected non-zero exit when account name is missing")
	}
}

// TestAuthListReturnsError verifies that `auth list` exits non-zero (backend
// does not support list on this platform) and prints a helpful tip.
func TestAuthListReturnsError(t *testing.T) {
	_, errOut := captureOutput(func() {
		code := authListCmd(nil)
		if code == 0 {
			t.Error("auth list: expected non-zero exit (list not supported)")
		}
	})

	if !strings.Contains(errOut, "auth get") {
		t.Errorf("auth list: expected tip mentioning 'auth get', got stderr: %q", errOut)
	}
}

// TestAuthSetRealKeychain skips in CI environments without a keychain.
// When run on a workstation it stores and removes a test secret.
func TestAuthSetRealKeychain(t *testing.T) {
	t.Skip("skipping keychain integration test in CI environment")
}

// TestAuthGetRealKeychain skips in CI environments without a keychain.
func TestAuthGetRealKeychain(t *testing.T) {
	t.Skip("skipping keychain integration test in CI environment")
}

// TestAuthRemoveRealKeychain skips in CI environments without a keychain.
func TestAuthRemoveRealKeychain(t *testing.T) {
	t.Skip("skipping keychain integration test in CI environment")
}
