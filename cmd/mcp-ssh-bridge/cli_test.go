package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestRegisterAndLookup verifies that registerSubcommand + lookupSubcommand
// round-trip correctly.
func TestRegisterAndLookup(t *testing.T) {
	const name = "test-cmd-roundtrip"
	want := 42

	registerSubcommand(name, func(_ []string) int { return want })

	h, ok := lookupSubcommand(name)
	if !ok {
		t.Fatalf("lookupSubcommand(%q): not found after registration", name)
	}
	if got := h(nil); got != want {
		t.Fatalf("handler returned %d, want %d", got, want)
	}
}

// TestLookupMissing verifies that an unknown subcommand is not found.
func TestLookupMissing(t *testing.T) {
	_, ok := lookupSubcommand("definitely-not-registered-xyz")
	if ok {
		t.Fatal("expected lookupSubcommand to return false for unknown name")
	}
}

// TestVersionCmdOutput verifies that versionCmd prints a line containing
// "mcp-ssh-bridge".
func TestVersionCmdOutput(t *testing.T) {
	// Capture stdout.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	code := versionCmd(nil)

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}

	if code != 0 {
		t.Fatalf("versionCmd returned exit code %d, want 0", code)
	}

	out := buf.String()
	if !strings.Contains(out, "mcp-ssh-bridge") {
		t.Fatalf("versionCmd output %q does not contain %q", out, "mcp-ssh-bridge")
	}
}
