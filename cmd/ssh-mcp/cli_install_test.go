package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout captures whatever f writes to os.Stdout.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// hasAutoApproveAssignment returns true if the text contains an autoApprove
// *assignment* (i.e. "autoApprove": or autoApprove =) rather than just a
// comment mentioning the word. This mirrors what check-no-insecure.sh checks.
func hasAutoApproveAssignment(s string) bool {
	// JSON key: "autoApprove":
	if strings.Contains(s, `"autoApprove"`) {
		return true
	}
	// TOML key: autoApprove =
	if strings.Contains(s, "autoApprove =") || strings.Contains(s, "autoApprove=") {
		return true
	}
	return false
}

// TestInstallClaudeDesktopNoAutoApprove verifies that the claude-desktop
// install snippet does NOT contain an autoApprove assignment (S-10).
// The output may contain the word in a warning comment, which is expected.
func TestInstallClaudeDesktopNoAutoApprove(t *testing.T) {
	out := captureStdout(t, func() {
		installClaudeDesktop("/usr/local/bin/ssh-mcp")
	})

	if hasAutoApproveAssignment(out) {
		t.Fatalf("S-10 violation: install claude-desktop output contains autoApprove assignment.\nOutput:\n%s", out)
	}
	// Must contain the binary reference.
	if !strings.Contains(out, "ssh-mcp") {
		t.Fatalf("install claude-desktop output missing binary reference.\nOutput:\n%s", out)
	}
	// Must contain JSON structure.
	if !strings.Contains(out, "mcpServers") {
		t.Fatalf("install claude-desktop output missing 'mcpServers' key.\nOutput:\n%s", out)
	}
}

// TestInstallClaudeCodeNoAutoApprove verifies the claude-code output (S-10).
// Claude Code now ships an MCP-management CLI, so the output is the
// `claude mcp add` command rather than a JSON snippet. We assert on the
// CLI form and the absence of any autoApprove assignment.
func TestInstallClaudeCodeNoAutoApprove(t *testing.T) {
	out := captureStdout(t, func() {
		installClaudeCode("/usr/local/bin/ssh-mcp")
	})

	if hasAutoApproveAssignment(out) {
		t.Fatalf("S-10 violation: install claude-code output contains autoApprove assignment.\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "claude mcp add") {
		t.Fatalf("install claude-code output missing 'claude mcp add' CLI hint.\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "ssh-bridge") {
		t.Fatalf("install claude-code output missing the ssh-bridge name.\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "/usr/local/bin/ssh-mcp") {
		t.Fatalf("install claude-code output missing the binary path.\nOutput:\n%s", out)
	}
}

// TestInstallCodexNoAutoApprove verifies the codex output (S-10).
// Codex ships `codex mcp add`, so we recommend that CLI rather than
// hand-editing the TOML.
func TestInstallCodexNoAutoApprove(t *testing.T) {
	out := captureStdout(t, func() {
		installCodex("/usr/local/bin/ssh-mcp")
	})

	if hasAutoApproveAssignment(out) {
		t.Fatalf("S-10 violation: install codex output contains autoApprove assignment.\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "codex mcp add") {
		t.Fatalf("install codex output missing 'codex mcp add' CLI hint.\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "ssh-bridge") {
		t.Fatalf("install codex output missing the ssh-bridge name.\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "/usr/local/bin/ssh-mcp") {
		t.Fatalf("install codex output missing the binary path.\nOutput:\n%s", out)
	}
}

// TestInstallUnknownTargetReturnsNonZero verifies unknown targets return 1.
func TestInstallUnknownTargetReturnsNonZero(t *testing.T) {
	code := installCmd([]string{"unknown-client"})
	if code == 0 {
		t.Fatal("expected non-zero exit code for unknown target")
	}
}

// TestInstallNoArgsReturnsNonZero verifies that no args returns 1.
func TestInstallNoArgsReturnsNonZero(t *testing.T) {
	code := installCmd([]string{})
	if code == 0 {
		t.Fatal("expected non-zero exit code when no args given")
	}
}
