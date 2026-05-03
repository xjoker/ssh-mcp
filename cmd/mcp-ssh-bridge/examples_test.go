package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExamplesNoAutoApprove mirrors the check-no-insecure.sh S-10 check:
// it scans each line of every example file; if a line contains "autoApprove"
// it must NOT also contain any destructive tool name on that same line.
// This is the same two-grep pipeline used in the script.
func TestExamplesNoAutoApprove(t *testing.T) {
	// Locate examples/ relative to the module root.
	// From cmd/mcp-ssh-bridge/ we go up two levels.
	examplesDir := filepath.Join("..", "..", "examples")
	if _, err := os.Stat(examplesDir); err != nil {
		t.Fatalf("examples dir not found at %q: %v", examplesDir, err)
	}

	destructiveTools := []string{
		"ssh_exec",
		"sftp_op",
		"ssh_group_exec",
		"tunnel",
		"session_send",
		"ssh_quick_setup",
	}

	entries, err := os.ReadDir(examplesDir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", examplesDir, err)
	}

	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".json" && ext != ".toml" {
			continue
		}

		path := filepath.Join(examplesDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", path, err)
		}

		// Check per-line: a line with "autoApprove" must not also have a tool name.
		for lineNum, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "autoApprove") {
				continue
			}
			for _, tool := range destructiveTools {
				if strings.Contains(line, tool) {
					t.Errorf("S-10 violation in %s line %d: line contains both 'autoApprove' and %q:\n  %s",
						path, lineNum+1, tool, line)
				}
			}
		}
	}
}

// TestExamplesFilesExist verifies that all five expected example files are
// present.
func TestExamplesFilesExist(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "examples")

	required := []string{
		"config.toml",
		"config-min.toml",
		"claude-desktop.json",
		"claude-code.json",
		"codex-config.toml",
	}

	for _, name := range required {
		path := filepath.Join(examplesDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing example file: %s (%v)", path, err)
		}
	}
}

// TestExamplesContainWarning checks that each example file contains the
// required WARNING comment (mentions autoApprove and must-not-use).
func TestExamplesContainWarning(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "examples")

	files := []string{
		"config.toml",
		"config-min.toml",
		"claude-desktop.json",
		"claude-code.json",
		"codex-config.toml",
	}

	for _, name := range files {
		path := filepath.Join(examplesDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", path, err)
		}
		content := string(data)
		// Must mention autoApprove in the context of a warning.
		if !strings.Contains(content, "autoApprove") {
			t.Errorf("%s: missing WARNING comment about autoApprove", path)
		}
		if !strings.Contains(content, "WARNING") {
			t.Errorf("%s: missing WARNING keyword", path)
		}
	}
}
