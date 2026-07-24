//go:build windows

package updater

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceWindowsBinaryCommitsBeforeReturning(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "candidate.exe")
	destination := filepath.Join(dir, "ssh-mcp.exe")
	mustWriteWindowsTestFile(t, source, "new")
	mustWriteWindowsTestFile(t, destination, "old")

	var backup string
	err := replaceWindowsBinary(source, destination, func(path string) error {
		backup = path
		if got := mustReadWindowsTestFile(t, destination); got != "new" {
			t.Fatalf("destination during cleanup scheduling = %q, want new", got)
		}
		if _, statErr := os.Stat(source); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("candidate still exists after synchronous replacement: %v", statErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustReadWindowsTestFile(t, destination); got != "new" {
		t.Fatalf("destination = %q, want new", got)
	}
	if got := mustReadWindowsTestFile(t, backup); got != "old" {
		t.Fatalf("backup = %q, want old", got)
	}
}

func TestReplaceWindowsBinaryCleanupStartFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "candidate.exe")
	destination := filepath.Join(dir, "ssh-mcp.exe")
	mustWriteWindowsTestFile(t, source, "new")
	mustWriteWindowsTestFile(t, destination, "old")

	err := replaceWindowsBinary(source, destination, func(string) error {
		return errors.New("cleanup helper unavailable")
	})
	if err == nil {
		t.Fatal("replaceWindowsBinary succeeded when cleanup helper could not start")
	}
	if got := mustReadWindowsTestFile(t, destination); got != "old" {
		t.Fatalf("destination after rollback = %q, want old", got)
	}
	if got := mustReadWindowsTestFile(t, source); got != "new" {
		t.Fatalf("candidate after rollback = %q, want new", got)
	}
}

func mustWriteWindowsTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustReadWindowsTestFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
