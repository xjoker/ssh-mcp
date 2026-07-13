package main

import (
	"path/filepath"
	"testing"
)

func TestParseTUIOptionsHonorsExplicitPaths(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	options, code, run := parseTUIOptions([]string{"--path", configPath})
	if code != 0 {
		t.Fatalf("parseTUIOptions exit code = %d", code)
	}
	if !run {
		t.Fatal("parseTUIOptions unexpectedly handled the command without running TUI")
	}
	if options.ConfigPath != configPath {
		t.Fatalf("options = %+v, want config path %q", options, configPath)
	}
}

func TestParseTUIOptionsRejectsRemovedManagementFlags(t *testing.T) {
	_, code, run := parseTUIOptions([]string{"--audit-dir", t.TempDir()})
	if code == 0 || run {
		t.Fatalf("removed --audit-dir flag returned code=%d run=%v", code, run)
	}
}

func TestTUICmdHelpReturnsSuccess(t *testing.T) {
	if code := tuiCmd([]string{"--help"}); code != 0 {
		t.Fatalf("tui --help exit code = %d, want 0", code)
	}
}
