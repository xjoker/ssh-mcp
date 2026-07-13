package main

import (
	"path/filepath"
	"testing"
)

func TestParseTUIOptionsHonorsExplicitPaths(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	auditPath := filepath.Join(t.TempDir(), "audit")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	options, code, run := parseTUIOptions([]string{"--path", configPath, "--audit-dir", auditPath, "--known-hosts", knownHostsPath})
	if code != 0 {
		t.Fatalf("parseTUIOptions exit code = %d", code)
	}
	if !run {
		t.Fatal("parseTUIOptions unexpectedly handled the command without running TUI")
	}
	if options.ConfigPath != configPath || options.AuditDir != auditPath || options.KnownHostsPath != knownHostsPath {
		t.Fatalf("options = %+v, want explicit paths", options)
	}
}

func TestTUICmdHelpReturnsSuccess(t *testing.T) {
	if code := tuiCmd([]string{"--help"}); code != 0 {
		t.Fatalf("tui --help exit code = %d, want 0", code)
	}
}
