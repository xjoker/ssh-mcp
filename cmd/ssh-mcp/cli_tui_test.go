package main

import (
	"path/filepath"
	"testing"
)

func TestParseTUIOptionsHonorsExplicitPaths(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	auditPath := filepath.Join(t.TempDir(), "audit")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	options, code := parseTUIOptions([]string{"--path", configPath, "--audit-dir", auditPath, "--known-hosts", knownHostsPath})
	if code != 0 {
		t.Fatalf("parseTUIOptions exit code = %d", code)
	}
	if options.ConfigPath != configPath || options.AuditDir != auditPath || options.KnownHostsPath != knownHostsPath {
		t.Fatalf("options = %+v, want explicit paths", options)
	}
}
