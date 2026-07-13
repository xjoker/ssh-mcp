package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestPermissionsClaudeCodeReadOnlyByDefault(t *testing.T) {
	out := captureStdout(t, func() {
		if code := permissionsCmd([]string{"claude-code"}); code != 0 {
			t.Fatalf("permissionsCmd returned %d, want 0", code)
		}
	})

	var snippet struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal([]byte(out), &snippet); err != nil {
		t.Fatalf("parse JSON output: %v\n%s", err, out)
	}

	want := []string{
		"mcp__ssh-bridge__audit_query",
		"mcp__ssh-bridge__list_servers",
		"mcp__ssh-bridge__sftp_list",
		"mcp__ssh-bridge__sftp_read",
		"mcp__ssh-bridge__sftp_stat",
	}
	if strings.Join(snippet.Permissions.Allow, "\n") != strings.Join(want, "\n") {
		t.Fatalf("allow list mismatch\ngot:  %q\nwant: %q", snippet.Permissions.Allow, want)
	}
}

func TestPermissionsStandardNeverAutoApprovesTier3(t *testing.T) {
	for _, target := range []string{"claude-code", "codex"} {
		t.Run(target, func(t *testing.T) {
			out := captureStdout(t, func() {
				if code := permissionsCmd([]string{target, "--tier", "standard"}); code != 0 {
					t.Fatalf("permissionsCmd returned %d, want 0", code)
				}
			})

			for _, forbidden := range []string{"sftp_upload", "tunnel", "ssh_persistent_setup", "self_update"} {
				if strings.Contains(out, forbidden) {
					t.Fatalf("%s output auto-approves Tier 3 tool %q:\n%s", target, forbidden, out)
				}
			}
			for _, required := range []string{"ssh_exec", "ssh_group_exec", "sftp_op", "session_send", "ssh_quick_setup"} {
				if !strings.Contains(out, required) {
					t.Fatalf("%s output is missing standard tool %q:\n%s", target, required, out)
				}
			}
		})
	}
}

func TestPermissionsCodexUsesPerToolApprovalMode(t *testing.T) {
	out := captureStdout(t, func() {
		if code := permissionsCmd([]string{"codex", "--server-name", "ops-bridge"}); code != 0 {
			t.Fatalf("permissionsCmd returned %d, want 0", code)
		}
	})

	if !strings.Contains(out, "[mcp_servers.ops-bridge.tools.list_servers]") {
		t.Fatalf("missing per-tool Codex table:\n%s", out)
	}
	if !strings.Contains(out, `approval_mode = "auto"`) {
		t.Fatalf("missing Codex auto approval mode:\n%s", out)
	}
	if strings.Contains(out, "enabled_tools") {
		t.Fatalf("permission output must not hide non-approved tools with enabled_tools:\n%s", out)
	}
	var parsed map[string]any
	if _, err := toml.Decode(out, &parsed); err != nil {
		t.Fatalf("Codex output is not valid TOML: %v\n%s", err, out)
	}
}

func TestPermissionsRejectsUnknownTargetAndTier(t *testing.T) {
	if code := permissionsCmd([]string{"unknown"}); code == 0 {
		t.Fatal("unknown target returned success")
	}
	if code := permissionsCmd([]string{"codex", "--tier", "all"}); code == 0 {
		t.Fatal("unsafe tier returned success")
	}
}
