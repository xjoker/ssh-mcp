package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
)

func TestSSHGroupExecSchemaExposesTerminateOnTimeout(t *testing.T) {
	if !strings.Contains(string(sshGroupExecSchema), `"terminate_on_timeout"`) {
		t.Fatalf("ssh_group_exec schema is missing terminate_on_timeout: %s", sshGroupExecSchema)
	}
}

// --------------------------------------------------------------------------
// H01 — cwd / default_dir allowed_paths enforcement (pre-connect syntactic)
// --------------------------------------------------------------------------

// groupDepsWithAllowedPaths builds a Deps that has server "s1" configured with
// allowed_paths=["/tmp"].  Pool is intentionally left nil: the syntactic
// allowed_paths check must fire BEFORE Pool.Get so these tests must never
// reach the Pool.
func groupDepsWithAllowedPaths() *Deps {
	d := minDeps(false)
	d.Cfg.Servers = map[string]config.ServerConfig{
		"s1": {
			Name:         "s1",
			Host:         "localhost",
			Port:         22,
			User:         "u",
			Auth:         "agent",
			AllowedPaths: []string{"/tmp"},
		},
	}
	return d
}

// TestGroupExec_CwdAllowedPathsEnforced: cwd="/etc" with allowed_paths=["/tmp"]
// must produce PERMISSION_DENIED in the per-server sub-result, not OK.
// Pool is nil — this test verifies that the allowed_paths check fires BEFORE
// any connection attempt.
func TestGroupExec_CwdAllowedPathsEnforced(t *testing.T) {
	deps := groupDepsWithAllowedPaths()
	args := mustJSON(map[string]any{
		"servers": []string{"s1"},
		"command": "ls",
		"cwd":     "/etc",
	})
	resp := handleSSHGroupExec(context.Background(), deps, args)

	// Top-level response is not OK (partial/total failure).
	if resp.OK {
		t.Fatal("expected not-OK when cwd is outside allowed_paths")
	}

	// Extract the per-server result.
	output, ok := resp.Data.(groupExecOutput)
	if !ok {
		t.Fatalf("expected groupExecOutput, got %T", resp.Data)
	}
	if len(output.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(output.Results))
	}
	r := output.Results[0]
	if r.OK {
		t.Fatal("server result should not be OK when cwd is denied")
	}
	if r.Error == nil {
		t.Fatal("server result should carry an error")
	}
	if r.Error.Code != envelope.CodePermissionDenied {
		t.Errorf("expected PERMISSION_DENIED, got %q", r.Error.Code)
	}
}

// TestGroupExec_DefaultDirEnforced: server.DefaultDir="/etc" with allowed_paths=["/tmp"],
// no explicit cwd → the default_dir must be subject to the same check.
func TestGroupExec_DefaultDirEnforced(t *testing.T) {
	d := minDeps(false)
	d.Cfg.Servers = map[string]config.ServerConfig{
		"s2": {
			Name:         "s2",
			Host:         "localhost",
			Port:         22,
			User:         "u",
			Auth:         "agent",
			AllowedPaths: []string{"/tmp"},
			DefaultDir:   "/etc",
		},
	}
	args := mustJSON(map[string]any{
		"servers": []string{"s2"},
		"command": "ls",
		// no "cwd" field — default_dir should be used and denied
	})
	resp := handleSSHGroupExec(context.Background(), d, args)

	if resp.OK {
		t.Fatal("expected not-OK when default_dir is outside allowed_paths")
	}

	output, ok := resp.Data.(groupExecOutput)
	if !ok {
		t.Fatalf("expected groupExecOutput, got %T", resp.Data)
	}
	if len(output.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(output.Results))
	}
	r := output.Results[0]
	if r.OK {
		t.Fatal("server result should not be OK when default_dir is denied")
	}
	if r.Error == nil {
		t.Fatal("server result should carry an error")
	}
	if r.Error.Code != envelope.CodePermissionDenied {
		t.Errorf("expected PERMISSION_DENIED, got %q", r.Error.Code)
	}
}

// --------------------------------------------------------------------------
// ssh_group_exec tests
// --------------------------------------------------------------------------

// TestSSHGroupExec_InvalidJSON verifies INVALID_ARGUMENT for malformed JSON.
func TestSSHGroupExec_InvalidJSON(t *testing.T) {
	deps := minDeps(false)
	resp := handleSSHGroupExec(context.Background(), deps, json.RawMessage(`{bad`))
	if resp.OK {
		t.Fatal("expected not-OK for invalid JSON")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSSHGroupExec_MissingCommand verifies INVALID_ARGUMENT for an empty command.
func TestSSHGroupExec_MissingCommand(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{
		"servers": []string{"server1"},
		"command": "",
	})
	resp := handleSSHGroupExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for empty command")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

func TestSSHGroupExec_RejectsTooSmallTimeout(t *testing.T) {
	deps := minDeps(false)
	deps.Cfg.Servers = map[string]config.ServerConfig{
		"s1": {Name: "s1", Host: "localhost", User: "u", Auth: "agent"},
	}
	args := mustJSON(map[string]any{
		"servers":    []string{"s1"},
		"command":    "ls",
		"timeout_ms": 1,
	})
	resp := handleSSHGroupExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for too-small timeout")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSSHGroupExec_BothServersAndTag verifies INVALID_ARGUMENT when both servers and
// tag are provided.
func TestSSHGroupExec_BothServersAndTag(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{
		"servers": []string{"s1"},
		"tag":     "production",
		"command": "ls",
	})
	resp := handleSSHGroupExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK when both servers and tag are supplied")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSSHGroupExec_NeitherServersNorTag verifies INVALID_ARGUMENT when neither
// servers nor tag is provided.
func TestSSHGroupExec_NeitherServersNorTag(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{
		"command": "ls",
	})
	resp := handleSSHGroupExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSSHGroupExec_UnknownServer verifies INVALID_ARGUMENT for a non-existent server
// name (checked before any connection attempt).
func TestSSHGroupExec_UnknownServer(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{
		"servers": []string{"ghost-server"},
		"command": "uptime",
	})
	resp := handleSSHGroupExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for unknown server")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSSHGroupExec_TagNoMatch verifies INVALID_ARGUMENT when the tag matches no
// configured servers.
func TestSSHGroupExec_TagNoMatch(t *testing.T) {
	deps := minDeps(false)
	deps.Cfg.Servers = map[string]config.ServerConfig{
		"srv1": {Name: "srv1", Host: "h1", Port: 22, User: "u", Tags: []string{"staging"}},
	}
	args := mustJSON(map[string]any{
		"tag":     "production",
		"command": "ls",
	})
	resp := handleSSHGroupExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK when tag matches no servers")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}
