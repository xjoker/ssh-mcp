package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
)

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
