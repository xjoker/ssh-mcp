package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
)

// mustJSON marshals v to JSON or panics. Used for concise test args.
// Also consumed by sftp_tools_test.go which calls mustJSON but does not define it.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// wrappedErr is a minimal error type used for testing error-mapping helpers.
type wrappedErr struct{ msg string }

func (e *wrappedErr) Error() string { return e.msg }

// --------------------------------------------------------------------------
// ssh_exec pre-validation tests
// --------------------------------------------------------------------------

// TestSSHExec_MissingCommand verifies that an empty command returns INVALID_ARGUMENT.
func TestSSHExec_MissingCommand(t *testing.T) {
	deps := minDeps(true)
	args := mustJSON(map[string]any{
		"server":  "prod",
		"command": "",
	})
	resp := handleSSHExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for empty command")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSSHExec_BothServerAndInline verifies INVALID_ARGUMENT when both server and
// inline are supplied (oneOf violation).
func TestSSHExec_BothServerAndInline(t *testing.T) {
	deps := minDeps(true)
	args := mustJSON(map[string]any{
		"server":  "prod",
		"inline":  map[string]any{"host": "1.2.3.4", "user": "root"},
		"command": "ls",
	})
	resp := handleSSHExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK when both server and inline supplied")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSSHExec_NeitherServerNorInline verifies INVALID_ARGUMENT when both are omitted.
func TestSSHExec_NeitherServerNorInline(t *testing.T) {
	deps := minDeps(true)
	args := mustJSON(map[string]any{
		"command": "ls",
	})
	resp := handleSSHExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK when neither server nor inline supplied")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSSHExec_InlineCredsDisabled verifies INLINE_CREDS_DISABLED when the feature
// is turned off in Settings.
func TestSSHExec_InlineCredsDisabled(t *testing.T) {
	deps := minDeps(false) // inline disabled
	args := mustJSON(map[string]any{
		"inline": map[string]any{
			"host": "1.2.3.4",
			"user": "root",
		},
		"command": "ls",
	})
	resp := handleSSHExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK when inline creds are disabled")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInlineCredsDisabled {
		t.Fatalf("expected INLINE_CREDS_DISABLED, got %+v", resp.Error)
	}
}

// TestSSHExec_ServerNotFound verifies INVALID_ARGUMENT for an unknown server name.
func TestSSHExec_ServerNotFound(t *testing.T) {
	deps := minDeps(true)
	args := mustJSON(map[string]any{
		"server":  "nonexistent-server",
		"command": "ls",
	})
	resp := handleSSHExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for unknown server")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSSHExec_InvalidJSON verifies INVALID_ARGUMENT for malformed JSON.
func TestSSHExec_InvalidJSON(t *testing.T) {
	deps := minDeps(true)
	resp := handleSSHExec(context.Background(), deps, json.RawMessage(`{invalid`))
	if resp.OK {
		t.Fatal("expected not-OK for invalid JSON")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// --------------------------------------------------------------------------
// Error mapping tests — exercise mapSSHConnErr directly (defined in conn.go)
// --------------------------------------------------------------------------

// TestMapSSHConnErr_HostKeyUnknown verifies HOST_KEY_UNKNOWN mapping.
func TestMapSSHConnErr_HostKeyUnknown(t *testing.T) {
	err := &wrappedErr{"HOST_KEY_UNKNOWN for host: not in known_hosts"}
	resp := mapSSHConnErr(err)
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error.Code != envelope.CodeHostKeyUnknown {
		t.Fatalf("expected HOST_KEY_UNKNOWN, got %s", resp.Error.Code)
	}
}

// TestMapSSHConnErr_HostKeyMismatch verifies HOST_KEY_MISMATCH mapping.
func TestMapSSHConnErr_HostKeyMismatch(t *testing.T) {
	err := &wrappedErr{"HOST_KEY_MISMATCH for host: key changed"}
	resp := mapSSHConnErr(err)
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error.Code != envelope.CodeHostKeyMismatch {
		t.Fatalf("expected HOST_KEY_MISMATCH, got %s", resp.Error.Code)
	}
}

// TestMapSSHConnErr_AuthFailed verifies AUTH_FAILED mapping.
func TestMapSSHConnErr_AuthFailed(t *testing.T) {
	err := &wrappedErr{"ssh: unable to authenticate, attempted methods [none publickey]"}
	resp := mapSSHConnErr(err)
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error.Code != envelope.CodeAuthFailed {
		t.Fatalf("expected AUTH_FAILED, got %s", resp.Error.Code)
	}
}
