package tools

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	"github.com/xjoker/mcp-ssh-bridge/internal/session"
)

// --------------------------------------------------------------------------
// fakeTransport — satisfies session.Transport without a real SSH connection.
// Used only to construct a real *session.Manager for idempotent Close tests.
// --------------------------------------------------------------------------

type fakeTransport struct{}

func (f *fakeTransport) OpenShell(_ context.Context, _ string) (
	io.WriteCloser, io.Reader, io.Reader, func() error, error,
) {
	pr, pw := io.Pipe()
	return pw, pr, pr, func() error { return pw.Close() }, nil
}

// newFakeSessionManager returns a real *session.Manager backed by fakeTransport.
// Its Close(id) is idempotent for unknown IDs (returns nil per SDD §6.4).
func newFakeSessionManager() *session.Manager {
	return session.NewManager(&fakeTransport{}, 30*time.Minute)
}

// --------------------------------------------------------------------------
// session_start tests
// --------------------------------------------------------------------------

// TestSessionStart_InvalidJSON verifies INVALID_ARGUMENT for bad JSON.
func TestSessionStart_InvalidJSON(t *testing.T) {
	deps := minDeps(false)
	resp := handleSessionStart(context.Background(), deps, json.RawMessage(`{bad`))
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSessionStart_MissingServer verifies INVALID_ARGUMENT when server is absent.
func TestSessionStart_MissingServer(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{})
	resp := handleSessionStart(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for missing server")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSessionStart_UnknownServer verifies INVALID_ARGUMENT for a server name not
// in the configuration.
func TestSessionStart_UnknownServer(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{"server": "ghost"})
	resp := handleSessionStart(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for unknown server")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// --------------------------------------------------------------------------
// session_send tests
// --------------------------------------------------------------------------

// TestSessionSend_InvalidJSON verifies INVALID_ARGUMENT for bad JSON.
func TestSessionSend_InvalidJSON(t *testing.T) {
	deps := minDeps(false)
	resp := handleSessionSend(context.Background(), deps, json.RawMessage(`{bad`))
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSessionSend_MissingSessionID verifies INVALID_ARGUMENT when session_id is absent.
func TestSessionSend_MissingSessionID(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{"command": "ls"})
	resp := handleSessionSend(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSessionSend_MissingCommand verifies INVALID_ARGUMENT when command is empty.
func TestSessionSend_MissingCommand(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{"session_id": "abc-123", "command": ""})
	resp := handleSessionSend(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// --------------------------------------------------------------------------
// Error mapping unit tests for mapSessionError
// --------------------------------------------------------------------------

// TestSessionError_NotFound verifies "not found" → NOT_FOUND.
func TestSessionError_NotFound(t *testing.T) {
	err := &wrappedErr{"session: Send: session \"dead-id\" not found"}
	resp := mapSessionError(err)
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeNotFound {
		t.Fatalf("expected NOT_FOUND, got %+v", resp.Error)
	}
}

// TestSessionError_Timeout verifies TIMEOUT is mapped with retriable=true.
func TestSessionError_Timeout(t *testing.T) {
	err := &wrappedErr{"session: Send: TIMEOUT: context deadline exceeded"}
	resp := mapSessionError(err)
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeTimeout {
		t.Fatalf("expected TIMEOUT, got %+v", resp.Error)
	}
	if !resp.Error.Retriable {
		t.Fatal("expected retriable=true for TIMEOUT")
	}
}

// TestSessionError_SessionDead verifies SESSION_DEAD mapping.
func TestSessionError_SessionDead(t *testing.T) {
	err := &wrappedErr{"session: Send: SESSION_DEAD (session in error state)"}
	resp := mapSessionError(err)
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeSessionDead {
		t.Fatalf("expected SESSION_DEAD, got %+v", resp.Error)
	}
}

// --------------------------------------------------------------------------
// session_close tests
// --------------------------------------------------------------------------

// TestSessionClose_InvalidJSON verifies INVALID_ARGUMENT for bad JSON.
func TestSessionClose_InvalidJSON(t *testing.T) {
	deps := minDeps(false)
	resp := handleSessionClose(context.Background(), deps, json.RawMessage(`{bad`))
	if resp.OK {
		t.Fatal("expected not-OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSessionClose_MissingSessionID verifies INVALID_ARGUMENT when session_id is
// absent.
func TestSessionClose_MissingSessionID(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{})
	resp := handleSessionClose(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for missing session_id")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// TestSessionClose_Idempotent verifies that closing an unknown session returns OK
// (SDD §6.4 idempotent contract).
func TestSessionClose_Idempotent(t *testing.T) {
	deps := &Deps{
		Cfg: &config.Config{
			Settings: config.Settings{},
			Servers:  map[string]config.ServerConfig{},
		},
		SessionMgr: newFakeSessionManager(),
	}
	args := mustJSON(map[string]any{"session_id": "nonexistent-session-id"})
	resp := handleSessionClose(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("expected OK for idempotent close of unknown session, got %+v", resp.Error)
	}
}
