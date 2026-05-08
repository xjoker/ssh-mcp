package tools

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/session"
	"github.com/xjoker/ssh-mcp/internal/ssh"
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

func (f *fakeTransport) OpenShellPTY(_ context.Context, _ string, _, _ uint32) (
	io.WriteCloser, io.Reader, func() error, error,
) {
	pr, pw := io.Pipe()
	return pw, pr, func() error { return pw.Close() }, nil
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

func TestSessionSend_RejectsTooSmallTimeout(t *testing.T) {
	deps := minDeps(false)
	args := mustJSON(map[string]any{
		"session_id": "abc-123",
		"command":    "ls",
		"timeout_ms": 1,
	})
	resp := handleSessionSend(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for too-small timeout")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

func TestSessionSendOutput_IncludesTruncated(t *testing.T) {
	raw, err := json.Marshal(sessionSendOutput{Truncated: true})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"truncated":true`) {
		t.Fatalf("expected truncated flag in JSON, got %s", raw)
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

// buildFakePool returns a real *ssh.Pool with a nil resolver that is safe to
// use as long as Pool.Get / Pool.GetAdHoc are never called. AddTempServer does
// not require a resolver and can be exercised safely.
func buildFakePool(cfg *config.Config) *ssh.Pool {
	return ssh.NewPool(cfg, nil)
}

// SDD §6.2 / Codex H07: session_start MUST accept inline credentials via
// the oneOf branch and surface a registered name.
func TestSessionStart_InlineDisabled(t *testing.T) {
	cfg := &config.Config{Settings: config.Settings{AllowInlineCredentials: false}}
	deps := &Deps{Cfg: cfg}
	args := json.RawMessage(`{"inline":{"host":"h","user":"u","password":"p"}}`)
	resp := handleSessionStart(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error when inline disabled")
	}
	if resp.Error.Code != envelope.CodeInlineCredsDisabled {
		t.Errorf("got %s want INLINE_CREDS_DISABLED", resp.Error.Code)
	}
}

func TestSessionStart_BothServerAndInlineRejected(t *testing.T) {
	cfg := &config.Config{Settings: config.Settings{AllowInlineCredentials: true}}
	deps := &Deps{Cfg: cfg}
	args := json.RawMessage(`{"server":"x","inline":{"host":"h","user":"u","password":"p"}}`)
	resp := handleSessionStart(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected mutual-exclusion error")
	}
	if resp.Error.Code != envelope.CodeInvalidArgument {
		t.Errorf("got %s want INVALID_ARGUMENT", resp.Error.Code)
	}
}

// TestConfigServerConfigFromInline_AcceptNewHostPropagated verifies that
// configServerConfigFromInline correctly forwards the acceptNewHost argument
// into the returned ServerConfig. This is a unit test for the helper itself.
func TestConfigServerConfigFromInline_AcceptNewHostPropagated(t *testing.T) {
	got := configServerConfigFromInline("myserver", "1.2.3.4", 22, "root", true)
	if !got.AcceptNewHost {
		t.Error("configServerConfigFromInline: AcceptNewHost should be true when acceptNewHost=true")
	}

	got2 := configServerConfigFromInline("myserver", "1.2.3.4", 22, "root", false)
	if got2.AcceptNewHost {
		t.Error("configServerConfigFromInline: AcceptNewHost should be false when acceptNewHost=false")
	}
}

// TestSessionStart_InlineAcceptNewHostPlumbed verifies that when session_start
// receives an inline request with accept_new_host=true the resulting
// QuickSetupSpec.AcceptNewHost is true (demonstrating end-to-end propagation).
func TestSessionStart_InlineAcceptNewHostPlumbed(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{AllowInlineCredentials: true, SessionIdleSeconds: 60},
		Servers:  map[string]config.ServerConfig{},
	}
	qs := &fakeQuickSetup{}
	pool := buildFakePool(cfg)
	// A real SessionMgr is required so Start does not panic; it will fail
	// because the transport is backed by fakeTransport (no real SSH), but that
	// happens after registerInlineSession which is what we are testing.
	mgr := newFakeSessionManager()
	deps := &Deps{Cfg: cfg, QuickSetup: qs, Pool: pool, SessionMgr: mgr}

	args := json.RawMessage(`{"inline":{"host":"h","user":"u","password":"pw","accept_new_host":true}}`)
	// Bound the call: registerInlineSession runs synchronously before
	// SessionMgr.Start is invoked, so by the time the timed-out Start
	// returns the spec has already been recorded. A short timeout keeps
	// the test fast; without it the fake shell sentinel scan blocks until
	// the test framework's outer timeout.
	tCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	handleSessionStart(tCtx, deps, args)

	if len(qs.registerCalls) == 0 {
		t.Fatal("expected inline session to call QuickSetup.Register")
	}
	if !qs.registerCalls[0].spec.AcceptNewHost {
		t.Error("QuickSetupSpec.AcceptNewHost should be true for inline accept_new_host=true")
	}
	// SessionMgr.Start fails (fake transport), so the inline registration
	// must be cleaned up immediately — it should NOT linger in qs.registered.
	if len(qs.removed) != 1 || qs.removed[0] != qs.registerCalls[0].name {
		t.Errorf("expected inline registration to be removed on Start failure; removed=%v", qs.removed)
	}
}

// TestSessionClose_KeepsInlineRegistration verifies that closing an inline
// shell session does not remove the temp-server registration. The server name
// remains reusable by ssh_exec/sftp/tunnel until TTL expiry or server shutdown.
func TestSessionClose_KeepsInlineRegistration(t *testing.T) {
	qs := &fakeQuickSetup{}
	// Pre-populate the inline registration map as if session_start had succeeded.
	const sessID = "sess-test-1"
	const regName = "qs-inline-1"
	inlineSessionRegistrations.Store(sessID, regName)

	deps := &Deps{
		Cfg:        &config.Config{},
		QuickSetup: qs,
		SessionMgr: newFakeSessionManager(),
	}
	args := mustJSON(map[string]any{"session_id": sessID})
	resp := handleSessionClose(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("session_close: %+v", resp.Error)
	}
	if len(qs.removed) != 0 {
		t.Errorf("session_close must not remove temp server %q; got removed=%v", regName, qs.removed)
	}
	if _, lingering := inlineSessionRegistrations.Load(sessID); lingering {
		t.Error("session-to-registration tracking should be removed after close")
	}
}

func TestSessionStart_InlineMissingCreds(t *testing.T) {
	cfg := &config.Config{Settings: config.Settings{AllowInlineCredentials: true, SessionIdleSeconds: 60}}
	qs := &fakeQuickSetup{}
	deps := &Deps{Cfg: cfg, QuickSetup: qs, Pool: nil}
	args := json.RawMessage(`{"inline":{"host":"h","user":"u"}}`)
	resp := handleSessionStart(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error when no inline creds")
	}
	if resp.Error.Code != envelope.CodeInvalidArgument {
		t.Errorf("got %s want INVALID_ARGUMENT", resp.Error.Code)
	}
}

// --------------------------------------------------------------------------
// PTY tool handler tests
// --------------------------------------------------------------------------

// newPTYDeps creates *Deps wired for PTY session tests.
// The SessionMgr uses the package-local fakeTransport whose OpenShellPTY
// returns a loopback pipe pair (stdin writes are readable on stdout).
func newPTYDeps(t *testing.T) *Deps {
	t.Helper()
	cfg := &config.Config{
		Settings: config.Settings{DefaultTimeoutMs: 120000},
		Servers: map[string]config.ServerConfig{
			"myserver": {Name: "myserver", Host: "localhost", Port: 22, User: "root", Auth: "key"},
		},
	}
	mgr := session.NewManager(&fakeTransport{}, 30*time.Minute)
	t.Cleanup(mgr.CloseAll)
	return &Deps{Cfg: cfg, SessionMgr: mgr}
}

// TestSessionStart_PTY_Mode verifies that session_start with pty:true
// returns mode="pty" and a non-empty session_id.
func TestSessionStart_PTY_Mode(t *testing.T) {
	deps := newPTYDeps(t)
	args := mustJSON(map[string]any{
		"server":       "myserver",
		"pty":          true,
		"init_wait_ms": 100,
	})
	tCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	resp := handleSessionStart(tCtx, deps, args)
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Data)
	var out sessionStartOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Mode != "pty" {
		t.Errorf("mode = %q, want 'pty'", out.Mode)
	}
	if out.SessionID == "" {
		t.Error("expected non-empty session_id")
	}
}

// TestSessionSend_PTY_RoutesToSendRaw verifies that session_send against a
// PTY session uses the time-based SendRaw path and returns OK.
func TestSessionSend_PTY_RoutesToSendRaw(t *testing.T) {
	deps := newPTYDeps(t)

	// Open a PTY session.
	startArgs := mustJSON(map[string]any{
		"server":       "myserver",
		"pty":          true,
		"init_wait_ms": 100,
	})
	tCtx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	startResp := handleSessionStart(tCtx, deps, startArgs)
	if !startResp.OK {
		t.Fatalf("session_start: %+v", startResp.Error)
	}
	raw, _ := json.Marshal(startResp.Data)
	var out sessionStartOutput
	_ = json.Unmarshal(raw, &out)

	// Send a command — PTY path uses SendRaw (time-based), no sentinel.
	sendCtx, sc := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer sc()
	sendResp := handleSessionSend(sendCtx, deps, mustJSON(map[string]any{
		"session_id": out.SessionID,
		"command":    "echo hi",
		"timeout_ms": 100,
	}))
	if !sendResp.OK {
		t.Fatalf("session_send (PTY): %+v", sendResp.Error)
	}
}

// TestSessionSend_PTY_StripANSI verifies strip_ansi removes ANSI escape
// sequences from PTY output.
func TestSessionSend_PTY_StripANSI(t *testing.T) {
	ansi := "\x1b[1;32mhello\x1b[0m world"
	clean := stripANSICodes(ansi)
	if strings.Contains(clean, "\x1b") {
		t.Errorf("stripANSICodes left ANSI codes: %q", clean)
	}
	if !strings.Contains(clean, "hello") || !strings.Contains(clean, "world") {
		t.Errorf("stripANSICodes removed non-ANSI content: %q", clean)
	}
}
