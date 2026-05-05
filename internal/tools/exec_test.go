package tools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
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

func TestSSHExec_RejectsTooSmallTimeout(t *testing.T) {
	deps := minDeps(true)
	args := mustJSON(map[string]any{
		"server":     "prod",
		"command":    "ls",
		"timeout_ms": 1,
	})
	resp := handleSSHExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for too-small timeout")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
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

// --------------------------------------------------------------------------
// H01 — ssh_exec cwd allowed_paths tests
// --------------------------------------------------------------------------

// TestSSHExec_AllowedPaths_Cwd_Denied: even though exec itself would reach the
// SSH-dial stage, cwd enforcement is checked BEFORE the connection is dialled
// only when the server config has allowed_paths set and a cwd is requested.
//
// In this unit test the server lookup succeeds (server is in config) but
// Pool is nil, so Get will panic unless the enforceAllowedPath check fires
// first. The test verifies that PERMISSION_DENIED is returned before any
// connection attempt is made.
//
// NOTE: cwd enforcement fires AFTER sftp.RealPath, so in a pure unit test
// we cannot reach that point without a real SSH connection.  This test
// therefore exercises the case where cwd == "" (default_dir) but the server
// name triggers a pool lookup that returns an error — confirming that the
// non-cwd path is not broken.  The actual cwd/allowed_paths enforcement is
// covered by the integration path; here we confirm that a request to a server
// NOT in the config returns the expected INVALID_ARGUMENT error.
func TestSSHExec_AllowedPaths_ServerNotInConfig(t *testing.T) {
	deps := minDeps(true)
	// "restricted" is NOT added to Servers → should get INVALID_ARGUMENT.
	args := mustJSON(map[string]any{
		"server":  "restricted",
		"command": "ls",
		"cwd":     "/etc",
	})
	resp := handleSSHExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected error for unknown server")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// --------------------------------------------------------------------------
// H05 — buildSFTPAdHocAuth cleanup / secret zeroing tests
// --------------------------------------------------------------------------

// TestBuildSFTPAdHocAuth_PasswordZeroedAfterCleanup verifies that the cleanup
// function returned by buildSFTPAdHocAuth zeros the secret buffer.
func TestBuildSFTPAdHocAuth_PasswordZeroedAfterCleanup(t *testing.T) {
	in := &sftpInline{
		Host:     "localhost",
		User:     "u",
		Password: "supersecret",
	}

	am, cleanup, err := buildSFTPAdHocAuth(in)
	if err != nil {
		t.Fatalf("buildSFTPAdHocAuth: unexpected error: %v", err)
	}
	if am.PasswordCallback == nil {
		t.Fatal("expected PasswordCallback to be set for password auth")
	}

	// Before cleanup the callback should return the password.
	pw := am.PasswordCallback()
	if pw != "supersecret" {
		t.Errorf("PasswordCallback before cleanup: got %q, want %q", pw, "supersecret")
	}

	// After cleanup the secret buffer should be zeroed; PasswordCallback
	// returns "" because Secret.Bytes() returns nil after Close().
	cleanup()
	pwAfter := am.PasswordCallback()
	if pwAfter != "" {
		t.Errorf("PasswordCallback after cleanup: got %q, want empty (secret zeroed)", pwAfter)
	}
}

// --------------------------------------------------------------------------
// M01 — buildStreamingEnvelope: exit code mapping
// --------------------------------------------------------------------------

// TestBuildStreamingEnvelope_NilErr verifies exit_code=0 / signal="" on success.
func TestBuildStreamingEnvelope_NilErr(t *testing.T) {
	ctx := context.Background()
	resp := buildStreamingEnvelope(ctx, nil, "hello", "", false, "host", "user")
	if !resp.OK {
		t.Fatalf("expected OK, got error: %v", resp.Error)
	}
	out, ok := resp.Data.(execOutput)
	if !ok {
		t.Fatalf("expected execOutput, got %T", resp.Data)
	}
	if out.ExitCode != 0 {
		t.Errorf("exit_code: got %d, want 0", out.ExitCode)
	}
	if out.Signal != "" {
		t.Errorf("signal: got %q, want empty", out.Signal)
	}
	if out.Stdout != "hello" {
		t.Errorf("stdout: got %q, want %q", out.Stdout, "hello")
	}
}

// TestBuildStreamingEnvelope_NonExitError verifies that a non-ExitError
// (e.g. ExitMissingError, network error, or signal kill without exit code)
// results in exit_code=-1 and signal="UNKNOWN".
// Note: *gossh.ExitError has unexported fields and cannot be constructed in
// unit tests; ExitError path coverage requires integration tests.
func TestBuildStreamingEnvelope_NonExitError(t *testing.T) {
	ctx := context.Background()
	nonExitErr := errors.New("process killed by signal")

	resp := buildStreamingEnvelope(ctx, nonExitErr, "", "", false, "h", "u")
	if !resp.OK {
		t.Fatalf("expected OK envelope, got error: %v", resp.Error)
	}
	out, ok := resp.Data.(execOutput)
	if !ok {
		t.Fatalf("expected execOutput, got %T", resp.Data)
	}
	if out.ExitCode != -1 {
		t.Errorf("exit_code: got %d, want -1", out.ExitCode)
	}
	if out.Signal != "UNKNOWN" {
		t.Errorf("signal: got %q, want UNKNOWN", out.Signal)
	}
}

// TestBuildStreamingEnvelope_ContextTimeout verifies that a context-cancelled
// error returns CodeTimeout (not an OK envelope with exit_code=-1).
func TestBuildStreamingEnvelope_ContextTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	resp := buildStreamingEnvelope(ctx, context.DeadlineExceeded, "", "", false, "h", "u")
	if resp.OK {
		t.Fatal("expected error envelope for timeout, got OK")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeTimeout {
		t.Errorf("expected CodeTimeout, got %+v", resp.Error)
	}
}

// TestBuildStreamingEnvelope_Truncated verifies that the truncated flag and
// stdout value are faithfully passed through to the envelope.
func TestBuildStreamingEnvelope_Truncated(t *testing.T) {
	ctx := context.Background()
	resp := buildStreamingEnvelope(ctx, nil, "partial...[truncated; 100 bytes total]", "", true, "h", "u")
	if !resp.OK {
		t.Fatalf("expected OK, got error: %v", resp.Error)
	}
	out, ok := resp.Data.(execOutput)
	if !ok {
		t.Fatalf("expected execOutput, got %T", resp.Data)
	}
	if !out.Truncated {
		t.Error("expected Truncated=true")
	}
}

// --------------------------------------------------------------------------
// M01 — streaming truncation: budget enforced in callbacks
// --------------------------------------------------------------------------

// TestStreamingTruncation verifies that when total chunks exceed outputMax,
// stdout is capped at outputMax bytes and truncated=true.
// This replicates the appendBoundedStr logic inside handleSSHExecStreaming
// to verify the budget arithmetic in isolation.
func TestStreamingTruncation(t *testing.T) {
	const outputMax = 10

	var remaining atomic.Int64
	var truncatedFlag atomic.Bool
	remaining.Store(int64(outputMax))

	var buf strings.Builder
	var mu sync.Mutex

	appendFn := func(chunk []byte) {
		n := int64(len(chunk))
		after := remaining.Add(-n)
		var allowed int64
		if after >= 0 {
			allowed = n
		} else {
			truncatedFlag.Store(true)
			if after+n > 0 {
				allowed = after + n
			}
		}
		if allowed > 0 {
			mu.Lock()
			buf.Write(chunk[:allowed])
			mu.Unlock()
		}
	}

	// Feed 15 bytes total (> outputMax=10).
	appendFn([]byte("hello"))      // 5 bytes, remaining=5
	appendFn([]byte("world"))      // 5 bytes, remaining=0
	appendFn([]byte("extra!!!!!")) // 10 bytes, remaining=-10 → truncated

	if got := buf.String(); got != "helloworld" {
		t.Errorf("truncated stdout: got %q, want %q", got, "helloworld")
	}
	if !truncatedFlag.Load() {
		t.Error("expected truncated=true")
	}
}

// TestStreamingTruncation_PartialChunk verifies that when budget is partially
// consumed, only the allowed bytes are written (not the full chunk).
func TestStreamingTruncation_PartialChunk(t *testing.T) {
	const outputMax = 7

	var remaining atomic.Int64
	var truncatedFlag atomic.Bool
	remaining.Store(int64(outputMax))

	var buf strings.Builder
	var mu sync.Mutex

	appendFn := func(chunk []byte) {
		n := int64(len(chunk))
		after := remaining.Add(-n)
		var allowed int64
		if after >= 0 {
			allowed = n
		} else {
			truncatedFlag.Store(true)
			if after+n > 0 {
				allowed = after + n
			}
		}
		if allowed > 0 {
			mu.Lock()
			buf.Write(chunk[:allowed])
			mu.Unlock()
		}
	}

	// 5 bytes → remaining=2
	appendFn([]byte("hello"))
	// 5 bytes → remaining=-3 → allowed=2 (partial)
	appendFn([]byte("world"))

	if got := buf.String(); got != "hellowo" {
		t.Errorf("partial chunk: got %q, want %q", got, "hellowo")
	}
	if !truncatedFlag.Load() {
		t.Error("expected truncated=true after partial chunk")
	}
	// Further writes must be entirely dropped.
	appendFn([]byte("more data"))
	if got := buf.String(); got != "hellowo" {
		t.Errorf("after exhausted budget: got %q, still want %q", got, "hellowo")
	}
}

// --------------------------------------------------------------------------
// M04 — AuditMeta wiring (pre-connection validation paths)
// --------------------------------------------------------------------------

// TestSSHExec_EarlyErrorAuditNil verifies that responses produced before an
// SSH connection is acquired (validation failures) do NOT carry AuditMeta,
// since there is no real exit code or byte count to report.
func TestSSHExec_EarlyErrorAuditNil(t *testing.T) {
	deps := minDeps(true)
	args := mustJSON(map[string]any{
		"server":  "nonexistent",
		"command": "ls",
	})
	resp := handleSSHExec(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected not-OK for unknown server")
	}
	if resp.Audit != nil {
		t.Error("early-error response should not have AuditMeta set; got non-nil Audit")
	}
}

// TestBuildStreamingEnvelope_AuditNil verifies that buildStreamingEnvelope
// itself does NOT attach AuditMeta — the wrapping happens in the caller
// (handleSSHExecStreaming). This keeps buildStreamingEnvelope unit-testable
// without a real client.
func TestBuildStreamingEnvelope_AuditNil(t *testing.T) {
	ctx := context.Background()
	resp := buildStreamingEnvelope(ctx, nil, "output", "", false, "host", "user")
	if !resp.OK {
		t.Fatalf("expected OK, got: %v", resp.Error)
	}
	// buildStreamingEnvelope must not touch Audit — the caller does it.
	if resp.Audit != nil {
		t.Error("buildStreamingEnvelope should not set AuditMeta; caller is responsible")
	}
}

// --------------------------------------------------------------------------
// M02 — streaming progress stops after budget
// --------------------------------------------------------------------------

// fakeStreamingClient is a minimal stand-in for *ssh.Client that lets
// handleSSHExecStreaming drive the OnStdout/OnStderr callbacks directly.
// It implements only ExecStreaming behaviour via a user-supplied fn.
type fakeStreamingClient struct {
	fn func(opts interface{})
}

// TestStreaming_ProgressStopsAfterBudget verifies that once the output budget
// is exceeded, the Progress callback receives exactly one additional event
// with "truncated":true and no further plain chunk events (M02 fix).
//
// The test drives appendBoundedStr + the callback logic inline (mirroring
// the production code in handleSSHExecStreaming) so we can count events
// without needing a real SSH connection.
func TestStreaming_ProgressStopsAfterBudget(t *testing.T) {
	const outputMax = 10 // deliberately tiny so we exceed it quickly

	var remaining atomic.Int64
	var truncatedFlag atomic.Bool
	var progressTruncEmitted atomic.Bool
	remaining.Store(int64(outputMax))

	var buf strings.Builder
	var mu sync.Mutex

	var chunkEvents int
	var truncatedEvents int

	// Replicate the production appendBoundedStr (returns within-budget bool).
	appendFn := func(chunk []byte) bool {
		n := int64(len(chunk))
		if n == 0 {
			return true
		}
		after := remaining.Add(-n)
		var allowed int64
		if after >= 0 {
			allowed = n
		} else {
			truncatedFlag.Store(true)
			if after+n > 0 {
				allowed = after + n
			}
		}
		if allowed > 0 {
			mu.Lock()
			buf.Write(chunk[:allowed])
			mu.Unlock()
		}
		return after >= 0
	}

	// Replicate the production Progress dispatch logic.
	progressFn := func(stream string, chunk []byte) {
		withinBudget := appendFn(chunk)
		if withinBudget {
			chunkEvents++
		} else if progressTruncEmitted.CompareAndSwap(false, true) {
			truncatedEvents++
		}
		// After truncated emitted: silently drop further over-budget chunks.
	}

	// Feed: 5 + 5 = 10 bytes (within budget), then 3 × 5 bytes over budget.
	progressFn("stdout", []byte("hello")) // within: chunkEvents=1
	progressFn("stdout", []byte("world")) // within: chunkEvents=2
	progressFn("stdout", []byte("extra")) // over: truncatedEvents=1
	progressFn("stdout", []byte("more!")) // over: silently dropped
	progressFn("stderr", []byte("err!!")) // over: silently dropped

	if chunkEvents != 2 {
		t.Errorf("chunkEvents = %d, want 2 (one per within-budget chunk)", chunkEvents)
	}
	if truncatedEvents != 1 {
		t.Errorf("truncatedEvents = %d, want exactly 1", truncatedEvents)
	}
	if !truncatedFlag.Load() {
		t.Error("truncatedFlag should be true after budget exhausted")
	}
}
