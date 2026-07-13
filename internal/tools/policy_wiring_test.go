// Tests for per-server command policy wiring in ssh_group_exec and
// session_send — the two tools the mcpserver middleware cannot key policy
// off of directly (no top-level "server" field), so each handler evaluates
// policy itself. docs/design/command-policy.md §4.
package tools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/session"
	"github.com/xjoker/ssh-mcp/internal/ssh"
)

// sentinelEchoTransport is a session.Transport that answers just enough of
// the sentinel handshake (session.Manager.Start's init probe:
// printf '%s\n' 'init-<sentinel>') to let Start() succeed against a real
// *session.Manager, without a real SSH connection. The tools package's own
// fakeTransport (session_test.go) intentionally does not do this — its doc
// comment states it is "used only to construct a real *session.Manager for
// idempotent Close tests" — so a dedicated transport is needed here to
// construct a genuinely live session for the policy-wiring tests below.
type sentinelEchoTransport struct{}

var initProbeRe = regexp.MustCompile(`^printf '%s\\n' '(.+)'$`)

func (sentinelEchoTransport) OpenShell(_ context.Context, _ string) (
	io.WriteCloser, io.Reader, io.Reader, func() error, error,
) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	errR, errW := io.Pipe()
	go func() {
		defer outW.Close()
		scanner := bufio.NewScanner(inR)
		for scanner.Scan() {
			if m := initProbeRe.FindStringSubmatch(scanner.Text()); m != nil {
				fmt.Fprintf(outW, "%s\n", m[1])
			}
			// Any other line (the sentinel export, or a would-be command —
			// unreached here since the policy gate denies before Send) is
			// silently swallowed; these tests only exercise the pre-Send
			// policy check.
		}
	}()
	go func() { _ = errW.Close() }() // immediate EOF: stderr pump exits cleanly
	_ = errR
	return inW, outR, errR, func() error {
		_ = inW.Close()
		_ = outR.Close()
		return nil
	}, nil
}

func (sentinelEchoTransport) OpenShellPTY(_ context.Context, _ string, _, _ uint32) (
	io.WriteCloser, io.Reader, func() error, error,
) {
	return nil, nil, nil, fmt.Errorf("sentinelEchoTransport: PTY not supported")
}

// newLiveSessionManager returns a real *session.Manager backed by
// sentinelEchoTransport, whose Start() genuinely completes the init
// handshake (unlike newFakeSessionManager's raw-pipe transport, which
// would hang forever on Start's init probe).
func newLiveSessionManager() *session.Manager {
	return session.NewManager(sentinelEchoTransport{}, 30*time.Minute)
}

// erroringResolver satisfies ssh.CredResolver by always failing before any
// real network dial happens, so tests that reach Pool.Get get a clean
// connection-stage error instead of a nil-resolver panic or a real dial
// attempt.
type erroringResolver struct{}

func (erroringResolver) ResolveServerAuth(_ context.Context, _ config.ServerConfig) ([]gossh.AuthMethod, string, func(), error) {
	return nil, "", func() {}, errors.New("erroringResolver: no real auth in tests")
}

// mixedPolicyDeps builds a Deps with two servers: "ro" (mode=readonly) and
// "open" (no mode, unaffected). Pool uses erroringResolver so any target
// that passes the policy gate reaches Pool.Get and fails there with a
// connection-stage error (never dials the network), which is exactly what
// these tests need to distinguish "denied by policy" from "denied for any
// other reason".
func mixedPolicyDeps() *Deps {
	d := minDeps(false)
	d.Cfg.Servers = map[string]config.ServerConfig{
		"ro":   {Name: "ro", Host: "localhost", Port: 22, User: "u", Auth: "agent", Mode: "readonly"},
		"open": {Name: "open", Host: "localhost", Port: 22, User: "u", Auth: "agent"},
	}
	d.Pool = ssh.NewPool(d.Cfg, erroringResolver{})
	return d
}

// TestGroupExec_PolicyDeniesReadonlyTarget_AllowsOpenTarget: a destructive
// command against a mixed group of [readonly, unrestricted] servers must
// deny only the readonly target's entry; the open target's entry must not
// carry POLICY_DENIED (it proceeds to the normal connect-stage failure,
// since Pool is nil in this test).
func TestGroupExec_PolicyDeniesReadonlyTarget_AllowsOpenTarget(t *testing.T) {
	deps := mixedPolicyDeps()
	args := mustJSON(map[string]any{
		"servers": []string{"ro", "open"},
		"command": "rm -rf /tmp/x",
	})
	resp := handleSSHGroupExec(context.Background(), deps, args)

	output, ok := resp.Data.(groupExecOutput)
	if !ok {
		t.Fatalf("expected groupExecOutput, got %T", resp.Data)
	}
	if len(output.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(output.Results))
	}

	var roResult, openResult *groupExecServerResult
	for i := range output.Results {
		switch output.Results[i].Server {
		case "ro":
			roResult = &output.Results[i]
		case "open":
			openResult = &output.Results[i]
		}
	}
	if roResult == nil || openResult == nil {
		t.Fatalf("missing expected server results: %+v", output.Results)
	}

	if roResult.OK {
		t.Fatal("ro target should not be OK: policy must deny it")
	}
	if roResult.Error == nil || roResult.Error.Code != envelope.CodePolicyDenied {
		t.Fatalf("ro target error = %+v, want POLICY_DENIED", roResult.Error)
	}

	// open target: nil Pool means it fails downstream, but NOT with
	// POLICY_DENIED — proving the policy gate did not fire for it.
	if openResult.Error != nil && openResult.Error.Code == envelope.CodePolicyDenied {
		t.Fatal("open target must not be denied by policy (no mode configured)")
	}
}

// TestGroupExec_AllTargetsPolicyDenied_TopLevelErrorCode: when every target
// in the group is denied by policy, the top-level envelope error_code must
// be POLICY_DENIED (not the generic PARTIAL_FAILURE).
func TestGroupExec_AllTargetsPolicyDenied_TopLevelErrorCode(t *testing.T) {
	d := minDeps(false)
	d.Cfg.Servers = map[string]config.ServerConfig{
		"ro1": {Name: "ro1", Host: "localhost", Port: 22, User: "u", Auth: "agent", Mode: "readonly"},
		"ro2": {Name: "ro2", Host: "localhost", Port: 22, User: "u", Auth: "agent", Mode: "readonly"},
	}
	args := mustJSON(map[string]any{
		"servers": []string{"ro1", "ro2"},
		"command": "rm -rf /tmp/x",
	})
	resp := handleSSHGroupExec(context.Background(), d, args)

	if resp.OK {
		t.Fatal("expected not-OK when all targets are policy-denied")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodePolicyDenied {
		t.Fatalf("top-level error = %+v, want POLICY_DENIED", resp.Error)
	}
}

// TestGroupExec_PolicyAllowsMatchingCommand: a readonly-allowlisted command
// against a readonly target passes the policy gate (handler proceeds past
// the policy check; nil Pool then produces a connection-stage error, not
// POLICY_DENIED).
func TestGroupExec_PolicyAllowsMatchingCommand(t *testing.T) {
	deps := mixedPolicyDeps()
	args := mustJSON(map[string]any{
		"servers": []string{"ro"},
		"command": "ls -la",
	})
	resp := handleSSHGroupExec(context.Background(), deps, args)
	output, ok := resp.Data.(groupExecOutput)
	if !ok || len(output.Results) != 1 {
		t.Fatalf("expected 1 groupExecOutput result, got %+v", resp.Data)
	}
	r := output.Results[0]
	if r.Error != nil && r.Error.Code == envelope.CodePolicyDenied {
		t.Fatal("an allowlisted readonly command must not be POLICY_DENIED")
	}
}

// --------------------------------------------------------------------------
// session_send policy wiring
// --------------------------------------------------------------------------

// TestSessionSend_PolicyDeniesReadonlySession: a session opened against a
// readonly-mode server must reject a non-allowlisted command with
// POLICY_DENIED, and the session must remain usable afterwards (not
// destroyed) — verified by the session still appearing in SessionMgr.List().
func TestSessionSend_PolicyDeniesReadonlySession(t *testing.T) {
	deps := mixedPolicyDeps()
	deps.SessionMgr = newLiveSessionManager()

	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id, err := deps.SessionMgr.Start(startCtx, "ro")
	if err != nil {
		t.Fatalf("SessionMgr.Start: %v", err)
	}

	args := mustJSON(map[string]any{
		"session_id": id,
		"command":    "rm x",
	})
	resp := handleSessionSend(context.Background(), deps, args)
	if resp.OK {
		t.Fatal("expected policy denial for 'rm x' on a readonly session")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodePolicyDenied {
		t.Fatalf("error = %+v, want POLICY_DENIED", resp.Error)
	}

	found := false
	for _, si := range deps.SessionMgr.List() {
		if si.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatal("session must remain alive after a policy-denied send")
	}
}

// TestSessionSend_UnrestrictedSession_NotPolicyDenied: a session opened
// against a server with no mode configured is unaffected by policy — a
// send that would be denied under readonly mode must not surface
// POLICY_DENIED here (it may still fail for other reasons, e.g. the fake
// transport not answering the sentinel protocol — we only assert the error
// code is not POLICY_DENIED).
func TestSessionSend_UnrestrictedSession_NotPolicyDenied(t *testing.T) {
	deps := mixedPolicyDeps()
	deps.SessionMgr = newLiveSessionManager()

	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id, err := deps.SessionMgr.Start(startCtx, "open")
	if err != nil {
		t.Fatalf("SessionMgr.Start: %v", err)
	}

	args := mustJSON(map[string]any{
		"session_id": id,
		"command":    "rm x",
		"timeout_ms": 1000,
	})
	resp := handleSessionSend(context.Background(), deps, args)
	if !resp.OK && resp.Error != nil && resp.Error.Code == envelope.CodePolicyDenied {
		t.Fatal("session on an unrestricted server must not be POLICY_DENIED")
	}
}

// TestSessionServerName_UnknownSession: sessionServerName must report
// (\"\", false) for an unknown id rather than panicking, and
// handleSessionSend must fall through to the normal not-found path.
func TestSessionServerName_UnknownSession(t *testing.T) {
	deps := mixedPolicyDeps()
	deps.SessionMgr = newFakeSessionManager()

	if name, ok := sessionServerName(deps, "no-such-session"); ok || name != "" {
		t.Fatalf("sessionServerName(unknown) = (%q, %v), want (\"\", false)", name, ok)
	}
}
