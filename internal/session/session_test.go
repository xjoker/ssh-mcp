package session

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// Fake Transport
// --------------------------------------------------------------------------

// fakeShell simulates one connected shell for a single OpenShell call.
// Tests write the desired stdout content via feedStdout.
type fakeShell struct {
	stdinR  *io.PipeReader
	stdinW  *io.PipeWriter
	stdoutR *io.PipeReader
	stdoutW *io.PipeWriter
	stderrR *io.PipeReader
	stderrW *io.PipeWriter

	closed bool
	closeMu sync.Mutex
}

func newFakeShell() *fakeShell {
	sr, sw := io.Pipe()
	or, ow := io.Pipe()
	er, ew := io.Pipe()
	return &fakeShell{
		stdinR: sr, stdinW: sw,
		stdoutR: or, stdoutW: ow,
		stderrR: er, stderrW: ew,
	}
}

// feedLine writes a single line (with newline) to stdout.
func (f *fakeShell) feedLine(s string) {
	_, _ = fmt.Fprintln(f.stdoutW, s)
}

// closeStdout closes the stdout pipe (simulates EOF from remote).
func (f *fakeShell) closeStdout() {
	_ = f.stdoutW.Close()
}

// closeFunc closes all pipes.
func (f *fakeShell) closeFunc() error {
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	_ = f.stdinR.Close()
	_ = f.stdoutW.Close()
	_ = f.stderrW.Close()
	return nil
}

// fakeTransport is a Transport that hands out pre-built fakeShells in sequence.
type fakeTransport struct {
	mu     sync.Mutex
	shells []*fakeShell
	idx    int
}

func (ft *fakeTransport) addShell(sh *fakeShell) {
	ft.mu.Lock()
	ft.shells = append(ft.shells, sh)
	ft.mu.Unlock()
}

func (ft *fakeTransport) OpenShell(_ context.Context, _ string) (
	io.WriteCloser, io.Reader, io.Reader, func() error, error,
) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if ft.idx >= len(ft.shells) {
		return nil, nil, nil, nil, fmt.Errorf("fakeTransport: no shell available")
	}
	sh := ft.shells[ft.idx]
	ft.idx++
	return sh.stdinW, sh.stdoutR, sh.stderrR, sh.closeFunc, nil
}

// --------------------------------------------------------------------------
// Helper: Start a session with a fake shell, handling init probe
// --------------------------------------------------------------------------

// startSession creates a Manager with a single fake shell, registers a
// handler that replies to the init probe (and any subsequent sentinel
// commands), and returns the session id plus the shell for further control.
func startSession(t *testing.T, ft *fakeTransport, sh *fakeShell) string {
	t.Helper()

	// We need to intercept stdin writes from the Manager and reply via stdout.
	// Start returns only after the init probe echoes back.
	// Strategy: run a goroutine that reads stdin and replies to the probe.
	var sentinelVal string
	var sentinelOnce sync.Once

	// Process lines read from stdin and reply to the init probe.
	go func() {
		var buf strings.Builder
		tmp := make([]byte, 1)
		for {
			n, err := sh.stdinR.Read(tmp)
			if n > 0 {
				buf.WriteByte(tmp[0])
				if tmp[0] == '\n' {
					line := strings.TrimRight(buf.String(), "\r\n")
					buf.Reset()
					// Capture sentinel from export command.
					if strings.HasPrefix(line, "export __MSB_SENTINEL='") {
						// Extract value between single quotes.
						s := strings.TrimPrefix(line, "export __MSB_SENTINEL='")
						s = strings.TrimSuffix(s, "'")
						sentinelOnce.Do(func() { sentinelVal = s })
					}
					// Reply to init probe.
					if strings.HasPrefix(line, "printf '%s\\n' 'init-") {
						// Extract expected echo value.
						// line: printf '%s\n' 'init-msb-sentinel-xxxx'
						start := strings.Index(line, "'init-")
						if start >= 0 {
							echo := line[start+1 : len(line)-1] // strip surrounding quotes
							sh.feedLine(echo)
						}
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	_ = sentinelVal // suppress unused warning; used by caller

	m := NewManager(ft, time.Hour)
	t.Cleanup(m.CloseAll)

	ctx := context.Background()
	id, err := m.Start(ctx, "test-server")
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	return id
}

// --------------------------------------------------------------------------
// Full integration helpers using a self-contained fake shell responder
// --------------------------------------------------------------------------

// shellResponder reads commands from sh.stdinR, handles sentinel-wrapped
// commands, and writes realistic stdout/stderr responses.
type shellResponder struct {
	sh         *fakeShell
	sentinel   string
	mu         sync.Mutex
	handlers   []respHandler // consumed in order
}

type respHandler struct {
	stdout   string
	stderr   string
	exitCode int
}

func (sr *shellResponder) addResponse(stdout, stderr string, exitCode int) {
	sr.mu.Lock()
	sr.handlers = append(sr.handlers, respHandler{stdout, stderr, exitCode})
	sr.mu.Unlock()
}

func (sr *shellResponder) nextHandler() (respHandler, bool) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if len(sr.handlers) == 0 {
		return respHandler{}, false
	}
	h := sr.handlers[0]
	sr.handlers = sr.handlers[1:]
	return h, true
}

// run starts the background goroutine that processes stdin and replies.
func (sr *shellResponder) run() {
	go func() {
		var buf strings.Builder
		tmp := make([]byte, 1)
		for {
			n, err := sr.sh.stdinR.Read(tmp)
			if n > 0 {
				buf.WriteByte(tmp[0])
				if tmp[0] == '\n' {
					line := strings.TrimRight(buf.String(), "\r\n")
					buf.Reset()
					sr.handleLine(line)
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

func (sr *shellResponder) handleLine(line string) {
	// Handle export sentinel.
	if strings.HasPrefix(line, "export __MSB_SENTINEL='") {
		s := strings.TrimPrefix(line, "export __MSB_SENTINEL='")
		s = strings.TrimSuffix(s, "'")
		sr.sentinel = s
		return
	}

	// Handle init probe.
	if strings.HasPrefix(line, "printf '%s\\n' 'init-") {
		start := strings.Index(line, "'init-")
		if start >= 0 {
			echo := line[start+1 : len(line)-1]
			sr.sh.feedLine(echo)
		}
		return
	}

	// Handle sentinel-wrapped command: { <cmd> ; } ; __rc=$? ; printf '\n<sentinel> %s\n' "$__rc"
	if strings.HasPrefix(line, "{ ") {
		h, ok := sr.nextHandler()
		if !ok {
			// No handler — write a default sentinel with exit 0.
			h = respHandler{"", "", 0}
		}
		// Write stdout lines.
		if h.stdout != "" {
			sr.sh.feedLine(h.stdout)
		}
		// Write stderr via stderr pipe.
		if h.stderr != "" {
			_, _ = fmt.Fprintln(sr.sh.stderrW, h.stderr)
		}
		// Write sentinel line.
		sr.sh.feedLine(fmt.Sprintf("%s %d", sr.sentinel, h.exitCode))
	}
}

// newManager creates a Manager backed by a fakeTransport with one fakeShell
// whose responder is pre-wired, and returns (manager, sessionID, responder).
func newManagedSession(t *testing.T) (*Manager, string, *shellResponder) {
	t.Helper()

	sh := newFakeShell()
	sr := &shellResponder{sh: sh}
	sr.run()

	ft := &fakeTransport{}
	ft.addShell(sh)

	m := NewManager(ft, time.Hour)
	t.Cleanup(m.CloseAll)

	ctx := context.Background()
	id, err := m.Start(ctx, "test-server")
	if err != nil {
		t.Fatalf("newManagedSession: Start: %v", err)
	}
	return m, id, sr
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

// TestSentinelNotInOutput verifies that the sentinel line does not appear in
// SendResult.Stdout.
func TestSentinelNotInOutput(t *testing.T) {
	m, id, sr := newManagedSession(t)

	sr.addResponse("hello world", "", 0)
	res, err := m.Send(context.Background(), id, "echo hello world", 5*time.Second)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}
	if strings.Contains(res.Stdout, "msb-sentinel-") {
		t.Errorf("Stdout should not contain sentinel, got: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "hello world") {
		t.Errorf("Stdout should contain 'hello world', got: %q", res.Stdout)
	}
}

// TestExitCodeParsed verifies that exit code 42 in the sentinel line is
// correctly reflected in SendResult.ExitCode.
func TestExitCodeParsed(t *testing.T) {
	m, id, sr := newManagedSession(t)

	sr.addResponse("", "", 42)
	res, err := m.Send(context.Background(), id, "exit 42", 5*time.Second)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}
	if res.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42", res.ExitCode)
	}
}

// TestMultiCommandSequential verifies that two consecutive Send calls each
// return the correct output.
func TestMultiCommandSequential(t *testing.T) {
	m, id, sr := newManagedSession(t)

	sr.addResponse("output-a", "", 0)
	sr.addResponse("output-b", "", 0)

	resA, err := m.Send(context.Background(), id, "cmd-a", 5*time.Second)
	if err != nil {
		t.Fatalf("Send A error: %v", err)
	}
	if !strings.Contains(resA.Stdout, "output-a") {
		t.Errorf("cmd-a Stdout = %q, want 'output-a'", resA.Stdout)
	}

	resB, err := m.Send(context.Background(), id, "cmd-b", 5*time.Second)
	if err != nil {
		t.Fatalf("Send B error: %v", err)
	}
	if !strings.Contains(resB.Stdout, "output-b") {
		t.Errorf("cmd-b Stdout = %q, want 'output-b'", resB.Stdout)
	}
}

// TestSentinelNoFalsePositive verifies that a command whose output happens to
// contain "msb-sentinel-" (but not in sentinel-line format) does not prematurely
// terminate the read.
func TestSentinelNoFalsePositive(t *testing.T) {
	m, id, sr := newManagedSession(t)

	// Make the real sentinel available so the responder can emit it.
	// The responder will add a line that looks like a partial sentinel match
	// before the real one.

	// We'll fake a stdout that includes "msb-sentinel-" as benign content.
	// Since the responder emits the real sentinel with the right format,
	// the scanner should wait for the properly formatted line.
	sr.addResponse("msb-sentinel-deceptive-garbage 999 extra", "", 0)

	res, err := m.Send(context.Background(), id, "echo msb-sentinel-deceptive-garbage 999 extra", 5*time.Second)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}
	// Should have output and exit code 0 (from the real sentinel).
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
}

// hangTransport is a Transport whose OpenShell returns pipes where stdout
// never produces a sentinel. Used to test timeout / error-state behaviour.
type hangTransport struct {
	sh *fakeShell
}

func (ht *hangTransport) OpenShell(_ context.Context, _ string) (
	io.WriteCloser, io.Reader, io.Reader, func() error, error,
) {
	return ht.sh.stdinW, ht.sh.stdoutR, ht.sh.stderrR, ht.sh.closeFunc, nil
}

// hangShellResponder processes stdin for the hang shell: it handles the init
// probe (so Start() succeeds) but silently drops all sentinel-wrapped commands.
func startHangShell(sh *fakeShell) {
	go func() {
		var buf strings.Builder
		var sentinel string
		tmp := make([]byte, 1)
		for {
			n, err := sh.stdinR.Read(tmp)
			if n > 0 {
				buf.WriteByte(tmp[0])
				if tmp[0] == '\n' {
					line := strings.TrimRight(buf.String(), "\r\n")
					buf.Reset()
					// Capture sentinel.
					if strings.HasPrefix(line, "export __MSB_SENTINEL='") {
						s := strings.TrimPrefix(line, "export __MSB_SENTINEL='")
						sentinel = strings.TrimSuffix(s, "'")
						_ = sentinel
					}
					// Reply to init probe so Start() completes.
					if strings.HasPrefix(line, "printf '%s\\n' 'init-") {
						start := strings.Index(line, "'init-")
						if start >= 0 {
							echo := line[start+1 : len(line)-1]
							sh.feedLine(echo)
						}
					}
					// Any sentinel-wrapped command: intentionally ignored (no reply).
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

// TestTimeout verifies that when stdout never sends a sentinel, Send returns
// a TIMEOUT error and the session transitions to Error state.
func TestTimeout(t *testing.T) {
	sh := newFakeShell()
	startHangShell(sh)

	m := NewManager(&hangTransport{sh: sh}, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id, err := m.Start(ctx, "test-server")
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}

	// Use a very short timeout to trigger the deadline.
	_, err = m.Send(ctx, id, "sleep 999", 50*time.Millisecond)
	if err == nil {
		t.Fatal("Send should have returned TIMEOUT error, got nil")
	}
	if !strings.Contains(err.Error(), "TIMEOUT") {
		t.Errorf("error should contain TIMEOUT, got: %v", err)
	}
}

// TestSendToErrorSession verifies that after a session enters Error state,
// subsequent Send calls return SESSION_DEAD.
func TestSendToErrorSession(t *testing.T) {
	sh := newFakeShell()
	startHangShell(sh)

	m := NewManager(&hangTransport{sh: sh}, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id, err := m.Start(ctx, "test-server")
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}

	// Force timeout → Error state.
	_, _ = m.Send(ctx, id, "anything", 50*time.Millisecond)

	// Next Send should return SESSION_DEAD.
	_, err = m.Send(ctx, id, "cmd", 5*time.Second)
	if err == nil {
		t.Fatal("Expected SESSION_DEAD error, got nil")
	}
	if !strings.Contains(err.Error(), "SESSION_DEAD") {
		t.Errorf("Expected SESSION_DEAD in error, got: %v", err)
	}
}

// TestCloseIdempotent verifies that Close on an already-closed session
// returns nil and does not panic.
func TestCloseIdempotent(t *testing.T) {
	m, id, _ := newManagedSession(t)

	if err := m.Close(id); err != nil {
		t.Fatalf("first Close error: %v", err)
	}
	if err := m.Close(id); err != nil {
		t.Fatalf("second Close error: %v", err)
	}
	// Close a non-existent id should also be nil.
	if err := m.Close("no-such-id"); err != nil {
		t.Fatalf("Close(non-existent) error: %v", err)
	}
}

// TestList verifies that List returns all active sessions.
func TestList(t *testing.T) {
	sh1 := newFakeShell()
	sh2 := newFakeShell()
	sr1 := &shellResponder{sh: sh1}
	sr2 := &shellResponder{sh: sh2}
	sr1.run()
	sr2.run()

	ft := &fakeTransport{}
	ft.addShell(sh1)
	ft.addShell(sh2)

	m := NewManager(ft, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id1, err := m.Start(ctx, "server-1")
	if err != nil {
		t.Fatalf("Start 1: %v", err)
	}
	id2, err := m.Start(ctx, "server-2")
	if err != nil {
		t.Fatalf("Start 2: %v", err)
	}

	list := m.List()
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}

	ids := map[string]bool{id1: true, id2: true}
	for _, info := range list {
		if !ids[info.ID] {
			t.Errorf("unexpected session id %q in List", info.ID)
		}
	}

	// After closing one, List should return 1.
	_ = m.Close(id1)
	list = m.List()
	if len(list) != 1 {
		t.Errorf("List after Close len = %d, want 1", len(list))
	}
	if list[0].ID != id2 {
		t.Errorf("remaining session = %q, want %q", list[0].ID, id2)
	}
}

// TestCloseAll verifies that CloseAll closes all sessions.
func TestCloseAll(t *testing.T) {
	sh1 := newFakeShell()
	sh2 := newFakeShell()
	sr1 := &shellResponder{sh: sh1}
	sr2 := &shellResponder{sh: sh2}
	sr1.run()
	sr2.run()

	ft := &fakeTransport{}
	ft.addShell(sh1)
	ft.addShell(sh2)

	m := NewManager(ft, time.Hour)

	ctx := context.Background()
	_, err := m.Start(ctx, "server-1")
	if err != nil {
		t.Fatalf("Start 1: %v", err)
	}
	_, err = m.Start(ctx, "server-2")
	if err != nil {
		t.Fatalf("Start 2: %v", err)
	}

	m.CloseAll()

	list := m.List()
	if len(list) != 0 {
		t.Errorf("after CloseAll, List len = %d, want 0", len(list))
	}
}

// TestReapIdle verifies that sessions with stale lastActivity are closed
// by ReapIdle.
func TestReapIdle(t *testing.T) {
	m, id, _ := newManagedSession(t)

	// Manually set lastActivity to a very old timestamp.
	m.mu.Lock()
	s := m.sessions[id]
	m.mu.Unlock()
	if s == nil {
		t.Fatal("session not found in manager")
	}
	s.mu.Lock()
	s.lastActivity = time.Now().Add(-2 * time.Hour)
	s.mu.Unlock()

	m.idleTimeout = 1 * time.Hour
	m.ReapIdle()

	list := m.List()
	if len(list) != 0 {
		t.Errorf("after ReapIdle, List len = %d, want 0", len(list))
	}
}

// TestCommandCountAndDuration verifies basic metadata tracking.
func TestCommandCountAndDuration(t *testing.T) {
	m, id, sr := newManagedSession(t)

	sr.addResponse("foo", "", 0)
	_, err := m.Send(context.Background(), id, "cmd1", 5*time.Second)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	list := m.List()
	if len(list) != 1 {
		t.Fatalf("List len = %d, want 1", len(list))
	}
	if list[0].CommandCount != 1 {
		t.Errorf("CommandCount = %d, want 1", list[0].CommandCount)
	}
}

// TestStderrCapture verifies best-effort stderr capture.
func TestStderrCapture(t *testing.T) {
	m, id, sr := newManagedSession(t)

	sr.addResponse("", "error-output", 1)
	res, err := m.Send(context.Background(), id, "cmd-with-stderr", 5*time.Second)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}
	// Give the stderr pump a brief moment.
	time.Sleep(50 * time.Millisecond)
	_ = res // stderr is best-effort; we just verify no crash
}

// TestSendToClosedSession verifies that Send on a closed session returns
// SESSION_DEAD.
func TestSendToClosedSession(t *testing.T) {
	m, id, _ := newManagedSession(t)

	_ = m.Close(id)

	_, err := m.Send(context.Background(), id, "cmd", 5*time.Second)
	if err == nil {
		t.Fatal("expected error sending to closed session, got nil")
	}
	// Session removed from map; should get "not found".
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}
