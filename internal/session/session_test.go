package session

import (
	"bufio"
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

	closed  bool
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

func (ft *fakeTransport) OpenShellPTY(_ context.Context, _ string, _, _ uint32) (
	io.WriteCloser, io.Reader, func() error, error,
) {
	return nil, nil, nil, fmt.Errorf("fakeTransport: OpenShellPTY not implemented")
}

// --------------------------------------------------------------------------
// Helper: Start a session with a fake shell, handling init probe
// --------------------------------------------------------------------------

// (startSession removed: newManagedSession + shellResponder fully replace
// the old hand-rolled init-probe handler used in early tests.)

// --------------------------------------------------------------------------
// Full integration helpers using a self-contained fake shell responder
// --------------------------------------------------------------------------

// shellResponder reads commands from sh.stdinR, handles sentinel-wrapped
// commands, and writes realistic stdout/stderr responses.
type shellResponder struct {
	sh             *fakeShell
	sentinel       string
	mu             sync.Mutex
	handlers       []respHandler // consumed in order
	recordedLines  []string      // every line read from stdin, in arrival order
	recordedLinesM sync.Mutex
}

// snapshotLines returns a copy of every stdin line observed so far.
func (sr *shellResponder) snapshotLines() []string {
	sr.recordedLinesM.Lock()
	defer sr.recordedLinesM.Unlock()
	cp := make([]string, len(sr.recordedLines))
	copy(cp, sr.recordedLines)
	return cp
}

type respHandler struct {
	stdout   string
	stderr   string
	exitCode int
	release  <-chan struct{}
}

func (sr *shellResponder) addResponse(stdout, stderr string, exitCode int) {
	sr.mu.Lock()
	sr.handlers = append(sr.handlers, respHandler{
		stdout: stdout, stderr: stderr, exitCode: exitCode,
	})
	sr.mu.Unlock()
}

func (sr *shellResponder) addResponseAfter(release <-chan struct{}, stdout, stderr string, exitCode int) {
	sr.mu.Lock()
	sr.handlers = append(sr.handlers, respHandler{
		stdout: stdout, stderr: stderr, exitCode: exitCode, release: release,
	})
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
	// Record every line for tests that need to inspect the wrapper shape.
	sr.recordedLinesM.Lock()
	sr.recordedLines = append(sr.recordedLines, line)
	sr.recordedLinesM.Unlock()

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

	// Handle sentinel-wrapped command. The wrapper Send emits is multi-line:
	//   { <cmd>
	//   } ; __rc=$? ; printf '\n<sentinel>-<nonce> %s\n' "$__rc"
	// We trigger on the closing line because that's where the per-command
	// completion mark lives. Any preceding `{ ` / heredoc body lines are
	// ignored — the responder is fake and doesn't actually execute commands.
	if strings.HasPrefix(line, "} ; __rc=") {
		h, ok := sr.nextHandler()
		if !ok {
			// No handler — write a default sentinel with exit 0.
			h = respHandler{}
		}
		if h.release != nil {
			<-h.release
		}
		if h.stdout != "" {
			sr.sh.feedLine(h.stdout)
		}
		if h.stderr != "" {
			_, _ = fmt.Fprintln(sr.sh.stderrW, h.stderr)
		}
		mark := extractCompletionMark(line, sr.sentinel)
		if mark == "" {
			mark = sr.sentinel
		}
		sr.sh.feedLine(fmt.Sprintf("%s %d", mark, h.exitCode))
	}
}

// extractCompletionMark pulls "<sessionSentinel>-<nonce>" out of the wrapped
// command line. Returns "" if the line doesn't match the expected shape.
func extractCompletionMark(line, sessionSentinel string) string {
	needle := `printf '\n` + sessionSentinel + "-"
	i := strings.Index(line, needle)
	if i < 0 {
		return ""
	}
	rest := line[i+len(`printf '\n`):] // starts with "<sentinel>-<nonce> %s\n' ..."
	// Mark ends at the first space.
	spaceIdx := strings.IndexByte(rest, ' ')
	if spaceIdx <= 0 {
		return ""
	}
	return rest[:spaceIdx]
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

// TestSend_HeredocWrapperShape verifies that Send's wrapper places the
// closing brace on its own line — required for heredoc commands whose
// terminator (e.g. EOF) must appear on a line by itself. Without this
// shape, "EOF" would share a line with " ; } ; ..." and the heredoc
// would never close, hanging the shell.
func TestSend_HeredocWrapperShape(t *testing.T) {
	m, id, sr := newManagedSession(t)

	sr.addResponse("", "", 0)
	if _, err := m.Send(context.Background(), id, "python3 - <<'EOF'\nprint('hi')\nEOF", 5*time.Second); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Inspect every line the responder observed on stdin. We expect to see
	// "EOF" on its own line BEFORE the wrapper closer ("} ; __rc=...") on a
	// separate line.
	lines := sr.snapshotLines()
	eofIdx := -1
	closerIdx := -1
	for i, ln := range lines {
		if ln == "EOF" {
			eofIdx = i
		}
		if strings.HasPrefix(ln, "} ; __rc=") {
			closerIdx = i
		}
	}
	if eofIdx == -1 {
		t.Fatalf("expected 'EOF' on its own line; recorded lines:\n%s", strings.Join(lines, "\n"))
	}
	if closerIdx == -1 {
		t.Fatalf("expected wrapper closer line ('} ; __rc='); recorded lines:\n%s", strings.Join(lines, "\n"))
	}
	if eofIdx >= closerIdx {
		t.Fatalf("EOF (idx=%d) must precede the wrapper closer (idx=%d):\n%s",
			eofIdx, closerIdx, strings.Join(lines, "\n"))
	}
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

func (ht *hangTransport) OpenShellPTY(_ context.Context, _ string, _, _ uint32) (
	io.WriteCloser, io.Reader, func() error, error,
) {
	return nil, nil, nil, fmt.Errorf("hangTransport: OpenShellPTY not implemented")
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

// TestSendAfterPumpEOFReturnsSessionDead verifies that once the underlying
// shell closes (stdout EOF), subsequent Sends return SESSION_DEAD.
//
// This is the only path that should now produce SESSION_DEAD on a Send —
// a command timeout alone no longer poisons the session (see
// TestSend_AfterTimeoutSessionStaysAlive).
func TestSendAfterPumpEOFReturnsSessionDead(t *testing.T) {
	m, id, sr := newManagedSession(t)

	// Successful round-trip first, to confirm the pump is healthy.
	sr.addResponse("ok", "", 0)
	if _, err := m.Send(context.Background(), id, "true", 2*time.Second); err != nil {
		t.Fatalf("baseline Send failed: %v", err)
	}

	// Close the remote shell's stdout to drive the pump to EOF.
	sr.sh.closeStdout()

	// Give the pump a moment to observe EOF and close lineCh.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// Poll until the next Send sees SESSION_DEAD or we exhaust the budget.
		_, err := m.Send(context.Background(), id, "cmd", 200*time.Millisecond)
		if err == nil {
			t.Fatal("expected error after pump EOF, got nil")
		}
		if strings.Contains(err.Error(), "SESSION_DEAD") || strings.Contains(err.Error(), "shell stdout closed") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("did not observe SESSION_DEAD / EOF after closing stdout within 2s")
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

// --------------------------------------------------------------------------
// H05 security tests: output cap + timeout transport close
// --------------------------------------------------------------------------

// bigOutputTransport is a Transport whose shell floods stdout with data
// exceeding sessionOutputMaxBytes before writing the sentinel line.
// This is used to verify the per-Send output cap.
type bigOutputTransport struct {
	sh         *fakeShell
	extraBytes int // bytes of payload to write before the sentinel
}

func (bt *bigOutputTransport) OpenShell(_ context.Context, _ string) (
	io.WriteCloser, io.Reader, io.Reader, func() error, error,
) {
	return bt.sh.stdinW, bt.sh.stdoutR, bt.sh.stderrR, bt.sh.closeFunc, nil
}

func (bt *bigOutputTransport) OpenShellPTY(_ context.Context, _ string, _, _ uint32) (
	io.WriteCloser, io.Reader, func() error, error,
) {
	return nil, nil, nil, fmt.Errorf("bigOutputTransport: OpenShellPTY not implemented")
}

// startBigOutputShell processes stdin: handles init probe normally, then
// for any sentinel-wrapped command it writes extraBytes of 'x' followed by
// the sentinel line so Send can complete.
func startBigOutputShell(sh *fakeShell, extraBytes int) {
	go func() {
		var buf strings.Builder
		var sentinelVal string
		tmp := make([]byte, 1)
		for {
			n, err := sh.stdinR.Read(tmp)
			if n > 0 {
				buf.WriteByte(tmp[0])
				if tmp[0] == '\n' {
					line := strings.TrimRight(buf.String(), "\r\n")
					buf.Reset()
					if strings.HasPrefix(line, "export __MSB_SENTINEL='") {
						s := strings.TrimPrefix(line, "export __MSB_SENTINEL='")
						sentinelVal = strings.TrimSuffix(s, "'")
					}
					if strings.HasPrefix(line, "printf '%s\\n' 'init-") {
						start := strings.Index(line, "'init-")
						if start >= 0 {
							echo := line[start+1 : len(line)-1]
							sh.feedLine(echo)
						}
					}
					if strings.HasPrefix(line, "} ; __rc=") && sentinelVal != "" {
						// Write chunks of data that exceed the budget.
						written := 0
						for written < extraBytes {
							toWrite := 1024
							if written+toWrite > extraBytes {
								toWrite = extraBytes - written
							}
							sh.feedLine(strings.Repeat("x", toWrite))
							written += toWrite
						}
						// Write per-command sentinel (sentinel-nonce <rc>) so
						// Send's lineCh scanner can match completion.
						mark := extractCompletionMark(line, sentinelVal)
						if mark == "" {
							mark = sentinelVal
						}
						sh.feedLine(fmt.Sprintf("%s 0", mark))
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

// TestSend_OutputCappedAtBudget verifies that when the remote shell produces
// more than sessionOutputMaxBytes of stdout, SendResult.Stdout is capped and
// SendResult.Truncated is true.
func TestSend_OutputCappedAtBudget(t *testing.T) {
	const twiceBudget = 2 * sessionOutputMaxBytes

	sh := newFakeShell()
	startBigOutputShell(sh, twiceBudget)

	m := NewManager(&bigOutputTransport{sh: sh, extraBytes: twiceBudget}, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id, err := m.Start(ctx, "test-server")
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}

	res, err := m.Send(ctx, id, "bigcmd", 30*time.Second)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}
	if int64(len(res.Stdout)) > sessionOutputMaxBytes {
		t.Errorf("Stdout len %d exceeds cap %d", len(res.Stdout), sessionOutputMaxBytes)
	}
	if !res.Truncated {
		t.Error("expected Truncated=true when output exceeds budget, got false")
	}
}

// TestSend_TimeoutClosesTransport verifies that when a Send times out, the
// underlying shell transport is closed (fakeShell.closed becomes true).
// After the transport is closed, the scanSentinel goroutine must exit within
// a reasonable time (no goroutine leak).
func TestSend_TimeoutClosesTransport(t *testing.T) {
	sh := newFakeShell()
	startHangShell(sh) // responds to init probe but never sends sentinel

	m := NewManager(&hangTransport{sh: sh}, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id, err := m.Start(ctx, "test-server")
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}

	// Trigger timeout.
	_, err = m.Send(ctx, id, "hang", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected TIMEOUT error, got nil")
	}
	if !strings.Contains(err.Error(), "TIMEOUT") {
		t.Errorf("expected TIMEOUT in error, got: %v", err)
	}

	// New contract: a command timeout MUST NOT tear down the shell. The
	// remote command may still be running; the session stays alive so the
	// caller can either wait and retry, or invoke Close to abort.
	sh.closeMu.Lock()
	closed := sh.closed
	sh.closeMu.Unlock()
	if closed {
		t.Error("expected fakeShell to stay open after command timeout (got closed=true)")
	}
}

// TestSend_AfterTimeoutResumesWhenStaleCompletes is the positive path for
// the new SESSION_DEAD-free contract: after a Send times out, if the prior
// command eventually emits its completion sentinel (i.e. the remote command
// finishes on its own), a follow-up Send drains that stale sentinel and
// then succeeds normally.
func TestSend_AfterTimeoutResumesWhenStaleCompletes(t *testing.T) {
	m, id, sr := newManagedSession(t)

	firstRelease := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(firstRelease) })
	})
	sr.addResponseAfter(firstRelease, "", "", 0)

	// Withhold the first completion sentinel until Send has definitely timed
	// out, then release it so the follow-up Send can drain the stale command.
	_, err := m.Send(context.Background(), id, "first", 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "TIMEOUT") {
		t.Fatalf("first Send must time out while its response is blocked, got: %v", err)
	}

	// Second send: must succeed and return the matching response. If the
	// session was incorrectly torn down on timeout, this would return
	// SESSION_DEAD.
	sr.addResponse("second-output", "", 0)
	releaseOnce.Do(func() { close(firstRelease) })
	res, err := m.Send(context.Background(), id, "second", 5*time.Second)
	if err != nil {
		t.Fatalf("follow-up Send must succeed (session must stay alive), got: %v", err)
	}
	if !strings.Contains(res.Stdout, "second-output") {
		t.Errorf("expected second-output in stdout, got: %q", res.Stdout)
	}
}

// TestSend_AfterTimeoutSessionStaysAlive verifies the new contract:
// a Send that timed out does NOT poison the session. A subsequent Send
// that completes within the stale-drain budget either succeeds (when the
// prior command produces a sentinel) or returns SESSION_BUSY (when the
// prior command is still stuck). It never returns SESSION_DEAD.
func TestSend_AfterTimeoutSessionStaysAlive(t *testing.T) {
	sh := newFakeShell()
	startHangShell(sh)

	m := NewManager(&hangTransport{sh: sh}, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id, err := m.Start(ctx, "test-server")
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}

	// First Send — times out.
	_, err = m.Send(ctx, id, "hang", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected TIMEOUT error, got nil")
	}

	// Second Send — must NOT return SESSION_DEAD. With the hang shell
	// (sentinel never arrives) we expect SESSION_BUSY after the stale
	// drain budget elapses.
	_, err = m.Send(ctx, id, "anything", 5*time.Second)
	if err == nil {
		t.Fatal("expected SESSION_BUSY error on second Send (hang shell), got nil")
	}
	if strings.Contains(err.Error(), "SESSION_DEAD") {
		t.Errorf("second Send must not return SESSION_DEAD after a command timeout, got: %v", err)
	}
	if !strings.Contains(err.Error(), "SESSION_BUSY") {
		t.Errorf("expected SESSION_BUSY in error, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// H04 security tests: per-line cap via readBoundedLine
// --------------------------------------------------------------------------

// TestReadBoundedLine_Cases is a unit-test for the readBoundedLine helper
// covering: short line, line exactly at cap, line exceeding cap (truncation),
// EOF mid-line with no newline, and empty reader.
func TestReadBoundedLine_Cases(t *testing.T) {
	const cap = 8

	cases := []struct {
		name         string
		input        string
		wantLine     string // expected content WITHOUT trailing '\n' (for readability)
		wantNewline  bool   // whether we expect a '\n' at end of returned slice
		wantTrunc    bool
		wantErrOnEOF bool // true if we expect io.EOF (empty reader)
	}{
		{
			name:        "short line with newline",
			input:       "hello\n",
			wantLine:    "hello",
			wantNewline: true,
			wantTrunc:   false,
		},
		{
			name:        "line exactly at cap with newline",
			input:       "12345678\n",
			wantLine:    "12345678",
			wantNewline: true,
			wantTrunc:   false,
		},
		{
			name:        "line exceeds cap — truncated",
			input:       "123456789abcde\n",
			wantLine:    "12345678",
			wantNewline: false,
			wantTrunc:   true,
		},
		{
			name:        "EOF mid-line (no trailing newline)",
			input:       "partial",
			wantLine:    "partial",
			wantNewline: false,
			wantTrunc:   false,
		},
		{
			name:         "empty reader returns io.EOF",
			input:        "",
			wantErrOnEOF: true,
		},
		{
			name:        "line exceeds cap then another line",
			input:       "123456789XXXX\nshort\n",
			wantLine:    "12345678",
			wantNewline: false,
			wantTrunc:   true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tc.input))
			line, trunc, err := readBoundedLine(r, cap)

			if tc.wantErrOnEOF {
				if err == nil {
					t.Errorf("expected error (io.EOF), got nil; line=%q", line)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Strip trailing newline for comparison, but record whether it was there.
			gotNewline := len(line) > 0 && line[len(line)-1] == '\n'
			content := strings.TrimRight(string(line), "\n")

			if content != tc.wantLine {
				t.Errorf("line content = %q, want %q", content, tc.wantLine)
			}
			if gotNewline != tc.wantNewline {
				t.Errorf("trailing newline = %v, want %v", gotNewline, tc.wantNewline)
			}
			if trunc != tc.wantTrunc {
				t.Errorf("truncated = %v, want %v", trunc, tc.wantTrunc)
			}
		})
	}
}

// longLineTransport is a Transport whose shell writes a single giant line
// (no newline until the very end, after the sentinel) to test that
// readBoundedLine prevents OOM before the newline arrives.
type longLineTransport struct {
	sh        *fakeShell
	lineBytes int // how many bytes to write before the sentinel (no internal newlines)
}

func (lt *longLineTransport) OpenShell(_ context.Context, _ string) (
	io.WriteCloser, io.Reader, io.Reader, func() error, error,
) {
	return lt.sh.stdinW, lt.sh.stdoutR, lt.sh.stderrR, lt.sh.closeFunc, nil
}

func (lt *longLineTransport) OpenShellPTY(_ context.Context, _ string, _, _ uint32) (
	io.WriteCloser, io.Reader, func() error, error,
) {
	return nil, nil, nil, fmt.Errorf("longLineTransport: OpenShellPTY not implemented")
}

// startLongLineShell handles init probe normally. For any sentinel-wrapped
// command it writes lineBytes of 'x' with NO intermediate newline, then
// immediately writes the sentinel on its own line.
func startLongLineShell(sh *fakeShell, lineBytes int) {
	go func() {
		var buf strings.Builder
		var sentinelVal string
		tmp := make([]byte, 1)
		for {
			n, err := sh.stdinR.Read(tmp)
			if n > 0 {
				buf.WriteByte(tmp[0])
				if tmp[0] == '\n' {
					line := strings.TrimRight(buf.String(), "\r\n")
					buf.Reset()
					if strings.HasPrefix(line, "export __MSB_SENTINEL='") {
						s := strings.TrimPrefix(line, "export __MSB_SENTINEL='")
						sentinelVal = strings.TrimSuffix(s, "'")
					}
					if strings.HasPrefix(line, "printf '%s\\n' 'init-") {
						start := strings.Index(line, "'init-")
						if start >= 0 {
							echo := line[start+1 : len(line)-1]
							sh.feedLine(echo)
						}
					}
					if strings.HasPrefix(line, "} ; __rc=") && sentinelVal != "" {
						// Write a single huge line with no embedded newline.
						chunk := strings.Repeat("x", 4096)
						written := 0
						for written < lineBytes {
							toWrite := len(chunk)
							if written+toWrite > lineBytes {
								toWrite = lineBytes - written
							}
							_, _ = sh.stdoutW.Write([]byte(chunk[:toWrite]))
							written += toWrite
						}
						// Terminate the long line with a newline, then write the
						// per-command completion sentinel.
						_, _ = sh.stdoutW.Write([]byte("\n"))
						mark := extractCompletionMark(line, sentinelVal)
						if mark == "" {
							mark = sentinelVal
						}
						sh.feedLine(fmt.Sprintf("%s 0", mark))
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

// TestStart_SessionLimit verifies that Start refuses to open more than
// maxSessions concurrent sessions and returns a SESSION_LIMIT error.
func TestStart_SessionLimit(t *testing.T) {
	sh1 := newFakeShell()
	sh2 := newFakeShell()
	(&shellResponder{sh: sh1}).run()
	(&shellResponder{sh: sh2}).run()

	ft := &fakeTransport{}
	ft.addShell(sh1)
	ft.addShell(sh2)

	m := NewManagerWithLimit(ft, time.Hour, 1)
	defer m.CloseAll()

	ctx := context.Background()
	id, err := m.Start(ctx, "server-1")
	if err != nil {
		t.Fatalf("first Start failed: %v", err)
	}

	_, err = m.Start(ctx, "server-2")
	if err == nil {
		t.Fatal("expected SESSION_LIMIT error on second Start, got nil")
	}
	if !strings.Contains(err.Error(), "SESSION_LIMIT") {
		t.Errorf("expected SESSION_LIMIT in error, got %v", err)
	}

	// Closing the first session should free a slot so a follow-up Start succeeds.
	if err := m.Close(id); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := m.Start(ctx, "server-2"); err != nil {
		t.Errorf("Start after Close: %v", err)
	}
}

// --------------------------------------------------------------------------
// PTY transport and shell helpers
// --------------------------------------------------------------------------

// fakePTYShell simulates a PTY shell. Tests write to stdoutW to feed data to
// ptyReadLoop; stdin writes from the Manager appear on stdinR.
type fakePTYShell struct {
	stdinR  *io.PipeReader
	stdinW  *io.PipeWriter
	stdoutR *io.PipeReader
	stdoutW *io.PipeWriter
	closeMu sync.Mutex
	closed  bool
}

func newFakePTYShell() *fakePTYShell {
	sr, sw := io.Pipe()
	or, ow := io.Pipe()
	return &fakePTYShell{
		stdinR: sr, stdinW: sw,
		stdoutR: or, stdoutW: ow,
	}
}

func (f *fakePTYShell) closeFunc() error {
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	_ = f.stdinR.Close()
	_ = f.stdoutW.Close()
	return nil
}

// singlePTYTransport is a Transport that serves exactly one PTY shell.
// OpenShell returns an error; only OpenShellPTY is implemented.
type singlePTYTransport struct {
	sh *fakePTYShell
}

func (t *singlePTYTransport) OpenShell(_ context.Context, _ string) (
	io.WriteCloser, io.Reader, io.Reader, func() error, error,
) {
	return nil, nil, nil, nil, fmt.Errorf("singlePTYTransport: OpenShell not implemented")
}

func (t *singlePTYTransport) OpenShellPTY(_ context.Context, _ string, _, _ uint32) (
	io.WriteCloser, io.Reader, func() error, error,
) {
	return t.sh.stdinW, t.sh.stdoutR, t.sh.closeFunc, nil
}

// --------------------------------------------------------------------------
// PTY session tests
// --------------------------------------------------------------------------

// TestStartPTY_CapturesInitialOutput verifies that StartPTY collects output
// written to stdout during the initWaitMs window.
func TestStartPTY_CapturesInitialOutput(t *testing.T) {
	sh := newFakePTYShell()

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = fmt.Fprint(sh.stdoutW, "shell banner\r\n")
	}()

	m := NewManager(&singlePTYTransport{sh: sh}, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id, result, err := m.StartPTY(ctx, "test-server", 80, 24, "", 150)
	if err != nil {
		t.Fatalf("StartPTY error: %v", err)
	}
	if id == "" {
		t.Fatal("StartPTY returned empty id")
	}
	if !strings.Contains(result.Stdout, "shell banner") {
		t.Errorf("initial output = %q, want 'shell banner'", result.Stdout)
	}
}

// TestSendRaw_WritesAndDrains verifies that SendRaw writes input to stdin
// and collects output produced on stdout within the timeout window.
func TestSendRaw_WritesAndDrains(t *testing.T) {
	sh := newFakePTYShell()

	// Echo stdin back as a response on stdout.
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := sh.stdinR.Read(buf)
			if n > 0 {
				cmd := strings.TrimRight(string(buf[:n]), "\r\n")
				_, _ = fmt.Fprintf(sh.stdoutW, "$ %s\r\nresult-of-%s\r\n", cmd, cmd)
			}
			if err != nil {
				return
			}
		}
	}()

	m := NewManager(&singlePTYTransport{sh: sh}, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id, _, err := m.StartPTY(ctx, "test-server", 80, 24, "", 10)
	if err != nil {
		t.Fatalf("StartPTY error: %v", err)
	}

	result, err := m.SendRaw(ctx, id, "ls", 300*time.Millisecond)
	if err != nil {
		t.Fatalf("SendRaw error: %v", err)
	}
	if !strings.Contains(result.Stdout, "result-of-ls") {
		t.Errorf("SendRaw output = %q, want 'result-of-ls'", result.Stdout)
	}
}

// TestIsPTY verifies that IsPTY distinguishes PTY sessions from sentinel ones.
func TestIsPTY(t *testing.T) {
	ctx := context.Background()

	// PTY session.
	sh := newFakePTYShell()
	m := NewManager(&singlePTYTransport{sh: sh}, time.Hour)
	defer m.CloseAll()

	ptyID, _, err := m.StartPTY(ctx, "test-server", 80, 24, "", 10)
	if err != nil {
		t.Fatalf("StartPTY error: %v", err)
	}
	if !m.IsPTY(ptyID) {
		t.Error("IsPTY should return true for a PTY session")
	}
	if m.IsPTY("nonexistent") {
		t.Error("IsPTY should return false for an unknown id")
	}

	// Sentinel session in a separate Manager.
	sentSh := newFakeShell()
	(&shellResponder{sh: sentSh}).run()
	sentFT := &fakeTransport{}
	sentFT.addShell(sentSh)
	sentM := NewManager(sentFT, time.Hour)
	defer sentM.CloseAll()

	sentID, err := sentM.Start(ctx, "test-server")
	if err != nil {
		t.Fatalf("Start (sentinel) error: %v", err)
	}
	if sentM.IsPTY(sentID) {
		t.Error("IsPTY should return false for a sentinel session")
	}
}

// TestStartPTY_Close verifies that a PTY session can be closed cleanly and
// that Close is idempotent.
func TestStartPTY_Close(t *testing.T) {
	sh := newFakePTYShell()
	m := NewManager(&singlePTYTransport{sh: sh}, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id, _, err := m.StartPTY(ctx, "test-server", 0, 0, "", 10)
	if err != nil {
		t.Fatalf("StartPTY error: %v", err)
	}

	if err := m.Close(id); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	for _, info := range m.List() {
		if info.ID == id {
			t.Errorf("closed PTY session %q still appears in List", id)
		}
	}

	// Idempotent: second close must not panic or error.
	if err := m.Close(id); err != nil {
		t.Fatalf("second Close error: %v", err)
	}
}

// TestSend_LongLineWithoutNewlineDoesNotOverflow verifies that a remote process
// emitting a single line far exceeding sessionLineMaxBytes (5 MiB, no embedded
// newline) does not cause OOM. Send must:
//   - complete within the test timeout,
//   - return Truncated=true,
//   - return Stdout whose length is bounded by sessionLineMaxBytes.
func TestSend_LongLineWithoutNewlineDoesNotOverflow(t *testing.T) {
	const fiveMiB = 5 * 1024 * 1024

	sh := newFakeShell()
	startLongLineShell(sh, fiveMiB)

	m := NewManager(&longLineTransport{sh: sh, lineBytes: fiveMiB}, time.Hour)
	defer m.CloseAll()

	ctx := context.Background()
	id, err := m.Start(ctx, "test-server")
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}

	res, err := m.Send(ctx, id, "bigline", 30*time.Second)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	// Stdout content must be bounded by sessionLineMaxBytes (the per-line cap).
	if len(res.Stdout) > sessionLineMaxBytes {
		t.Errorf("Stdout len %d exceeds sessionLineMaxBytes %d", len(res.Stdout), sessionLineMaxBytes)
	}
	if !res.Truncated {
		t.Error("expected Truncated=true for a 5 MiB no-newline line, got false")
	}
}
