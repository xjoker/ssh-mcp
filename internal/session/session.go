// Package session manages persistent shell sessions for multi-step interactions.
// SDD §5.7, §12.2, §12.3.
//
// Module boundary: no dependency on internal/ssh (uses Transport interface);
// no dependency on internal/safety (not needed here).
package session

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// --------------------------------------------------------------------------
// Transport interface
// --------------------------------------------------------------------------

// Transport is the interface that callers inject to open shell channels.
// The concrete implementation (provided by the mcpserver/tools layer) wraps
// internal/ssh.Client.
type Transport interface {
	// OpenShell opens an interactive shell channel on the named server.
	// It must start a shell and return the three streams and a close function.
	// The caller owns all returned values and must call close() when done.
	// Implementations should avoid allocating a PTY unless they explicitly
	// want prompts/control sequences and merged stderr.
	OpenShell(ctx context.Context, server string) (
		stdin io.WriteCloser,
		stdout io.Reader,
		stderr io.Reader,
		close func() error,
		err error,
	)

	// OpenShellPTY opens an interactive shell with a PTY allocated.
	// stderr is merged into stdout (standard PTY behaviour).
	// cols and rows set the terminal dimensions (0 defaults to 220×50).
	OpenShellPTY(ctx context.Context, server string, cols, rows uint32) (
		stdin  io.WriteCloser,
		stdout io.Reader,
		close  func() error,
		err    error,
	)
}

// --------------------------------------------------------------------------
// Public types
// --------------------------------------------------------------------------

// SendResult holds the output of a single Send call.
type SendResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Truncated bool // true when stdout+stderr exceeded sessionOutputMaxBytes
}

// SessionInfo is a snapshot of session metadata (for List).
type SessionInfo struct {
	ID           string
	Server       string
	StartedAt    time.Time
	LastActivity time.Time
	CommandCount int
}

// --------------------------------------------------------------------------
// Internal session state
// --------------------------------------------------------------------------

type sessionState int

const (
	stateReady  sessionState = iota
	stateBusy                // executing a Send
	stateError               // timed-out or sentinel error; next Send returns SESSION_DEAD
	stateClosed              // Close() called
)

// session holds the live state for one persistent shell.
type session struct {
	mu           sync.Mutex // serialises Send calls on this session
	id           string
	server       string
	startedAt    time.Time
	lastActivity time.Time
	commandCount int
	state        sessionState

	sentinel string // "msb-sentinel-<hex>"

	stdin      io.WriteCloser
	stdout     *bufio.Reader
	stderr     *bufio.Reader
	closeShell func() error

	// stderrBuf accumulates stderr lines read by the background stderr pump.
	// stderrBytes counts bytes held in stderrBuf; once the combined output
	// budget is exceeded, new stderr lines are silently dropped.
	stderrMu    sync.Mutex
	stderrBuf   strings.Builder
	stderrBytes int64
	stderrDone  chan struct{}

	// PTY mode — only set when opened via StartPTY.
	isPTY     bool
	ptyStop   chan struct{} // closed by Close() to signal ptyReadLoop exit
	ptyChunks chan []byte  // raw output chunks from ptyReadLoop; closed on loop exit
}

// appendStderr is called by the background stderr goroutine for each
// complete line read from the remote shell's stderr. Lines are silently
// dropped once the accumulated stderr exceeds sessionOutputMaxBytes.
func (s *session) appendStderr(line string) {
	s.stderrMu.Lock()
	defer s.stderrMu.Unlock()
	if s.stderrBytes+int64(len(line)) > sessionOutputMaxBytes {
		return
	}
	s.stderrBuf.WriteString(line)
	s.stderrBytes += int64(len(line))
}

// consumeStderr atomically snapshots and clears the accumulated stderr.
func (s *session) consumeStderr() string {
	s.stderrMu.Lock()
	defer s.stderrMu.Unlock()
	v := s.stderrBuf.String()
	s.stderrBuf.Reset()
	s.stderrBytes = 0
	return v
}

// ptyReadLoop reads raw bytes from the PTY stdout and forwards chunks to
// ptyChunks. Runs as a background goroutine; exits when ptyStop is closed
// or the underlying reader returns an error.
func (s *session) ptyReadLoop() {
	defer close(s.ptyChunks)
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.ptyStop:
			return
		default:
		}
		n, err := s.stdout.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case s.ptyChunks <- chunk:
			case <-s.ptyStop:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// --------------------------------------------------------------------------
// Manager
// --------------------------------------------------------------------------

// Manager owns all active sessions. It is safe for concurrent use.
// A background goroutine reaps idle sessions every reaperInterval.
type Manager struct {
	transport   Transport
	idleTimeout time.Duration
	// maxSessions caps the number of concurrent live sessions. Start returns
	// a SESSION_LIMIT error when the cap is reached. Zero or negative means
	// "unlimited" (used by tests that need to spin up many sessions).
	maxSessions int

	mu       sync.RWMutex
	sessions map[string]*session

	stopReaper chan struct{}
	reaperDone chan struct{}
}

const reaperInterval = 60 * time.Second

// sessionOutputMaxBytes is the per-Send ceiling for stdout+stderr combined.
// Any output beyond this limit is silently dropped and SendResult.Truncated
// is set to true. 1 MiB is enough for normal interactive commands while
// preventing memory/goroutine DoS from a runaway remote process.
const sessionOutputMaxBytes = 1 << 20 // 1 MiB

// sessionLineMaxBytes is the per-line cap used by readBoundedLine. Once a
// logical line exceeds this size the reader forcibly flushes the buffer and
// discards the remainder of the physical line. This prevents a remote process
// that never emits a newline from growing an unbounded in-memory buffer
// (memory DoS via a single huge line).
const sessionLineMaxBytes = 64 * 1024 // 64 KiB per logical line

// NewManager creates a Manager and starts the idle-session reaper goroutine.
// Call CloseAll to shut down cleanly.
//
// maxSessions defaults to 0 (unlimited) for backwards compatibility with tests.
// Production callers should use NewManagerWithLimit to set the cap.
func NewManager(transport Transport, idleTimeout time.Duration) *Manager {
	return NewManagerWithLimit(transport, idleTimeout, 0)
}

// NewManagerWithLimit is like NewManager but caps live sessions at
// maxSessions (<=0 means unlimited). When the cap is reached, Start returns
// an error containing "SESSION_LIMIT" so the tools layer can map it.
func NewManagerWithLimit(transport Transport, idleTimeout time.Duration, maxSessions int) *Manager {
	m := &Manager{
		transport:   transport,
		idleTimeout: idleTimeout,
		maxSessions: maxSessions,
		sessions:    make(map[string]*session),
		stopReaper:  make(chan struct{}),
		reaperDone:  make(chan struct{}),
	}
	go m.reaperLoop()
	return m
}

func (m *Manager) reaperLoop() {
	defer close(m.reaperDone)
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopReaper:
			return
		case <-ticker.C:
			m.ReapIdle()
		}
	}
}

// ReapIdle closes sessions whose last activity exceeds the idle timeout.
// Called by the internal reaper goroutine; also callable by tests directly.
func (m *Manager) ReapIdle() {
	if m.idleTimeout <= 0 {
		return
	}
	now := time.Now()

	m.mu.RLock()
	var expired []string
	for id, s := range m.sessions {
		s.mu.Lock()
		if s.state != stateClosed && now.Sub(s.lastActivity) > m.idleTimeout {
			expired = append(expired, id)
		}
		s.mu.Unlock()
	}
	m.mu.RUnlock()

	for _, id := range expired {
		_ = m.Close(id)
	}
}

// Start opens a new persistent shell session on the named server and returns
// its session ID (UUID v4). SDD §5.7.
//
// Concurrency cap: when maxSessions > 0, Start returns a SESSION_LIMIT error
// if adding this session would exceed the cap. The check is performed BEFORE
// dialing the remote shell so an over-quota request fails fast without
// consuming an SSH channel. SDD §6.2.
func (m *Manager) Start(ctx context.Context, server string) (string, error) {
	if m.maxSessions > 0 {
		m.mu.RLock()
		live := len(m.sessions)
		m.mu.RUnlock()
		if live >= m.maxSessions {
			return "", fmt.Errorf("session: Start: SESSION_LIMIT: %d concurrent sessions reached", m.maxSessions)
		}
	}

	stdin, stdoutRaw, stderrRaw, closeShell, err := m.transport.OpenShell(ctx, server)
	if err != nil {
		return "", fmt.Errorf("session: Start: OpenShell: %w", err)
	}

	// Generate a random sentinel.
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		_ = closeShell()
		return "", fmt.Errorf("session: Start: rand: %w", err)
	}
	sentinel := "msb-sentinel-" + hex.EncodeToString(buf)

	id := newUUID()
	now := time.Now()

	s := &session{
		id:           id,
		server:       server,
		startedAt:    now,
		lastActivity: now,
		state:        stateReady,
		sentinel:     sentinel,
		stdin:        stdin,
		stdout:       bufio.NewReader(stdoutRaw),
		stderr:       bufio.NewReader(stderrRaw),
		closeShell:   closeShell,
		stderrDone:   make(chan struct{}),
	}

	// Start background stderr pump. Each line is capped at sessionLineMaxBytes
	// to prevent a remote process from streaming a single unbounded line and
	// growing the stderrBuf without limit.
	go func() {
		defer close(s.stderrDone)
		for {
			raw, _, err := readBoundedLine(s.stderr, sessionLineMaxBytes)
			if len(raw) > 0 {
				s.appendStderr(string(raw))
			}
			if err != nil {
				return
			}
		}
	}()

	// Export the sentinel into the shell.
	exportCmd := fmt.Sprintf("export __MSB_SENTINEL='%s'\n", sentinel)
	if _, err := fmt.Fprint(stdin, exportCmd); err != nil {
		_ = closeShell()
		return "", fmt.Errorf("session: Start: write export: %w", err)
	}

	// Send an init probe and wait for the echo to confirm the shell is ready.
	probeCmd := fmt.Sprintf("printf '%%s\\n' 'init-%s'\n", sentinel)
	if _, err := fmt.Fprint(stdin, probeCmd); err != nil {
		_ = closeShell()
		return "", fmt.Errorf("session: Start: write probe: %w", err)
	}

	initLine := "init-" + sentinel
	if err := scanUntilLine(ctx, s.stdout, initLine); err != nil {
		_ = closeShell()
		return "", fmt.Errorf("session: Start: shell init timeout: %w", err)
	}

	m.mu.Lock()
	if m.maxSessions > 0 && len(m.sessions) >= m.maxSessions {
		m.mu.Unlock()
		_ = closeShell()
		return "", fmt.Errorf("session: Start: SESSION_LIMIT: %d concurrent sessions reached", m.maxSessions)
	}
	m.sessions[id] = s
	m.mu.Unlock()

	return id, nil
}

// Send writes a command to the session, waits for sentinel-based completion,
// and returns the result. SDD §5.7. Each Send on a session is serialised.
func (m *Manager) Send(ctx context.Context, id, command string, timeout time.Duration) (*SendResult, error) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("session: Send: session %q not found", id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case stateClosed:
		return nil, fmt.Errorf("session: Send: SESSION_DEAD (session closed)")
	case stateError:
		return nil, fmt.Errorf("session: Send: SESSION_DEAD (session in error state)")
	}

	// Apply per-Send timeout on top of the caller's context.
	sendCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		sendCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Wrap the command with sentinel-based completion detection.
	// { <cmd> ; } ; __rc=$? ; printf '\n%s %s\n' "$__MSB_SENTINEL" "$__rc"
	wrapped := fmt.Sprintf("{ %s ; } ; __rc=$? ; printf '\\n%s %%s\\n' \"$__rc\"\n", command, s.sentinel)

	// Clear any accumulated stderr before this command.
	_ = s.consumeStderr()

	s.state = stateBusy
	start := time.Now()

	if _, err := fmt.Fprint(s.stdin, wrapped); err != nil {
		s.state = stateError
		return nil, fmt.Errorf("session: Send: write: %w", err)
	}

	// Read stdout lines until we see the sentinel line.
	var outputLines []string
	exitCode, truncated, err := scanSentinel(sendCtx, s.stdout, s.sentinel, &outputLines, sessionOutputMaxBytes)
	duration := time.Since(start)

	if err != nil {
		s.state = stateError
		if isContextErr(err) {
			// On timeout: close the transport immediately so the scanSentinel
			// goroutine's blocking ReadString receives an EOF and exits cleanly,
			// preventing goroutine and memory leaks.
			// We deliberately do NOT delete from m.sessions here to avoid a
			// lock-order inversion (Send holds s.mu; Close/ReapIdle hold m.mu
			// first then s.mu). The stateError flag is enough to make any
			// subsequent Send return SESSION_DEAD. The entry will be cleaned up
			// by the next Close(id) or ReapIdle cycle.
			if s.closeShell != nil {
				_ = s.closeShell()
				s.closeShell = nil
			}
			return nil, fmt.Errorf("session: Send: TIMEOUT: %w", err)
		}
		return nil, fmt.Errorf("session: Send: %w", err)
	}

	// Snapshot stderr (best-effort: whatever arrived by now).
	stderrOut := s.consumeStderr()

	s.state = stateReady
	s.lastActivity = time.Now()
	s.commandCount++

	return &SendResult{
		Stdout:    strings.Join(outputLines, "\n"),
		Stderr:    stderrOut,
		ExitCode:  exitCode,
		Duration:  duration,
		Truncated: truncated,
	}, nil
}

// Close shuts down the session identified by id. Idempotent.
func (m *Manager) Close(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()

	if !ok {
		// Idempotent — session already gone or never existed.
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == stateClosed {
		return nil
	}
	s.state = stateClosed

	if s.isPTY && s.ptyStop != nil {
		select {
		case <-s.ptyStop:
		default:
			close(s.ptyStop)
		}
	}

	if s.closeShell != nil {
		_ = s.closeShell()
	}
	return nil
}

// List returns a snapshot of all active (non-closed) sessions.
func (m *Manager) List() []SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		s.mu.Lock()
		if s.state != stateClosed {
			out = append(out, SessionInfo{
				ID:           s.id,
				Server:       s.server,
				StartedAt:    s.startedAt,
				LastActivity: s.lastActivity,
				CommandCount: s.commandCount,
			})
		}
		s.mu.Unlock()
	}
	return out
}

// CloseAll closes all sessions and stops the reaper goroutine.
func (m *Manager) CloseAll() {
	// Stop the reaper first.
	select {
	case <-m.stopReaper:
		// already stopped
	default:
		close(m.stopReaper)
	}
	<-m.reaperDone

	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	for _, id := range ids {
		_ = m.Close(id)
	}
}

// --------------------------------------------------------------------------
// PTY session methods
// --------------------------------------------------------------------------

// drainPTY collects raw PTY output for the given duration and returns a
// SendResult with everything accumulated in Stdout. Output is capped at
// sessionOutputMaxBytes to match sentinel-session behaviour (S-DoS defence).
func (m *Manager) drainPTY(ctx context.Context, s *session, timeout time.Duration) *SendResult {
	var buf strings.Builder
	var truncated bool
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case chunk, ok := <-s.ptyChunks:
			if !ok {
				return &SendResult{Stdout: buf.String(), Truncated: truncated}
			}
			if int64(buf.Len())+int64(len(chunk)) > sessionOutputMaxBytes {
				truncated = true
				// Drain remaining chunks without buffering to keep ptyReadLoop moving.
				continue
			}
			buf.Write(chunk)
		case <-timer.C:
			return &SendResult{Stdout: buf.String(), Truncated: truncated}
		case <-ctx.Done():
			return &SendResult{Stdout: buf.String(), Truncated: truncated}
		}
	}
}

// StartPTY opens a new PTY session on server and optionally runs an initial
// command. initWaitMs controls how long to wait for initial shell/command
// output (defaults to 500 ms when ≤ 0). Returns the session ID and initial output.
func (m *Manager) StartPTY(ctx context.Context, server string, cols, rows uint32, command string, initWaitMs int) (string, *SendResult, error) {
	if m.maxSessions > 0 {
		m.mu.RLock()
		live := len(m.sessions)
		m.mu.RUnlock()
		if live >= m.maxSessions {
			return "", nil, fmt.Errorf("session: StartPTY: SESSION_LIMIT: %d concurrent sessions reached", m.maxSessions)
		}
	}

	stdin, stdoutRaw, closeShell, err := m.transport.OpenShellPTY(ctx, server, cols, rows)
	if err != nil {
		return "", nil, fmt.Errorf("session: StartPTY: OpenShellPTY: %w", err)
	}

	id := newUUID()
	now := time.Now()
	ptyStop := make(chan struct{})
	stderrDone := make(chan struct{})
	close(stderrDone) // no stderr pump for PTY sessions

	s := &session{
		id:           id,
		server:       server,
		startedAt:    now,
		lastActivity: now,
		state:        stateReady,
		stdin:        stdin,
		stdout:       bufio.NewReader(stdoutRaw),
		closeShell:   closeShell,
		stderrDone:   stderrDone,
		isPTY:        true,
		ptyStop:      ptyStop,
		ptyChunks:    make(chan []byte, 256),
	}

	go s.ptyReadLoop()

	if command != "" {
		if _, werr := fmt.Fprintf(stdin, "%s\n", command); werr != nil {
			close(ptyStop)
			_ = closeShell()
			return "", nil, fmt.Errorf("session: StartPTY: write command: %w", werr)
		}
	}

	m.mu.Lock()
	if m.maxSessions > 0 && len(m.sessions) >= m.maxSessions {
		m.mu.Unlock()
		close(ptyStop)
		_ = closeShell()
		return "", nil, fmt.Errorf("session: StartPTY: SESSION_LIMIT: %d concurrent sessions reached", m.maxSessions)
	}
	m.sessions[id] = s
	m.mu.Unlock()

	initWait := time.Duration(initWaitMs) * time.Millisecond
	if initWait <= 0 {
		initWait = 500 * time.Millisecond
	}
	initialResult := m.drainPTY(ctx, s, initWait)

	return id, initialResult, nil
}

// SendRaw writes input followed by a newline to the PTY session's stdin and
// drains output for the given timeout. Use for PTY sessions opened via StartPTY.
func (m *Manager) SendRaw(ctx context.Context, id, input string, timeout time.Duration) (*SendResult, error) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("session: SendRaw: session %q not found", id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case stateClosed:
		return nil, fmt.Errorf("session: SendRaw: SESSION_DEAD (session closed)")
	case stateError:
		return nil, fmt.Errorf("session: SendRaw: SESSION_DEAD (session in error state)")
	}

	// Empty input means "drain without sending" (pure read for PTY).
	if input != "" {
		if _, werr := fmt.Fprintf(s.stdin, "%s\n", input); werr != nil {
			s.state = stateError
			return nil, fmt.Errorf("session: SendRaw: write: %w", werr)
		}
	}

	s.state = stateBusy
	start := time.Now()
	result := m.drainPTY(ctx, s, timeout)
	result.Duration = time.Since(start)
	s.state = stateReady
	s.lastActivity = time.Now()
	s.commandCount++

	return result, nil
}

// IsPTY reports whether the session identified by id was opened with a PTY.
func (m *Manager) IsPTY(id string) bool {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isPTY
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

// readBoundedLine reads one logical line from r, returning at most maxBytes
// bytes of content (not including any trailing newline that was consumed).
// The returned slice DOES include the '\n' byte when the line ended normally.
//
// truncatedLine is true when the physical line exceeded maxBytes: the caller
// receives the first maxBytes bytes and all remaining bytes up to (and
// including) the next '\n' are silently discarded.
//
// If EOF is reached before any byte is read, (nil, false, io.EOF) is returned.
// If EOF is reached mid-line the partial content is returned with err == nil
// (consistent with bufio.Reader.ReadString behaviour for partial lines).
func readBoundedLine(r *bufio.Reader, maxBytes int) (line []byte, truncatedLine bool, err error) {
	var buf []byte
	for {
		b, e := r.ReadByte()
		if e != nil {
			if len(buf) > 0 {
				// Partial line before EOF — return what we have.
				return buf, false, nil
			}
			return nil, false, e
		}
		if b == '\n' {
			return append(buf, '\n'), false, nil
		}
		if len(buf) >= maxBytes {
			// Forced flush: drain remainder of this physical line, then return.
			for {
				b2, e2 := r.ReadByte()
				if e2 != nil {
					return buf, true, nil
				}
				if b2 == '\n' {
					return buf, true, nil
				}
				// Discard bytes beyond the cap.
			}
		}
		buf = append(buf, b)
	}
}

// scanUntilLine reads lines from r until one matches target or ctx is done.
// Each line is capped at sessionLineMaxBytes to prevent memory DoS from a
// remote process emitting a single unbounded line (e.g. a malicious shell
// startup banner).
func scanUntilLine(ctx context.Context, r *bufio.Reader, target string) error {
	done := make(chan error, 1)
	go func() {
		for {
			raw, _, err := readBoundedLine(r, sessionLineMaxBytes)
			line := strings.TrimRight(string(raw), "\r\n")
			if line == target {
				done <- nil
				return
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// scanSentinel reads lines from r, accumulates them into outputLines, and
// returns once it finds a line matching "<sentinel> <decimal>".
// The sentinel line itself is NOT added to outputLines.
// maxBytes caps the total bytes appended to outputLines; lines beyond the cap
// are discarded and truncated is set to true via the returned flag.
func scanSentinel(ctx context.Context, r *bufio.Reader, sentinel string, outputLines *[]string, maxBytes int64) (exitCode int, truncated bool, err error) {
	type scanResult struct {
		exitCode  int
		truncated bool
		err       error
	}
	done := make(chan scanResult, 1)

	go func() {
		// We accumulate all lines; trailing empty lines before the sentinel
		// will be stripped at the end.
		var lines []string
		var bytesAccum int64
		var trunc bool
		for {
			raw, lineTrunc, readErr := readBoundedLine(r, sessionLineMaxBytes)
			// A truncated physical line still counts toward the output cap and
			// sets the overall truncation flag.
			if lineTrunc {
				trunc = true
			}
			line := strings.TrimRight(string(raw), "\r\n")

			// Check for sentinel line: must start with our specific sentinel string.
			// Sentinel lines are never truncated in practice (they are short), but
			// we only match when lineTrunc is false to be safe.
			if !lineTrunc && strings.HasPrefix(line, sentinel+" ") {
				rest := line[len(sentinel)+1:]
				var rc int
				_, scanErr := fmt.Sscanf(rest, "%d", &rc)
				if scanErr == nil {
					// Strip leading empty line that the printf '\n...' adds.
					if len(lines) > 0 && lines[0] == "" {
						lines = lines[1:]
					}
					// Trim trailing empty line.
					for len(lines) > 0 && lines[len(lines)-1] == "" {
						lines = lines[:len(lines)-1]
					}
					*outputLines = lines
					done <- scanResult{rc, trunc, nil}
					return
				}
				// Malformed sentinel line — treat as output.
			}

			// Accumulate with cap enforcement.
			lineBytes := int64(len(line) + 1) // +1 for the stripped newline
			bytesAccum += lineBytes
			if bytesAccum <= maxBytes {
				lines = append(lines, line)
			} else {
				trunc = true
				// Still consume the line but don't store it.
			}

			if readErr != nil {
				done <- scanResult{-1, trunc, readErr}
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return -1, false, ctx.Err()
	case res := <-done:
		return res.exitCode, res.truncated, res.err
	}
}

// isContextErr returns true if err is context.DeadlineExceeded or
// context.Canceled.
func isContextErr(err error) bool {
	return err == context.DeadlineExceeded || err == context.Canceled
}

// newUUID generates a UUID v4 string using crypto/rand to avoid an external
// dependency on github.com/google/uuid.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("session: newUUID: rand.Read failed: " + err.Error())
	}
	// Set version 4 bits.
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits.
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
