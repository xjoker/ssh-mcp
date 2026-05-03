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
	// It must allocate a PTY and start a shell, then return the three streams
	// and a close function. The caller owns all returned values and must call
	// close() when done.
	OpenShell(ctx context.Context, server string) (
		stdin io.WriteCloser,
		stdout io.Reader,
		stderr io.Reader,
		close func() error,
		err error,
	)
}

// --------------------------------------------------------------------------
// Public types
// --------------------------------------------------------------------------

// SendResult holds the output of a single Send call.
type SendResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
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

	stdin    io.WriteCloser
	stdout   *bufio.Reader
	stderr   *bufio.Reader
	closeShell func() error

	// stderrBuf accumulates stderr lines read by the background stderr pump.
	stderrMu  sync.Mutex
	stderrBuf strings.Builder
	stderrDone chan struct{}
}

// drainStderrLine is called by the background stderr goroutine for each
// complete line read from the remote shell's stderr.
func (s *session) appendStderr(line string) {
	s.stderrMu.Lock()
	defer s.stderrMu.Unlock()
	s.stderrBuf.WriteString(line)
}

// consumeStderr atomically snapshots and clears the accumulated stderr.
func (s *session) consumeStderr() string {
	s.stderrMu.Lock()
	defer s.stderrMu.Unlock()
	v := s.stderrBuf.String()
	s.stderrBuf.Reset()
	return v
}

// --------------------------------------------------------------------------
// Manager
// --------------------------------------------------------------------------

// Manager owns all active sessions. It is safe for concurrent use.
// A background goroutine reaps idle sessions every reaperInterval.
type Manager struct {
	transport   Transport
	idleTimeout time.Duration

	mu       sync.RWMutex
	sessions map[string]*session

	stopReaper chan struct{}
	reaperDone chan struct{}
}

const reaperInterval = 60 * time.Second

// NewManager creates a Manager and starts the idle-session reaper goroutine.
// Call CloseAll to shut down cleanly.
func NewManager(transport Transport, idleTimeout time.Duration) *Manager {
	m := &Manager{
		transport:   transport,
		idleTimeout: idleTimeout,
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
func (m *Manager) Start(ctx context.Context, server string) (string, error) {
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

	// Start background stderr pump.
	go func() {
		defer close(s.stderrDone)
		for {
			line, err := s.stderr.ReadString('\n')
			if line != "" {
				s.appendStderr(line)
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
	exitCode, err := scanSentinel(sendCtx, s.stdout, s.sentinel, &outputLines)
	duration := time.Since(start)

	if err != nil {
		s.state = stateError
		if isContextErr(err) {
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
		Stdout:   strings.Join(outputLines, "\n"),
		Stderr:   stderrOut,
		ExitCode: exitCode,
		Duration: duration,
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
// Internal helpers
// --------------------------------------------------------------------------

// scanUntilLine reads lines from r until one matches target or ctx is done.
func scanUntilLine(ctx context.Context, r *bufio.Reader, target string) error {
	done := make(chan error, 1)
	go func() {
		for {
			line, err := r.ReadString('\n')
			line = strings.TrimRight(line, "\r\n")
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
func scanSentinel(ctx context.Context, r *bufio.Reader, sentinel string, outputLines *[]string) (int, error) {
	type scanResult struct {
		exitCode int
		err      error
	}
	done := make(chan scanResult, 1)

	go func() {
		// We accumulate all lines; trailing empty lines before the sentinel
		// will be stripped at the end.
		var lines []string
		for {
			line, err := r.ReadString('\n')
			line = strings.TrimRight(line, "\r\n")

			// Check for sentinel line: must start with our specific sentinel string.
			if strings.HasPrefix(line, sentinel+" ") {
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
					done <- scanResult{rc, nil}
					return
				}
				// Malformed sentinel line — treat as output.
				lines = append(lines, line)
			} else {
				lines = append(lines, line)
			}

			if err != nil {
				done <- scanResult{-1, err}
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return -1, ctx.Err()
	case r := <-done:
		return r.exitCode, r.err
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
