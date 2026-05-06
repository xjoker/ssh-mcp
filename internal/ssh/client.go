package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	sftppkg "github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
)

// Client wraps a *gossh.Client with metadata and convenience methods.
// Callers must call Close() when done.
type Client struct {
	inner    *gossh.Client
	serverID string // server name or ad-hoc host label
	authMode string // human-readable auth label (e.g. "key", "password", "agent")

	// keepalive state
	kaStop chan struct{}
	dead   atomic.Bool

	// home directory cache
	homeOnce sync.Once
	homeDir  string
	homeErr  error

	// closeFunc optionally overrides the Close behaviour (used in tests).
	closeFunc func() error
}

// Underlying returns the wrapped *gossh.Client. Intended for the mcpserver
// adapter layer to build session.Transport / tunnel.Dialer implementations.
// Callers MUST NOT close the returned client directly; use Client.Close.
func (c *Client) Underlying() *gossh.Client { return c.inner }

// ServerID returns the label associated with this client (configured server
// name or ad-hoc host descriptor).
func (c *Client) ServerID() string { return c.serverID }

// AuthMode returns the human-readable authentication label recorded at dial
// time (e.g. "key", "password", "agent"). Returns "" for ad-hoc connections
// or when the auth mode was not captured.
func (c *Client) AuthMode() string { return c.authMode }

// newClient creates a Client wrapping the given ssh.Client and starts a
// background keepalive goroutine.
func newClient(inner *gossh.Client, serverID string) *Client {
	c := &Client{
		inner:    inner,
		serverID: serverID,
		kaStop:   make(chan struct{}),
	}
	go c.keepaliveLoop()
	return c
}

// newClientWithAuthMode is like newClient but also records the auth label.
func newClientWithAuthMode(inner *gossh.Client, serverID, authMode string) *Client {
	c := &Client{
		inner:    inner,
		serverID: serverID,
		authMode: authMode,
		kaStop:   make(chan struct{}),
	}
	go c.keepaliveLoop()
	return c
}

// keepaliveLoop probes the connection every keepaliveInterval.
// After keepaliveMaxFails consecutive failures it marks the client dead.
func (c *Client) keepaliveLoop() {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	fails := 0
	for {
		select {
		case <-c.kaStop:
			return
		case <-ticker.C:
			_, _, err := c.inner.Conn.SendRequest("keepalive@msb", true, nil)
			if err != nil {
				fails++
				if fails >= keepaliveMaxFails {
					c.dead.Store(true)
					return
				}
			} else {
				fails = 0
			}
		}
	}
}

// IsAlive returns true if the keepalive loop has not declared the connection dead.
func (c *Client) IsAlive() bool {
	if c.dead.Load() {
		return false
	}
	// Do a fast probe to detect an already-dead connection early.
	_, _, err := c.inner.Conn.SendRequest("keepalive@msb", true, nil)
	if err != nil {
		c.dead.Store(true)
		return false
	}
	return true
}

// Close shuts down keepalive and the underlying ssh.Client.
func (c *Client) Close() error {
	// If a test stub is provided, delegate entirely to it.
	if c.closeFunc != nil {
		return c.closeFunc()
	}
	// Signal keepalive goroutine to stop (idempotent with select).
	select {
	case <-c.kaStop:
		// already closed
	default:
		close(c.kaStop)
	}
	c.dead.Store(true)
	if c.inner == nil {
		return nil
	}
	return c.inner.Close()
}

// SFTP opens an SFTP sub-system on the connection.
// The returned *sftp.Client is from github.com/pkg/sftp; the caller is
// responsible for closing it.
func (c *Client) SFTP() (*sftppkg.Client, error) {
	return sftppkg.NewClient(c.inner)
}

// ResolveHome returns the remote $HOME directory, using a per-client cache.
func (c *Client) ResolveHome(ctx context.Context) (string, error) {
	c.homeOnce.Do(func() {
		result, err := c.execSimple(ctx, `printf '%s' "$HOME"`)
		if err != nil {
			c.homeErr = fmt.Errorf("ssh: ResolveHome: %w", err)
			return
		}
		h := string(bytes.TrimSpace(result))
		if h == "" {
			c.homeErr = fmt.Errorf("ssh: ResolveHome: $HOME is empty")
			return
		}
		c.homeDir = h
	})
	return c.homeDir, c.homeErr
}

// execSimple runs a command and returns combined stdout as bytes (no streaming,
// no truncation). Internal helper used by ResolveHome.
func (c *Client) execSimple(ctx context.Context, cmd string) ([]byte, error) {
	sess, err := c.inner.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh: NewSession: %w", err)
	}
	defer sess.Close()

	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)

	go func() {
		out, err := sess.Output(cmd)
		ch <- result{out, err}
	}()

	select {
	case <-ctx.Done():
		_ = sess.Signal(gossh.SIGTERM)
		_ = sess.Close()
		return nil, ctx.Err()
	case r := <-ch:
		return r.out, r.err
	}
}

// appendBounded writes p into buf, consuming up to the current remaining budget
// tracked by atomicRemaining. If the budget runs out, the excess bytes are
// discarded and atomicTruncated is set to true.
//
// This helper is unexported so it can be tested in isolation with -race.
// Each buf has its own mutex (bufMu) because two goroutines never share a
// single buffer; the mu is provided by the caller for clarity.
func appendBounded(buf *bytes.Buffer, bufMu *sync.Mutex, p []byte, atomicRemaining *atomic.Int64, atomicTruncated *atomic.Bool) {
	n := int64(len(p))
	if n == 0 {
		return
	}
	// Atomically subtract n from the remaining budget.
	after := atomicRemaining.Add(-n)
	// How many bytes are we actually allowed to write?
	var allowed int64
	if after >= 0 {
		// Budget was sufficient: write all n bytes.
		allowed = n
	} else {
		// Budget partially or fully exhausted.
		atomicTruncated.Store(true)
		// after = remaining_after_subtraction; remaining before = after + n.
		// allowed = max(0, (after + n)) = max(0, remaining_before).
		// But remaining_before may have already been negative if another
		// goroutine raced us, so clamp at 0.
		if after+n > 0 {
			allowed = after + n
		} else {
			allowed = 0
		}
	}
	if allowed > 0 {
		bufMu.Lock()
		buf.Write(p[:allowed])
		bufMu.Unlock()
	}
}

// ExecBuffered runs cmd on the remote host, buffering stdout and stderr.
// SDD §5.5.
func (c *Client) ExecBuffered(ctx context.Context, cmd safety.RemoteCommand, opts ExecOpts) (*ExecResult, error) {
	maxBytes := opts.OutputMaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultOutputMaxBytes
	}

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	start := time.Now()

	sess, err := c.inner.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh: ExecBuffered: NewSession: %w", err)
	}
	defer sess.Close()

	// Request PTY before wiring pipes so the terminal type is negotiated
	// before the server allocates the channel data streams.
	if opts.PTY {
		cols := opts.PTYCols
		if cols == 0 {
			cols = 220
		}
		rows := opts.PTYRows
		if rows == 0 {
			rows = 50
		}
		modes := gossh.TerminalModes{
			gossh.ECHO:          0,     // no local echo — we read server output directly
			gossh.TTY_OP_ISPEED: 38400,
			gossh.TTY_OP_OSPEED: 38400,
		}
		if err := sess.RequestPty("xterm-256color", int(rows), int(cols), modes); err != nil {
			return nil, fmt.Errorf("ssh: ExecBuffered: RequestPty: %w", err)
		}
	}

	stdoutPipe, err := sess.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh: ExecBuffered: StdoutPipe: %w", err)
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh: ExecBuffered: StderrPipe: %w", err)
	}

	var (
		stdoutBuf   bytes.Buffer
		stdoutBufMu sync.Mutex
		stderrBuf   bytes.Buffer
		stderrBufMu sync.Mutex
	)

	// Shared budget across both streams — managed with atomics so concurrent
	// reader goroutines never race on remaining / truncated (H04).
	var atomicRemaining atomic.Int64
	var atomicTruncated atomic.Bool
	atomicRemaining.Store(int64(maxBytes))

	type readResult struct {
		err error
	}

	// Reader goroutine: reads from r into buf, honouring the shared byte budget.
	startReader := func(r io.Reader, buf *bytes.Buffer, bufMu *sync.Mutex) chan readResult {
		ch := make(chan readResult, 1)
		go func() {
			tmp := make([]byte, 4096)
			for {
				n, readErr := r.Read(tmp)
				if n > 0 {
					appendBounded(buf, bufMu, tmp[:n], &atomicRemaining, &atomicTruncated)
				}
				if readErr != nil {
					if readErr == io.EOF {
						ch <- readResult{nil}
					} else {
						ch <- readResult{readErr}
					}
					return
				}
			}
		}()
		return ch
	}

	stdoutDone := startReader(stdoutPipe, &stdoutBuf, &stdoutBufMu)
	stderrDone := startReader(stderrPipe, &stderrBuf, &stderrBufMu)

	if err := sess.Start(cmd.Raw()); err != nil {
		return nil, fmt.Errorf("ssh: ExecBuffered: Start: %w", err)
	}

	// Wait for the command or context cancellation.
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- sess.Wait()
	}()

	var waitErr error
	select {
	case waitErr = <-waitDone:
		// normal completion
	case <-ctx.Done():
		// Context cancelled: close the SSH channel promptly so callers get a
		// TIMEOUT response without waiting for the remote command to finish.
		_ = sess.Signal(gossh.SIGTERM)
		_ = sess.Close()
		select {
		case <-waitDone:
		default:
		}
		waitErr = ctx.Err()
	}

	// Drain reader goroutines.
	<-stdoutDone
	<-stderrDone

	duration := time.Since(start)
	res := &ExecResult{
		Stdout:    stdoutBuf.Bytes(),
		Stderr:    stderrBuf.Bytes(),
		Truncated: atomicTruncated.Load(),
		Duration:  duration,
	}

	if waitErr != nil {
		if waitErr == context.DeadlineExceeded || waitErr == context.Canceled {
			res.ExitCode = -1
			return res, waitErr
		}
		var exitErr *gossh.ExitError
		if asExitErr(waitErr, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			if exitErr.Signal() != "" {
				res.Signal = exitErr.Signal()
			}
		} else {
			// ExitMissingError or other
			res.ExitCode = -1
			res.Signal = "UNKNOWN"
		}
	}

	return res, nil
}

// asExitErr is a helper wrapping errors.As to avoid an import cycle if ever
// the type changes. This is just a convenience wrapper.
func asExitErr(err error, target **gossh.ExitError) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*gossh.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// ExecStreaming runs cmd, calling OnStdout/OnStderr callbacks as chunks arrive.
// SDD §5.5, §6.1.4.
func (c *Client) ExecStreaming(ctx context.Context, cmd safety.RemoteCommand, opts StreamOpts) error {
	chunkSize := opts.ChunkBytes
	if chunkSize <= 0 {
		chunkSize = defaultChunkBytes
	}

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	sess, err := c.inner.NewSession()
	if err != nil {
		return fmt.Errorf("ssh: ExecStreaming: NewSession: %w", err)
	}
	defer sess.Close()

	stdoutPipe, err := sess.StdoutPipe()
	if err != nil {
		return fmt.Errorf("ssh: ExecStreaming: StdoutPipe: %w", err)
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		return fmt.Errorf("ssh: ExecStreaming: StderrPipe: %w", err)
	}

	type streamResult struct{ err error }

	// startStreamReader reads from r and calls cb with chunks. Tries to align
	// on newlines up to chunkSize; if no newline found within chunkSize it
	// flushes unconditionally.
	startStreamReader := func(r io.Reader, cb func([]byte, bool)) chan streamResult {
		ch := make(chan streamResult, 1)
		go func() {
			buf := make([]byte, 0, chunkSize*2)
			tmp := make([]byte, chunkSize)
			for {
				n, readErr := r.Read(tmp)
				if n > 0 {
					buf = append(buf, tmp[:n]...)
					// Flush any complete lines or chunks that are large enough.
					for len(buf) >= chunkSize {
						// Find last newline within chunkSize window.
						cut := bytes.LastIndexByte(buf[:chunkSize], '\n')
						if cut < 0 {
							// No newline — flush exactly chunkSize.
							cut = chunkSize - 1
						}
						if cb != nil {
							cb(buf[:cut+1], false)
						}
						buf = buf[cut+1:]
					}
				}
				if readErr != nil {
					// Flush remainder.
					if len(buf) > 0 && cb != nil {
						cb(buf, false)
					}
					if cb != nil {
						cb(nil, true)
					}
					if readErr == io.EOF {
						ch <- streamResult{nil}
					} else {
						ch <- streamResult{readErr}
					}
					return
				}
			}
		}()
		return ch
	}

	var stdoutCB, stderrCB func([]byte, bool)
	if opts.OnStdout != nil {
		stdoutCB = opts.OnStdout
	}
	if opts.OnStderr != nil {
		stderrCB = opts.OnStderr
	}

	stdoutDone := startStreamReader(stdoutPipe, stdoutCB)
	stderrDone := startStreamReader(stderrPipe, stderrCB)

	if err := sess.Start(cmd.Raw()); err != nil {
		return fmt.Errorf("ssh: ExecStreaming: Start: %w", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- sess.Wait()
	}()

	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-ctx.Done():
		_ = sess.Signal(gossh.SIGTERM)
		_ = sess.Close()
		select {
		case <-waitDone:
		default:
		}
		waitErr = ctx.Err()
	}

	<-stdoutDone
	<-stderrDone

	if waitErr != nil {
		if waitErr == context.DeadlineExceeded || waitErr == context.Canceled {
			return waitErr
		}
		var exitErr *gossh.ExitError
		if asExitErr(waitErr, &exitErr) {
			return fmt.Errorf("ssh: ExecStreaming: exit %d: %w", exitErr.ExitStatus(), waitErr)
		}
		return fmt.Errorf("ssh: ExecStreaming: %w", waitErr)
	}

	return nil
}
