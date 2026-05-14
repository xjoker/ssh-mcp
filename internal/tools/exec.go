package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/safety"
	internalsftp "github.com/xjoker/ssh-mcp/internal/sftp"
	"github.com/xjoker/ssh-mcp/internal/ssh"
)

func init() {
	Registered = append(Registered, toolSSHExec())
}

// --------------------------------------------------------------------------
// Input/output types
// --------------------------------------------------------------------------

// execInput mirrors the JSON input schema for ssh_exec (SDD §6.1).
// The inline field reuses the shared sftpInline type from conn.go.
type execInput struct {
	Server    string      `json:"server"`
	Inline    *sftpInline `json:"inline,omitempty"`
	Command   string      `json:"command"`
	Cwd       string      `json:"cwd,omitempty"`
	Stream    bool        `json:"stream"`
	TimeoutMs int         `json:"timeout_ms"`
	// PTY parameters
	PTY       bool `json:"pty"`
	PTYCols   int  `json:"cols"`
	PTYRows   int  `json:"rows"`
	StripANSI bool `json:"strip_ansi"`
}

// ansiEscape matches ANSI/VT100 escape sequences (CSI, OSC, etc.).
var ansiEscape = regexp.MustCompile(`\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))`)

func stripANSICodes(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

type execOutput struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	Signal     string `json:"signal"`
	DurationMs int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated"`
	Host       string `json:"host"`
	User       string `json:"user"`
}

// --------------------------------------------------------------------------
// Tool descriptor
// --------------------------------------------------------------------------

var sshExecSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "server":  { "type": "string", "description": "Configured server name" },
    "inline":  {
      "type": "object",
      "description": "Ad-hoc connection params (alternative to server). Credentials passed inline are NOT persisted.",
      "properties": {
        "host":            { "type": "string" },
        "port":            { "type": "integer", "minimum": 1, "maximum": 65535, "default": 22 },
        "user":            { "type": "string" },
        "password":        { "type": "string" },
        "private_key_pem": { "type": "string" },
        "passphrase":      { "type": "string" }
      },
      "required": ["host", "user"]
    },
    "command":    { "type": "string", "description": "Shell command to execute on the remote host." },
    "cwd":        { "type": "string", "description": "Working directory. Resolved via SFTP realpath; supports ~ expansion." },
    "stream":     { "type": "boolean", "default": false },
    "timeout_ms": { "type": "integer", "minimum": 1000, "maximum": 1800000, "default": 120000 },
    "pty":        { "type": "boolean", "default": false, "description": "Allocate a pseudo-terminal. Required for TUI programs (btop, htop, ncdu). Merges stderr into stdout." },
    "cols":       { "type": "integer", "minimum": 10, "maximum": 500, "default": 220, "description": "Terminal width for PTY (columns). Only used when pty=true." },
    "rows":       { "type": "integer", "minimum": 5, "maximum": 200, "default": 50, "description": "Terminal height for PTY (rows). Only used when pty=true." },
    "strip_ansi": { "type": "boolean", "default": false, "description": "Strip ANSI escape sequences from output. Useful with pty=true to get plain text." }
  },
  "required": ["command"]
}`)

func toolSSHExec() Tool {
	return Tool{
		Name:        "ssh_exec",
		Description: "Execute a single command on a remote SSH server. Returns stdout, stderr, and exit code.",
		InputSchema: sshExecSchema,
		Handle:      handleSSHExec,
	}
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

func handleSSHExec(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input execInput
	if err := json.Unmarshal(args, &input); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
	}

	// oneOf: exactly one of server or inline must be set
	hasServer := input.Server != ""
	hasInline := input.Inline != nil
	if hasServer == hasInline {
		return envelope.Err(envelope.CodeInvalidArgument,
			"exactly one of 'server' or 'inline' must be provided", false)
	}
	if input.Command == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'command' is required", false)
	}

	// Inline credentials check
	if hasInline && !deps.Cfg.Settings.AllowInlineCredentials {
		return envelope.Err(envelope.CodeInlineCredsDisabled,
			"inline credentials are disabled by server configuration", false)
	}

	// Timeout
	if input.TimeoutMs > 0 && input.TimeoutMs < 1000 {
		return envelope.Err(envelope.CodeInvalidArgument, "timeout_ms must be >= 1000", false)
	}
	timeoutMs := input.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = deps.Cfg.Settings.DefaultTimeoutMs
	}
	if timeoutMs <= 0 {
		timeoutMs = 120000
	}
	maxMs := deps.Cfg.Settings.MaxTimeoutMs
	if maxMs > 0 && timeoutMs > maxMs {
		timeoutMs = maxMs
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	// Acquire client
	var client *ssh.Client
	var hostLabel, userLabel string
	var adHoc bool

	if hasServer {
		info, ok := lookupServer(deps, input.Server)
		if !ok {
			return envelope.Err(envelope.CodeInvalidArgument,
				fmt.Sprintf("server %q not found in configuration", input.Server), false)
		}
		hostLabel = info.Host
		userLabel = info.User

		c, err := deps.Pool.Get(ctx, input.Server)
		if err != nil {
			return mapSSHConnErr(err)
		}
		client = c
	} else { //nolint:gocritic // intentional else after return
		in := input.Inline
		port := in.Port
		if port == 0 {
			port = 22
		}
		hostLabel = in.Host
		userLabel = in.User
		adHoc = true

		am, cleanup, err := buildSFTPAdHocAuth(in)
		if err != nil {
			return envelope.Err(envelope.CodeAuthFailed, err.Error(), false)
		}

		// AcceptNewHost is hard-coded to false: AI tools must not initiate
		// first-contact trust. Use `ssh-mcp trust ...` from the CLI to
		// inspect and pin the host fingerprint before any AI-driven call.
		c, dialErr := deps.Pool.GetAdHoc(ctx, ssh.AdHocParams{
			Host:          in.Host,
			Port:          port,
			User:          in.User,
			Auth:          am,
			AcceptNewHost: false,
		})
		cleanup() // zero the secret immediately after dial
		if dialErr != nil {
			return mapSSHConnErr(dialErr)
		}
		client = c
	}

	// Ad-hoc connections are not pooled — close when done.
	if adHoc {
		defer client.Close()
	}

	// Resolve cwd
	cwdStr := input.Cwd
	if cwdStr == "" && hasServer {
		if srv, ok := deps.Cfg.Servers[input.Server]; ok {
			cwdStr = srv.DefaultDir
		}
	}

	var absDir string
	if cwdStr != "" {
		// Expand ~ via ResolveHome if needed
		if strings.HasPrefix(cwdStr, "~") {
			home, err := client.ResolveHome(ctx)
			if err != nil {
				return envelope.Err(envelope.CodeInternalError,
					"cannot resolve home directory: "+err.Error(), true)
			}
			if cwdStr == "~" {
				cwdStr = home
			} else if strings.HasPrefix(cwdStr, "~/") {
				cwdStr = home + cwdStr[1:]
			}
		}

		// R2-C01: route cwd through internal/sftp.Realpath which validates
		// the canonical form (NUL-byte / absolute / length checks) before
		// applying allowed_paths. This closes the symlink-bypass that the
		// raw pkg/sftp.RealPath path had.
		internalSFTP, err := internalsftp.New(client.Underlying())
		if err != nil {
			return envelope.Err(envelope.CodeInternalError,
				"cannot open SFTP sub-system: "+err.Error(), true)
		}
		defer internalSFTP.Close()

		serverNameForCheck := ""
		if hasServer {
			serverNameForCheck = input.Server
		}
		cwdRP, errResp, ok := resolveAndCheckRemotePath(deps, serverNameForCheck, internalSFTP, cwdStr, false)
		if !ok {
			return errResp
		}
		absDir = cwdRP.String()
	}

	// Build remote command via safety package
	remoteCmd, err := safety.NewRemoteCommand(input.Command, absDir)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}

	// Execute
	outputMax := deps.Cfg.Settings.OutputMaxBytes
	if outputMax <= 0 {
		outputMax = 65536
	}

	if input.Stream {
		return handleSSHExecStreaming(ctx, deps, client, remoteCmd, timeout, hostLabel, userLabel, outputMax)
	}

	ptyOpts := ssh.ExecOpts{
		OutputMaxBytes: outputMax,
		Timeout:        timeout,
	}
	if input.PTY {
		ptyOpts.PTY = true
		ptyOpts.PTYCols = clampPTYDim(input.PTYCols, 220, 10, 500)
		ptyOpts.PTYRows = clampPTYDim(input.PTYRows, 50, 5, 200)
	}

	result, err := client.ExecBuffered(ctx, remoteCmd, ptyOpts)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return envelope.Err(envelope.CodeTimeout,
				"command timed out: "+err.Error(), true)
		}
		return mapExecError(err)
	}

	stdoutStr := string(result.Stdout)
	if input.StripANSI {
		stdoutStr = stripANSICodes(stdoutStr)
	}
	if result.Truncated {
		total := len(result.Stdout) + len(result.Stderr)
		stdoutStr += fmt.Sprintf("...[truncated; %d bytes total]", total)
	}

	bytesOut := int64(len(result.Stdout) + len(result.Stderr))
	return envelope.OK(execOutput{
		Stdout:     stdoutStr,
		Stderr:     string(result.Stderr),
		ExitCode:   result.ExitCode,
		Signal:     result.Signal,
		DurationMs: result.Duration.Milliseconds(),
		Truncated:  result.Truncated,
		Host:       hostLabel,
		User:       userLabel,
	}).WithAudit(envelope.AuditMeta{
		ExitCode: result.ExitCode,
		BytesOut: bytesOut,
		AuthMode: client.AuthMode(),
		Stdout:   stdoutStr,
		Stderr:   string(result.Stderr),
	})
}

// handleSSHExecStreaming handles stream=true by calling ExecStreaming with
// progress callbacks. Output is truncated in real-time at outputMax bytes
// (SDD §6.1). The real exit code and signal are extracted from the error
// returned by ExecStreaming.
func handleSSHExecStreaming(
	ctx context.Context,
	deps *Deps,
	client *ssh.Client,
	cmd safety.RemoteCommand,
	timeout time.Duration,
	host, user string,
	outputMax int,
) envelope.Response {
	// Shared budget and truncation flag across stdout/stderr callbacks.
	var remaining atomic.Int64
	var truncatedFlag atomic.Bool
	remaining.Store(int64(outputMax))

	var stdoutBuf strings.Builder
	var stderrBuf strings.Builder
	var stdoutMu, stderrMu sync.Mutex

	// M02: progressTruncEmitted guards the single "truncated" progress event
	// that is emitted once the output budget is exhausted. After that one
	// event no further progress chunks are sent to the client, so BytesOut
	// reflects only bytes actually delivered (not the raw remote output total).
	var progressTruncEmitted atomic.Bool

	// appendBoundedStr appends up to the remaining budget from chunk into buf.
	// Returns whether the chunk was within budget (true) or truncated (false).
	appendBoundedStr := func(buf *strings.Builder, mu *sync.Mutex, chunk []byte) bool {
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

	streamErr := client.ExecStreaming(ctx, cmd, ssh.StreamOpts{
		Timeout: timeout,
		OnStdout: func(chunk []byte, eof bool) {
			withinBudget := appendBoundedStr(&stdoutBuf, &stdoutMu, chunk)
			if deps.Progress != nil && !eof {
				if withinBudget {
					deps.Progress(map[string]any{
						"stream": "stdout",
						"chunk":  string(chunk),
					})
				} else if progressTruncEmitted.CompareAndSwap(false, true) {
					// M02: budget exceeded — emit exactly one truncated event.
					deps.Progress(map[string]any{
						"stream":    "stdout",
						"truncated": true,
					})
				}
			}
		},
		OnStderr: func(chunk []byte, eof bool) {
			withinBudget := appendBoundedStr(&stderrBuf, &stderrMu, chunk)
			if deps.Progress != nil && !eof {
				if withinBudget {
					deps.Progress(map[string]any{
						"stream": "stderr",
						"chunk":  string(chunk),
					})
				} else if progressTruncEmitted.CompareAndSwap(false, true) {
					// M02: budget exceeded — emit exactly one truncated event.
					deps.Progress(map[string]any{
						"stream":    "stderr",
						"truncated": true,
					})
				}
			}
		},
	})

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()
	truncated := truncatedFlag.Load()

	if truncated {
		total := len(stdoutStr) + len(stderrStr)
		stdoutStr += fmt.Sprintf("...[truncated; %d bytes total]", total)
	}

	// M02: BytesOut reflects the bytes actually buffered (and sent to the client),
	// not the raw remote output total. This is computed before the truncation
	// suffix is appended to stdoutStr.
	bytesOut := int64(stdoutBuf.Len() + stderrBuf.Len())
	resp := buildStreamingEnvelope(ctx, streamErr, stdoutStr, stderrStr, truncated, host, user)
	if resp.OK {
		// Only attach AuditMeta on success; error path already loses exit code fidelity.
		exitCode := 0
		if resp.Data != nil {
			if out, ok := resp.Data.(execOutput); ok {
				exitCode = out.ExitCode
			}
		}
		resp = resp.WithAudit(envelope.AuditMeta{
			ExitCode: exitCode,
			BytesOut: bytesOut,
			AuthMode: client.AuthMode(),
			Stdout:   stdoutStr,
			Stderr:   stderrStr,
		})
	}
	return resp
}

// buildStreamingEnvelope constructs the final envelope.Response for a streaming
// execution. It maps the error from ExecStreaming to exit_code / signal,
// matching the semantics of ExecBuffered (SDD §6.1).
//
// This helper is unexported so it can be unit-tested in isolation without
// needing a real SSH connection.
func buildStreamingEnvelope(
	ctx context.Context,
	streamErr error,
	stdout, stderr string,
	truncated bool,
	host, user string,
) envelope.Response {
	if streamErr != nil && (ctx.Err() != nil || errors.Is(streamErr, context.DeadlineExceeded) || errors.Is(streamErr, context.Canceled)) {
		return envelope.Err(envelope.CodeTimeout,
			"streaming command timed out: "+streamErr.Error(), true)
	}

	exitCode := 0
	signal := ""

	if streamErr != nil {
		var exitErr *gossh.ExitError
		if e, ok := streamErr.(*gossh.ExitError); ok {
			exitErr = e
		}
		// ExecStreaming wraps the exit error with fmt.Errorf, so also unwrap.
		if exitErr == nil {
			cause := streamErr
			for cause != nil {
				if e, ok := cause.(*gossh.ExitError); ok {
					exitErr = e
					break
				}
				// unwrap one level
				type unwrapper interface{ Unwrap() error }
				if uw, ok := cause.(unwrapper); ok {
					cause = uw.Unwrap()
				} else {
					break
				}
			}
		}
		if exitErr != nil {
			exitCode = exitErr.ExitStatus()
			if exitErr.Signal() != "" {
				signal = exitErr.Signal()
			}
		} else {
			// ExitMissingError or other non-exit-code error (e.g. signal kill).
			exitCode = -1
			signal = "UNKNOWN"
		}
	}

	return envelope.OK(execOutput{
		Stdout:     stdout,
		Stderr:     stderr,
		ExitCode:   exitCode,
		Signal:     signal,
		DurationMs: 0, // streaming does not track duration separately
		Truncated:  truncated,
		Host:       host,
		User:       user,
	})
}

// --------------------------------------------------------------------------
// Error mapping helper (for exec-level errors)
// --------------------------------------------------------------------------

// mapExecError translates exec-level errors to envelope responses.
// Connection-level errors use mapSSHConnErr from conn.go.
func mapExecError(err error) envelope.Response {
	if err == nil {
		return envelope.OK(nil)
	}
	msg := err.Error()
	if strings.Contains(msg, "permission denied") {
		return envelope.Err(envelope.CodePermissionDenied, msg, false)
	}
	return envelope.Err(envelope.CodeInternalError, msg, false)
}
