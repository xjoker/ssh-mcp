package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
	"github.com/xjoker/mcp-ssh-bridge/internal/ssh"
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
        "passphrase":      { "type": "string" },
        "accept_new_host": { "type": "boolean", "default": false }
      },
      "required": ["host", "user"]
    },
    "command":    { "type": "string", "description": "Shell command to execute on the remote host." },
    "cwd":        { "type": "string", "description": "Working directory. Resolved via SFTP realpath; supports ~ expansion." },
    "stream":     { "type": "boolean", "default": false },
    "timeout_ms": { "type": "integer", "minimum": 1000, "maximum": 1800000, "default": 120000 }
  },
  "oneOf": [
    { "required": ["server", "command"] },
    { "required": ["inline", "command"] }
  ]
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
		srv, ok := deps.Cfg.Servers[input.Server]
		if !ok {
			return envelope.Err(envelope.CodeInvalidArgument,
				fmt.Sprintf("server %q not found in configuration", input.Server), false)
		}
		hostLabel = srv.Host
		userLabel = srv.User

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

		am, err := buildSFTPAdHocAuth(in)
		if err != nil {
			return envelope.Err(envelope.CodeAuthFailed, err.Error(), false)
		}

		c, err := deps.Pool.GetAdHoc(ctx, ssh.AdHocParams{
			Host:          in.Host,
			Port:          port,
			User:          in.User,
			Auth:          am,
			AcceptNewHost: in.AcceptNewHost,
		})
		if err != nil {
			return mapSSHConnErr(err)
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

		// Use pkg/sftp RealPath to resolve the absolute path
		sftpClient, err := client.SFTP()
		if err != nil {
			return envelope.Err(envelope.CodeInternalError,
				"cannot open SFTP sub-system: "+err.Error(), true)
		}
		defer sftpClient.Close()

		resolved, err := sftpClient.RealPath(cwdStr)
		if err != nil {
			return envelope.Err(envelope.CodeInvalidArgument,
				fmt.Sprintf("cannot resolve cwd %q: %v", cwdStr, err), false)
		}
		absDir = resolved
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

	result, err := client.ExecBuffered(ctx, remoteCmd, ssh.ExecOpts{
		OutputMaxBytes: outputMax,
		Timeout:        timeout,
	})
	if err != nil {
		if ctx.Err() != nil {
			return envelope.Err(envelope.CodeTimeout,
				"command timed out: "+err.Error(), true)
		}
		return mapExecError(err)
	}

	stdoutStr := string(result.Stdout)
	if result.Truncated {
		total := len(result.Stdout) + len(result.Stderr)
		stdoutStr += fmt.Sprintf("...[truncated; %d bytes total]", total)
	}

	return envelope.OK(execOutput{
		Stdout:     stdoutStr,
		Stderr:     string(result.Stderr),
		ExitCode:   result.ExitCode,
		Signal:     result.Signal,
		DurationMs: result.Duration.Milliseconds(),
		Truncated:  result.Truncated,
		Host:       hostLabel,
		User:       userLabel,
	})
}

// handleSSHExecStreaming handles stream=true by calling ExecStreaming with
// progress callbacks.
func handleSSHExecStreaming(
	ctx context.Context,
	deps *Deps,
	client *ssh.Client,
	cmd safety.RemoteCommand,
	timeout time.Duration,
	host, user string,
	outputMax int,
) envelope.Response {
	var stdoutBuf strings.Builder
	var stderrBuf strings.Builder

	streamErr := client.ExecStreaming(ctx, cmd, ssh.StreamOpts{
		Timeout: timeout,
		OnStdout: func(chunk []byte, eof bool) {
			stdoutBuf.Write(chunk)
			if deps.Progress != nil && !eof {
				deps.Progress(map[string]any{
					"stream": "stdout",
					"chunk":  string(chunk),
				})
			}
		},
		OnStderr: func(chunk []byte, eof bool) {
			stderrBuf.Write(chunk)
			if deps.Progress != nil && !eof {
				deps.Progress(map[string]any{
					"stream": "stderr",
					"chunk":  string(chunk),
				})
			}
		},
	})

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()
	truncated := false

	// Apply output cap (best-effort for streaming)
	total := len(stdoutStr) + len(stderrStr)
	if outputMax > 0 && total > outputMax {
		if len(stdoutStr) > outputMax {
			stdoutStr = stdoutStr[:outputMax]
			truncated = true
		}
	}
	if truncated {
		stdoutStr += fmt.Sprintf("...[truncated; %d bytes total]", total)
	}

	exitCode := 0
	if streamErr != nil {
		if ctx.Err() != nil {
			return envelope.Err(envelope.CodeTimeout,
				"streaming command timed out: "+streamErr.Error(), true)
		}
		exitCode = -1
	}

	return envelope.OK(execOutput{
		Stdout:     stdoutStr,
		Stderr:     stderrStr,
		ExitCode:   exitCode,
		Signal:     "",
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
