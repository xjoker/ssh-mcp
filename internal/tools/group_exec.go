package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
	internalsftp "github.com/xjoker/mcp-ssh-bridge/internal/sftp"
	"github.com/xjoker/mcp-ssh-bridge/internal/ssh"
)

func init() {
	Registered = append(Registered, toolSSHGroupExec())
}

// --------------------------------------------------------------------------
// Input/output types
// --------------------------------------------------------------------------

type groupExecInput struct {
	Servers        []string `json:"servers,omitempty"`
	Tag            string   `json:"tag,omitempty"`
	Command        string   `json:"command"`
	Cwd            string   `json:"cwd,omitempty"`
	TimeoutMs      int      `json:"timeout_ms"`
	StopOnError    bool     `json:"stop_on_error"`
	MaxConcurrency int      `json:"max_concurrency"`
}

type groupExecServerResult struct {
	Server     string         `json:"server"`
	OK         bool           `json:"ok"`
	Stdout     string         `json:"stdout,omitempty"`
	Stderr     string         `json:"stderr,omitempty"`
	ExitCode   int            `json:"exit_code,omitempty"`
	DurationMs int64          `json:"duration_ms,omitempty"`
	Error      *envelope.Error `json:"error,omitempty"`
}

type groupExecSummary struct {
	Total      int   `json:"total"`
	Succeeded  int   `json:"succeeded"`
	Failed     int   `json:"failed"`
	DurationMs int64 `json:"duration_ms"`
}

type groupExecOutput struct {
	Results []groupExecServerResult `json:"results"`
	Summary groupExecSummary        `json:"summary"`
}

// --------------------------------------------------------------------------
// Tool descriptor
// --------------------------------------------------------------------------

var sshGroupExecSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "servers": { "type": "array", "items": { "type": "string" }, "minItems": 1, "maxItems": 32 },
    "tag":     { "type": "string", "description": "Alternative to 'servers': run on all servers with this tag" },
    "command": { "type": "string" },
    "cwd":     { "type": "string" },
    "timeout_ms":       { "type": "integer", "default": 120000 },
    "stop_on_error":    { "type": "boolean", "default": false },
    "max_concurrency":  { "type": "integer", "default": 8, "maximum": 16 }
  },
  "required": ["command"],
  "oneOf": [
    { "required": ["servers"] },
    { "required": ["tag"] }
  ]
}`)

func toolSSHGroupExec() Tool {
	return Tool{
		Name:        "ssh_group_exec",
		Description: "Run the same command across a group of servers concurrently. Returns one result per server.",
		InputSchema: sshGroupExecSchema,
		Handle:      handleSSHGroupExec,
	}
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

func handleSSHGroupExec(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input groupExecInput
	if err := json.Unmarshal(args, &input); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
	}

	// oneOf: exactly one of servers or tag
	hasServers := len(input.Servers) > 0
	hasTag := input.Tag != ""
	if hasServers == hasTag {
		return envelope.Err(envelope.CodeInvalidArgument,
			"exactly one of 'servers' or 'tag' must be provided", false)
	}
	if input.Command == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'command' is required", false)
	}

	// Resolve server list
	var serverNames []string
	if hasServers {
		serverNames = input.Servers
	} else {
		// Filter by tag
		for name, srv := range deps.Cfg.Servers {
			for _, t := range srv.Tags {
				if t == input.Tag {
					serverNames = append(serverNames, name)
					break
				}
			}
		}
		if len(serverNames) == 0 {
			return envelope.Err(envelope.CodeInvalidArgument,
				fmt.Sprintf("no servers found with tag %q", input.Tag), false)
		}
	}

	// Validate all server names exist upfront
	for _, name := range serverNames {
		if _, ok := deps.Cfg.Servers[name]; !ok {
			return envelope.Err(envelope.CodeInvalidArgument,
				fmt.Sprintf("server %q not found in configuration", name), false)
		}
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

	// Concurrency
	maxConc := input.MaxConcurrency
	if maxConc <= 0 {
		maxConc = 8
	}
	if maxConc > 16 {
		maxConc = 16
	}

	// Output max
	outputMax := deps.Cfg.Settings.OutputMaxBytes
	if outputMax <= 0 {
		outputMax = 65536
	}

	overallStart := time.Now()

	// Cancellable context for stop_on_error
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Semaphore channel
	sem := make(chan struct{}, maxConc)

	results := make([]groupExecServerResult, len(serverNames))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i, name := range serverNames {
		i, name := i, name
		wg.Add(1)

		go func() {
			defer wg.Done()

			// Acquire semaphore
			select {
			case sem <- struct{}{}:
			case <-execCtx.Done():
				mu.Lock()
				results[i] = groupExecServerResult{
					Server: name,
					OK:     false,
					Error: &envelope.Error{
						Code:      envelope.CodeTimeout,
						Message:   "cancelled before execution",
						Retriable: false,
					},
				}
				mu.Unlock()
				return
			}
			defer func() { <-sem }()

			// Check if cancelled before starting
			select {
			case <-execCtx.Done():
				mu.Lock()
				results[i] = groupExecServerResult{
					Server: name,
					OK:     false,
					Error: &envelope.Error{
						Code:      envelope.CodeTimeout,
						Message:   "cancelled before execution",
						Retriable: false,
					},
				}
				mu.Unlock()
				return
			default:
			}

			res := execOnServer(execCtx, deps, name, input.Command, input.Cwd, timeout, outputMax)
			mu.Lock()
			results[i] = res
			mu.Unlock()

			if !res.OK && input.StopOnError {
				cancel()
			}
		}()
	}

	wg.Wait()
	overallDuration := time.Since(overallStart)

	// Compute summary
	succeeded := 0
	failed := 0
	for _, r := range results {
		if r.OK {
			succeeded++
		} else {
			failed++
		}
	}

	output := groupExecOutput{
		Results: results,
		Summary: groupExecSummary{
			Total:      len(serverNames),
			Succeeded:  succeeded,
			Failed:     failed,
			DurationMs: overallDuration.Milliseconds(),
		},
	}

	if failed == 0 {
		return envelope.OK(output)
	}

	// Partial or total failure: return structured data but mark top-level as error
	resp := envelope.Response{
		OK:   false,
		Data: output,
		Error: &envelope.Error{
			Code:      envelope.CodePartialFailure,
			Message:   fmt.Sprintf("%d of %d servers failed", failed, len(serverNames)),
			Retriable: false,
		},
	}
	return resp
}

// earlyCwdCheck performs a syntactic allowed_paths check on an absolute cwd/defaultDir
// BEFORE a connection is established. This catches obvious policy violations (e.g.
// cwd="/etc" with allowed_paths=["/tmp"]) without needing SSH, and ensures the
// test suite can verify rejection without a live pool. Paths starting with "~" are
// skipped here because they require home-dir resolution over SSH first.
//
// Returns (errResult, true) when the path is denied; (zero, false) when allowed or
// when the path needs post-connect resolution (e.g. "~").
func earlyCwdCheck(deps *Deps, serverName, rawPath string) (groupExecServerResult, bool) {
	if rawPath == "" || strings.HasPrefix(rawPath, "~") {
		return groupExecServerResult{}, false
	}
	rp, err := safety.ValidateRemotePath(rawPath)
	if err != nil {
		return groupExecServerResult{
			Server: serverName,
			OK:     false,
			Error: &envelope.Error{
				Code:    envelope.CodeInvalidArgument,
				Message: fmt.Sprintf("invalid cwd %q: %v", rawPath, err),
			},
		}, true
	}
	errResp, allowed := enforceAllowedPath(deps.Cfg, serverName, rp)
	if !allowed {
		return groupExecServerResult{
			Server: serverName,
			OK:     false,
			Error:  errResp.Error,
		}, true
	}
	return groupExecServerResult{}, false
}

// execOnServer runs command on a single named server and returns a result struct.
func execOnServer(
	ctx context.Context,
	deps *Deps,
	serverName, command, cwd string,
	timeout time.Duration,
	outputMax int,
) groupExecServerResult {
	// Determine what cwd/defaultDir string we intend to use so we can
	// syntactically validate allowed_paths BEFORE acquiring a connection.
	// This ensures that even with a nil Pool the early-rejection tests pass
	// (S-1/S-2) and that we fail fast without consuming a connection slot.
	rawCwd := cwd
	if rawCwd == "" {
		if srv, ok := deps.Cfg.Servers[serverName]; ok {
			rawCwd = srv.DefaultDir
		}
	}

	if result, denied := earlyCwdCheck(deps, serverName, rawCwd); denied {
		return result
	}

	client, err := deps.Pool.Get(ctx, serverName)
	if err != nil {
		errResp := mapSSHConnErr(err)
		return groupExecServerResult{
			Server: serverName,
			OK:     false,
			Error:  errResp.Error,
		}
	}

	// Resolve cwd through internal/sftp.Realpath + resolveAndCheckRemotePath
	// (symlink-resistant, enforces allowed_paths on the canonical form).
	absDir := ""
	cwdStr := cwd
	if cwdStr == "" {
		if srv, ok := deps.Cfg.Servers[serverName]; ok {
			cwdStr = srv.DefaultDir
		}
	}

	if cwdStr != "" {
		// Expand ~ via ResolveHome if needed (mirrors exec.go behaviour).
		if strings.HasPrefix(cwdStr, "~") {
			home, herr := client.ResolveHome(ctx)
			if herr == nil {
				if cwdStr == "~" {
					cwdStr = home
				} else if strings.HasPrefix(cwdStr, "~/") {
					cwdStr = home + cwdStr[1:]
				}
			}
		}

		internalSFTP, serr := internalsftp.New(client.Underlying())
		if serr != nil {
			return groupExecServerResult{
				Server: serverName,
				OK:     false,
				Error: &envelope.Error{
					Code:      envelope.CodeInternalError,
					Message:   "cannot open SFTP sub-system: " + serr.Error(),
					Retriable: true,
				},
			}
		}
		defer internalSFTP.Close()

		cwdRP, errResp, ok := resolveAndCheckRemotePath(deps, serverName, internalSFTP, cwdStr, false)
		if !ok {
			return groupExecServerResult{
				Server: serverName,
				OK:     false,
				Error:  errResp.Error,
			}
		}
		absDir = cwdRP.String()
	}

	remoteCmd, err := safety.NewRemoteCommand(command, absDir)
	if err != nil {
		return groupExecServerResult{
			Server: serverName,
			OK:     false,
			Error: &envelope.Error{
				Code:    envelope.CodeInvalidArgument,
				Message: err.Error(),
			},
		}
	}

	result, err := client.ExecBuffered(ctx, remoteCmd, ssh.ExecOpts{
		OutputMaxBytes: outputMax,
		Timeout:        timeout,
	})
	if err != nil {
		if ctx.Err() != nil {
			return groupExecServerResult{
				Server: serverName,
				OK:     false,
				Error: &envelope.Error{
					Code:      envelope.CodeTimeout,
					Message:   "command timed out or cancelled",
					Retriable: true,
				},
			}
		}
		errResp := mapExecError(err)
		return groupExecServerResult{
			Server: serverName,
			OK:     false,
			Error:  errResp.Error,
		}
	}

	stdoutStr := string(result.Stdout)
	if result.Truncated {
		total := len(result.Stdout) + len(result.Stderr)
		stdoutStr += fmt.Sprintf("...[truncated; %d bytes total]", total)
	}

	return groupExecServerResult{
		Server:     serverName,
		OK:         true,
		Stdout:     stdoutStr,
		Stderr:     string(result.Stderr),
		ExitCode:   result.ExitCode,
		DurationMs: result.Duration.Milliseconds(),
	}
}
