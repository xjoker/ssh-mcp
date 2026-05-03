package tools

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
)

func init() {
	Registered = append(Registered, toolSessionStart())
	Registered = append(Registered, toolSessionSend())
	Registered = append(Registered, toolSessionClose())
}

// --------------------------------------------------------------------------
// session_start
// --------------------------------------------------------------------------

var sessionStartSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "server": { "type": "string", "description": "Configured server name" }
  },
  "required": ["server"]
}`)

func toolSessionStart() Tool {
	return Tool{
		Name:        "session_start",
		Description: "Open a persistent shell session on a remote server. Subsequent session_send calls reuse the same shell.",
		InputSchema: sessionStartSchema,
		Handle:      handleSessionStart,
	}
}

type sessionStartInput struct {
	Server string `json:"server"`
}

type sessionStartOutput struct {
	SessionID string `json:"session_id"`
	Server    string `json:"server"`
	StartedAt string `json:"started_at"`
}

func handleSessionStart(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input sessionStartInput
	if err := json.Unmarshal(args, &input); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
	}
	if input.Server == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'server' is required", false)
	}
	if _, ok := deps.Cfg.Servers[input.Server]; !ok {
		return envelope.Err(envelope.CodeInvalidArgument,
			"server \""+input.Server+"\" not found in configuration", false)
	}

	id, err := deps.SessionMgr.Start(ctx, input.Server)
	if err != nil {
		return mapSessionError(err)
	}

	return envelope.OK(sessionStartOutput{
		SessionID: id,
		Server:    input.Server,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// --------------------------------------------------------------------------
// session_send
// --------------------------------------------------------------------------

var sessionSendSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "session_id": { "type": "string" },
    "command":    { "type": "string" },
    "timeout_ms": { "type": "integer", "default": 120000 }
  },
  "required": ["session_id", "command"]
}`)

func toolSessionSend() Tool {
	return Tool{
		Name:        "session_send",
		Description: "Send a command to an existing persistent shell session. Waits for completion via sentinel-based protocol.",
		InputSchema: sessionSendSchema,
		Handle:      handleSessionSend,
	}
}

type sessionSendInput struct {
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
	TimeoutMs int    `json:"timeout_ms"`
}

type sessionSendOutput struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
}

func handleSessionSend(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input sessionSendInput
	if err := json.Unmarshal(args, &input); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
	}
	if input.SessionID == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'session_id' is required", false)
	}
	if input.Command == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'command' is required", false)
	}

	timeoutMs := input.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 120000
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	result, err := deps.SessionMgr.Send(ctx, input.SessionID, input.Command, timeout)
	if err != nil {
		return mapSessionError(err)
	}

	return envelope.OK(sessionSendOutput{
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		ExitCode:   result.ExitCode,
		DurationMs: result.Duration.Milliseconds(),
	})
}

// --------------------------------------------------------------------------
// session_close
// --------------------------------------------------------------------------

var sessionCloseSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "session_id": { "type": "string" }
  },
  "required": ["session_id"]
}`)

func toolSessionClose() Tool {
	return Tool{
		Name:        "session_close",
		Description: "Close a persistent shell session. Idempotent: closing an already-closed session returns OK.",
		InputSchema: sessionCloseSchema,
		Handle:      handleSessionClose,
	}
}

type sessionCloseInput struct {
	SessionID string `json:"session_id"`
}

func handleSessionClose(_ context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input sessionCloseInput
	if err := json.Unmarshal(args, &input); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
	}
	if input.SessionID == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'session_id' is required", false)
	}

	// Close is idempotent per SDD §6.4 — NOT_FOUND also returns OK.
	_ = deps.SessionMgr.Close(input.SessionID)

	return envelope.OK(map[string]bool{"closed": true})
}

// --------------------------------------------------------------------------
// Error mapping helper
// --------------------------------------------------------------------------

// mapSessionError maps session Manager errors to envelope responses.
func mapSessionError(err error) envelope.Response {
	if err == nil {
		return envelope.OK(nil)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "TIMEOUT"):
		return envelope.Err(envelope.CodeTimeout, msg, true)
	case strings.Contains(msg, "SESSION_DEAD"):
		return envelope.Err(envelope.CodeSessionDead, msg, false)
	case strings.Contains(msg, "not found"):
		return envelope.Err(envelope.CodeNotFound, msg, false)
	case strings.Contains(msg, "SESSION_LIMIT"):
		return envelope.Err(envelope.CodeSessionLimit, msg, false)
	// Connection errors from session.Start (which dials via Pool internally)
	case strings.Contains(msg, "HOST_KEY_MISMATCH"):
		return envelope.Err(envelope.CodeHostKeyMismatch, msg, false)
	case strings.Contains(msg, "HOST_KEY_UNKNOWN"):
		return envelope.ErrWithHint(envelope.CodeHostKeyUnknown, msg,
			"Run 'mcp-ssh-bridge trust <host>' to add the host to known_hosts", false)
	case strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "Authentication failed") ||
		strings.Contains(msg, "auth failed"):
		return envelope.Err(envelope.CodeAuthFailed, msg, false)
	default:
		return envelope.Err(envelope.CodeInternalError, msg, false)
	}
}
