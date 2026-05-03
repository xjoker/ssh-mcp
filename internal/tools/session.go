package tools

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
)

// configServerConfigFromInline builds a minimal ServerConfig used when an
// inline session_start request is registered as a temp server. Auth is
// "quick_setup" so the credResolver consults the QuickSetup registry.
// acceptNewHost is forwarded from the inline.accept_new_host argument so that
// the SSH pool honours the caller's host-key policy for this ephemeral entry.
func configServerConfigFromInline(name, host string, port int, user string, acceptNewHost bool) config.ServerConfig {
	return config.ServerConfig{
		Name:          name,
		Host:          host,
		Port:          port,
		User:          user,
		Auth:          "quick_setup",
		AcceptNewHost: acceptNewHost,
	}
}

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
    "server": { "type": "string", "description": "Configured server name" },
    "inline": {
      "type": "object",
      "description": "Ad-hoc connection params (alternative to server). Credentials live only for the lifetime of this session and are cleared on session_close.",
      "properties": {
        "host":             { "type": "string" },
        "port":             { "type": "integer", "minimum": 1, "maximum": 65535, "default": 22 },
        "user":             { "type": "string" },
        "password":         { "type": "string" },
        "private_key_pem":  { "type": "string" },
        "passphrase":       { "type": "string" },
        "accept_new_host":  { "type": "boolean", "default": false }
      },
      "required": ["host", "user"]
    }
  },
  "oneOf": [
    { "required": ["server"] },
    { "required": ["inline"] }
  ]
}`)

func toolSessionStart() Tool {
	return Tool{
		Name:        "session_start",
		Description: "Open a persistent shell session on a remote server. Accepts either a configured server name or inline ad-hoc credentials. Subsequent session_send calls reuse the same shell.",
		InputSchema: sessionStartSchema,
		Handle:      handleSessionStart,
	}
}

type sessionStartInput struct {
	Server string      `json:"server,omitempty"`
	Inline *sftpInline `json:"inline,omitempty"`
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

	hasServer := input.Server != ""
	hasInline := input.Inline != nil
	if !hasServer && !hasInline {
		return envelope.Err(envelope.CodeInvalidArgument,
			"either 'server' or 'inline' is required", false)
	}
	if hasServer && hasInline {
		return envelope.Err(envelope.CodeInvalidArgument,
			"'server' and 'inline' are mutually exclusive", false)
	}

	serverName := input.Server
	if hasInline {
		// SDD §6.2 oneOf inline branch — register an ephemeral server in
		// the QuickSetup registry + Pool, then drive the standard Start
		// path so audit/Pool.Get/keepalive all behave normally.
		registered, errResp, ok := registerInlineSession(deps, input.Inline)
		if !ok {
			return errResp
		}
		serverName = registered
	} else {
		if _, ok := deps.Cfg.Servers[input.Server]; !ok {
			return envelope.Err(envelope.CodeInvalidArgument,
				"server \""+input.Server+"\" not found in configuration", false)
		}
	}

	id, err := deps.SessionMgr.Start(ctx, serverName)
	if err != nil {
		return mapSessionError(err)
	}

	return envelope.OK(sessionStartOutput{
		SessionID: id,
		Server:    serverName,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// registerInlineSession converts inline credentials into a runtime entry
// in the QuickSetup registry + ssh.Pool so that the rest of the session
// machinery can address it by name. The TTL matches the configured session
// idle timeout so the credential lives only as long as the session itself.
//
// Returns (registeredName, errorResponse, ok).
func registerInlineSession(deps *Deps, in *sftpInline) (string, envelope.Response, bool) {
	if !deps.Cfg.Settings.AllowInlineCredentials {
		return "", envelope.Err(envelope.CodeInlineCredsDisabled,
			"inline credentials are disabled by configuration", false), false
	}
	if in.Password == "" && in.PrivateKeyPEM == "" {
		return "", envelope.Err(envelope.CodeInvalidArgument,
			"inline: 'password' or 'private_key_pem' is required", false), false
	}
	if deps.QuickSetup == nil || deps.Pool == nil {
		return "", envelope.Err(envelope.CodeInternalError,
			"session_start: inline path requires QuickSetup + Pool", false), false
	}

	port := in.Port
	if port == 0 {
		port = 22
	}
	ttl := deps.Cfg.Settings.SessionIdleSeconds / 60
	if ttl < 1 {
		ttl = 1
	}
	if ttl > 240 {
		ttl = 240
	}

	spec := QuickSetupSpec{
		NameHint:      "inline-session-" + in.Host,
		Host:          in.Host,
		Port:          port,
		User:          in.User,
		AcceptNewHost: in.AcceptNewHost,
		TTLMinutes:    ttl,
	}
	if in.Password != "" {
		spec.AuthKind = "password"
		spec.Secret = []byte(in.Password)
	} else {
		spec.AuthKind = "key"
		spec.Secret = []byte(in.PrivateKeyPEM)
		if in.Passphrase != "" {
			spec.Passphrase = []byte(in.Passphrase)
		}
	}
	name, expiresAt, err := deps.QuickSetup.Register(spec)
	if err != nil {
		return "", envelope.Err(envelope.CodeInternalError,
			"register inline session: "+err.Error(), false), false
	}

	deps.Pool.AddTempServer(name, configServerConfigFromInline(name, in.Host, port, in.User, in.AcceptNewHost), time.Unix(expiresAt, 0))
	return name, envelope.Response{}, true
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
