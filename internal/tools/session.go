package tools

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
)

// inlineSessionRegistrations records session_id → registered temp-server name
// for sessions opened via the inline path. The entry is retained until the
// temp-server TTL/session shutdown path removes it; session_close only closes
// the shell and deliberately does not remove the server registration.
var inlineSessionRegistrations sync.Map // map[string]string

// configServerConfigFromInline builds a minimal ServerConfig used when an
// inline session_start request is registered as a temp server. Auth is
// "quick_setup" so the credResolver consults the QuickSetup registry.
//
// AcceptNewHost is hard-coded to false: AI-initiated first-contact trust
// is forbidden. If the host is unknown, the dial will fail with
// HOST_KEY_UNKNOWN and the caller must run `ssh-mcp trust ...` before
// retrying.
func configServerConfigFromInline(name, host string, port int, user string) config.ServerConfig {
	return config.ServerConfig{
		Name:          name,
		Host:          host,
		Port:          port,
		User:          user,
		Auth:          "quick_setup",
		AcceptNewHost: false,
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
      "description": "Ad-hoc connection params (alternative to server). Credentials are promoted to an in-memory temp server for this MCP session.",
      "properties": {
        "host":             { "type": "string" },
        "port":             { "type": "integer", "minimum": 1, "maximum": 65535, "default": 22 },
        "user":             { "type": "string" },
        "password":         { "type": "string" },
        "private_key_pem":  { "type": "string" },
        "passphrase":       { "type": "string" }
      },
      "required": ["host", "user"]
    },
    "pty":          { "type": "boolean", "description": "Allocate a PTY for interactive TUI programs (btop, htop, ncdu). Stderr is merged into stdout; sentinel protocol is replaced by time-based output collection.", "default": false },
    "cols":         { "type": "integer", "minimum": 10, "maximum": 500, "default": 220, "description": "PTY terminal width (columns). Only used when pty=true." },
    "rows":         { "type": "integer", "minimum": 5, "maximum": 200, "default": 50, "description": "PTY terminal height (rows). Only used when pty=true." },
    "command":      { "type": "string", "description": "Optional command to run immediately after the shell opens (PTY mode). A newline is appended automatically." },
    "init_wait_ms": { "type": "integer", "minimum": 100, "maximum": 10000, "default": 1000, "description": "Milliseconds to wait for initial shell/command output after opening (PTY mode)." }
  }
}`)

func toolSessionStart() Tool {
	return Tool{
		Name:        "session_start",
		Description: "Open a persistent shell session on a remote server. Accepts either a configured server name or inline ad-hoc credentials. Subsequent session_send calls reuse the same shell.",
		InputSchema: sessionStartSchema,
		Handle:      handleSessionStart,
		Annotations: &Annotations{
			Title:           "Start persistent shell session",
			ReadOnlyHint:    false,
			DestructiveHint: false,
			IdempotentHint:  false,
			OpenWorldHint:   true,
		},
	}
}

type sessionStartInput struct {
	Server     string      `json:"server,omitempty"`
	Inline     *sftpInline `json:"inline,omitempty"`
	PTY        bool        `json:"pty"`
	PTYCols    int         `json:"cols"`
	PTYRows    int         `json:"rows"`
	Command    string      `json:"command"`
	InitWaitMs int         `json:"init_wait_ms"`
}

type sessionStartOutput struct {
	SessionID     string `json:"session_id"`
	Server        string `json:"server"`
	StartedAt     string `json:"started_at"`
	Mode          string `json:"mode"`
	InitialOutput string `json:"initial_output,omitempty"`
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
	inlineRegistered := ""
	if hasInline {
		// SDD §6.2 oneOf inline branch — register an ephemeral server in
		// the QuickSetup registry + Pool, then drive the standard Start
		// path so audit/Pool.Get/keepalive all behave normally.
		registered, errResp, ok := registerInlineSession(deps, input.Inline)
		if !ok {
			return errResp
		}
		serverName = registered
		inlineRegistered = registered
	} else {
		if _, ok := lookupServer(deps, input.Server); !ok {
			return envelope.Err(envelope.CodeInvalidArgument,
				"server \""+input.Server+"\" not found in configuration", false)
		}
	}

	if input.PTY {
		cols := clampPTYDim(input.PTYCols, 220, 10, 500)
		rows := clampPTYDim(input.PTYRows, 50, 5, 200)
		id, initialResult, err := deps.SessionMgr.StartPTY(ctx, serverName, cols, rows, input.Command, input.InitWaitMs)
		if err != nil {
			if inlineRegistered != "" {
				cleanupInlineRegistration(deps, inlineRegistered)
			}
			return mapSessionError(err)
		}
		if inlineRegistered != "" {
			inlineSessionRegistrations.Store(id, inlineRegistered)
		}
		out := sessionStartOutput{
			SessionID: id,
			Server:    serverName,
			StartedAt: time.Now().UTC().Format(time.RFC3339),
			Mode:      "pty",
		}
		if initialResult != nil {
			out.InitialOutput = initialResult.Stdout
		}
		return envelope.OK(out)
	}

	id, err := deps.SessionMgr.Start(ctx, serverName)
	if err != nil {
		// On Start failure, scrub the inline registration immediately so the
		// secret does not linger in the QuickSetup registry / Pool until TTL
		// expiry.
		if inlineRegistered != "" {
			cleanupInlineRegistration(deps, inlineRegistered)
		}
		return mapSessionError(err)
	}

	if inlineRegistered != "" {
		inlineSessionRegistrations.Store(id, inlineRegistered)
	}

	return envelope.OK(sessionStartOutput{
		SessionID: id,
		Server:    serverName,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Mode:      "sentinel",
	})
}

// cleanupInlineRegistration removes a temp-server registration created for an
// inline session_start request. Safe to call with a name that was never
// registered (idempotent).
func cleanupInlineRegistration(deps *Deps, name string) {
	if name == "" {
		return
	}
	if deps.QuickSetup != nil {
		deps.QuickSetup.Remove(name)
	}
	if deps.Pool != nil {
		deps.Pool.RemoveTempServer(name)
	}
}

// lookupServer reports whether the name resolves to a configured server or a
// live temp-server in the SSH pool. Quick_setup-registered entries are
// addressable by ssh_exec / ssh_group_exec / session_start once registered.
func lookupServer(deps *Deps, name string) (struct{ Host, User string }, bool) {
	var info struct{ Host, User string }
	if deps == nil || name == "" {
		return info, false
	}
	if srv, ok := deps.Cfg.Servers[name]; ok {
		info.Host = srv.Host
		info.User = srv.User
		return info, true
	}
	if deps.Pool != nil {
		if srv, ok := deps.Pool.LookupTempServer(name); ok {
			info.Host = srv.Host
			info.User = srv.User
			return info, true
		}
	}
	return info, false
}

// sessionServerName resolves the server name a live session was opened
// against, by scanning SessionMgr.List() for a matching ID. Used by
// session_send to key command-policy evaluation off the session's origin
// server (session_send itself carries no "server" field). Returns
// ("", false) for an unknown/closed session — handleSessionSend then falls
// through to deps.SessionMgr.Send, which returns the normal SESSION_DEAD /
// not-found error.
func sessionServerName(deps *Deps, sessionID string) (string, bool) {
	if deps == nil || deps.SessionMgr == nil {
		return "", false
	}
	for _, si := range deps.SessionMgr.List() {
		if si.ID == sessionID {
			return si.Server, true
		}
	}
	return "", false
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
		NameHint: "inline-session-" + in.Host,
		Host:     in.Host,
		Port:     port,
		User:     in.User,
		// AcceptNewHost: see configServerConfigFromInline doc — hard-coded
		// false. AI tools must not establish first-contact trust.
		AcceptNewHost: false,
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

	deps.Pool.AddTempServer(name, configServerConfigFromInline(name, in.Host, port, in.User), time.Unix(expiresAt, 0))
	return name, envelope.Response{}, true
}

// --------------------------------------------------------------------------
// session_send
// --------------------------------------------------------------------------

var sessionSendSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "session_id":  { "type": "string" },
    "command":     { "type": "string", "description": "For sentinel sessions: the shell command to run. For PTY sessions: sent to stdin followed by a newline (use \\x03 for Ctrl-C, etc.)." },
    "timeout_ms":  { "type": "integer", "minimum": 100, "maximum": 1800000, "default": 120000, "description": "For sentinel sessions: max wait for command completion. For PTY sessions: duration to collect output after writing input." },
    "strip_ansi":  { "type": "boolean", "default": false, "description": "Strip ANSI escape sequences from output (useful for PTY sessions running TUI programs)." }
  },
  "required": ["session_id", "command"]
}`)

func toolSessionSend() Tool {
	return Tool{
		Name: "session_send",
		Description: "Send a command to an existing persistent shell session. Waits for completion via sentinel-based protocol. " +
			"The command runs with the full privileges of the SSH user; side effects depend entirely on the command.",
		InputSchema: sessionSendSchema,
		Handle:      handleSessionSend,
		Annotations: &Annotations{
			Title:           "Send command to session",
			ReadOnlyHint:    false,
			DestructiveHint: true,
			IdempotentHint:  false,
			OpenWorldHint:   true,
		},
	}
}

type sessionSendInput struct {
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
	TimeoutMs int    `json:"timeout_ms"`
	StripANSI bool   `json:"strip_ansi"`
}

type sessionSendOutput struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated"`
}

func handleSessionSend(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input sessionSendInput
	if err := json.Unmarshal(args, &input); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
	}
	if input.SessionID == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'session_id' is required", false)
	}

	// Per-server command policy (docs/design/command-policy.md §4).
	// session_send has no top-level "server" field for the mcpserver
	// middleware to key off (only session_id), so it is resolved here via
	// the session's own Server metadata. An empty command (PTY drain-only
	// send, per SDD §6.4) carries no command semantics to evaluate.
	if input.Command != "" {
		if srvName, ok := sessionServerName(deps, input.SessionID); ok {
			policy, perr := PolicyForServer(deps, srvName)
			if perr != nil {
				return envelope.Err(envelope.CodeInternalError, "policy compile: "+perr.Error(), false)
			}
			if policy != nil {
				if err := policy.EvaluateCommand(input.Command); err != nil {
					return envelope.Err(envelope.CodePolicyDenied, err.Error(), false)
				}
			}
		}
	}

	timeoutMs := input.TimeoutMs
	if deps.SessionMgr != nil && deps.SessionMgr.IsPTY(input.SessionID) {
		// PTY: empty command is allowed — means "drain output without sending input".
		if input.Command == "" && timeoutMs <= 0 {
			timeoutMs = 2000
		}
		// PTY sessions use time-based drain; allow shorter timeouts.
		if timeoutMs <= 0 {
			timeoutMs = 2000 // default 2 s for PTY
		}
		if timeoutMs > 1800000 {
			timeoutMs = 1800000
		}
		timeout := time.Duration(timeoutMs) * time.Millisecond
		result, err := deps.SessionMgr.SendRaw(ctx, input.SessionID, input.Command, timeout)
		if err != nil {
			return mapSessionError(err)
		}
		stdout := result.Stdout
		if input.StripANSI {
			stdout = stripANSICodes(stdout)
		}
		return envelope.OK(sessionSendOutput{
			Stdout:     stdout,
			ExitCode:   result.ExitCode,
			DurationMs: result.Duration.Milliseconds(),
			Truncated:  result.Truncated,
		}).WithAudit(envelope.AuditMeta{
			ExitCode: result.ExitCode,
			BytesOut: int64(len(result.Stdout)),
			Stdout:   stdout,
		})
	}

	// Sentinel-based session.
	if input.Command == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'command' is required for non-PTY sessions", false)
	}
	if input.TimeoutMs > 0 && input.TimeoutMs < 1000 {
		return envelope.Err(envelope.CodeInvalidArgument, "timeout_ms must be >= 1000", false)
	}
	if timeoutMs <= 0 {
		timeoutMs = deps.Cfg.Settings.DefaultTimeoutMs
	}
	if timeoutMs <= 0 {
		timeoutMs = 120000
	}
	maxMs := deps.Cfg.Settings.MaxTimeoutMs
	if maxMs <= 0 || maxMs > 1800000 {
		maxMs = 1800000
	}
	if timeoutMs > maxMs {
		timeoutMs = maxMs
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	result, err := deps.SessionMgr.Send(ctx, input.SessionID, input.Command, timeout)
	if err != nil {
		return mapSessionError(err)
	}

	stdout := result.Stdout
	stderr := result.Stderr
	if input.StripANSI {
		stdout = stripANSICodes(stdout)
		stderr = stripANSICodes(stderr)
	}
	return envelope.OK(sessionSendOutput{
		Stdout:     stdout,
		Stderr:     stderr,
		ExitCode:   result.ExitCode,
		DurationMs: result.Duration.Milliseconds(),
		Truncated:  result.Truncated,
	}).WithAudit(envelope.AuditMeta{
		ExitCode: result.ExitCode,
		BytesOut: int64(len(result.Stdout) + len(result.Stderr)),
		Stdout:   stdout,
		Stderr:   stderr,
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
		Annotations: &Annotations{
			Title:           "Close session",
			ReadOnlyHint:    false,
			DestructiveHint: true,
			IdempotentHint:  true,
			OpenWorldHint:   true,
		},
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

	// Intentionally keep any inline temp-server registration alive. The
	// registered server remains addressable by ssh_exec/sftp/tunnel until TTL
	// expiry or MCP server shutdown, matching ssh_quick_setup semantics.
	inlineSessionRegistrations.Delete(input.SessionID)

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
	case strings.Contains(msg, "SESSION_BUSY"):
		// Distinct from DEAD: the shell is alive, the prior command is
		// just still flushing. Retriable; caller may wait or session_close.
		return envelope.ErrWithHint(envelope.CodeSessionBusy, msg,
			"Previous command still producing output. Retry briefly, or call session_close to abort.", true)
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
			"Run 'ssh-mcp trust <host>' to add the host to known_hosts", false)
	case strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "Authentication failed") ||
		strings.Contains(msg, "auth failed"):
		return envelope.Err(envelope.CodeAuthFailed, msg, false)
	default:
		return envelope.Err(envelope.CodeInternalError, msg, false)
	}
}
