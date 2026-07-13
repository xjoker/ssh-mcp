// Package mcpserver — dispatch.go registers all tools.Tool descriptors with the
// MCP SDK server and wraps each handler with the middleware chain.
// SDD §4.3.
package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xjoker/ssh-mcp/internal/audit"
	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/safety"
	"github.com/xjoker/ssh-mcp/internal/tools"
)

// destructiveTools lists tool names whose invocations have side effects on
// remote systems. SDD §9.3 fail-closed: each call MUST emit a "pending"
// audit record before the handler runs; if that record cannot be written,
// the handler is refused and the caller receives AUDIT_FAILED.
var destructiveTools = map[string]struct{}{
	"ssh_exec":             {},
	"ssh_group_exec":       {},
	"sftp_op":              {},
	"sftp_upload":          {},
	"session_send":         {},
	"session_start":        {},
	"session_close":        {},
	"tunnel":               {},
	"ssh_quick_setup":      {},
	"ssh_persistent_setup": {},
	// self_update replaces the local binary — i.e. it can swap out the
	// security boundary itself. It MUST go through fail-closed audit
	// pre-record so an unwritable audit log can refuse the update, and so
	// the action is visible in audit history before it takes effect.
	"self_update": {},
}

func isDestructive(name string) bool {
	_, ok := destructiveTools[name]
	return ok
}

// newCorrelationID returns a 16-byte hex token for matching pending /
// completed audit records.
func newCorrelationID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

var fallbackSessionID = "local-" + newCorrelationID()

// registerAll iterates over tools.All() and registers each tool with the
// MCP SDK server. It wires the middleware chain around every handler.
func registerAll(mcpSrv *mcp.Server, deps *tools.Deps) error {
	allTools := tools.All()
	for _, t := range allTools {
		if err := registerOne(mcpSrv, t, deps); err != nil {
			return fmt.Errorf("dispatch: register %q: %w", t.Name, err)
		}
	}
	return nil
}

// buildMCPTool constructs the *mcp.Tool descriptor for a tools.Tool,
// including the mapping from tools.Annotations to mcp.ToolAnnotations.
// Factored out of registerOne so it can be exercised directly in tests.
func buildMCPTool(t tools.Tool) *mcp.Tool {
	// InputSchema may be json.RawMessage or nil.
	// mcp.Tool.InputSchema is `any`, so we can assign RawMessage directly.
	// If nil, default to empty object schema.
	var schema any = t.InputSchema
	if len(t.InputSchema) == 0 {
		schema = json.RawMessage(`{"type":"object"}`)
	}

	mcpTool := &mcp.Tool{
		Name:        t.Name,
		Description: t.Description,
		InputSchema: schema,
	}

	if t.Annotations != nil {
		destructive := t.Annotations.DestructiveHint
		openWorld := t.Annotations.OpenWorldHint
		mcpTool.Annotations = &mcp.ToolAnnotations{
			Title:           t.Annotations.Title,
			ReadOnlyHint:    t.Annotations.ReadOnlyHint,
			DestructiveHint: &destructive,
			IdempotentHint:  t.Annotations.IdempotentHint,
			OpenWorldHint:   &openWorld,
		}
	}

	return mcpTool
}

// registerOne registers a single tool with the MCP SDK server.
func registerOne(mcpSrv *mcp.Server, t tools.Tool, deps *tools.Deps) error {
	mcpTool := buildMCPTool(t)

	// Capture loop variables for closure.
	toolName := t.Name
	handler := t.Handle
	d := deps

	mcpSrv.AddTool(mcpTool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return middlewareChain(ctx, req, toolName, handler, d)
	})

	return nil
}

// middlewareChain runs the tool handler through:
// 1. recover (panic → INTERNAL_ERROR)
// 2. progress adapter (inject ProgressFunc into deps)
// 3. elicit adapter (inject ElicitFunc into deps)
// 4. audit (record entry after handler returns; fail-closed on write error)
func middlewareChain(
	ctx context.Context,
	req *mcp.CallToolRequest,
	toolName string,
	handler tools.HandlerFunc,
	deps *tools.Deps,
) (result *mcp.CallToolResult, retErr error) {
	start := time.Now()
	resp := envelope.Response{}
	shouldPostAudit := false
	rawArgs := req.Params.Arguments
	argsRedacted := redactAuditArgs(toolName, rawArgs)
	serverName := extractServerName(rawArgs)
	correlationID := newCorrelationID()
	sessionID := requestSessionID(req, deps.SessionID)

	// 1. Recover from panics — return INTERNAL_ERROR without exposing stack to client.
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			fmt.Fprintf(getStderr(), "mcpserver: PANIC in tool %q: %v\n%s\n", toolName, r, stack)
			resp = envelope.Err(envelope.CodeInternalError,
				fmt.Sprintf("internal server error in tool %q", toolName), false)
			result = envelopeToCallToolResult(resp)
			retErr = nil
			// Force post-audit on panic so read-only tools (sftp_list,
			// audit_query, etc.) also leave a debugging trail. Without
			// this, only destructive tools have a record of the panic.
			shouldPostAudit = true
		}

		if !shouldPostAudit {
			return
		}

		recordOutput := true
		outputCap := 32 * 1024
		if deps.Cfg != nil {
			recordOutput = deps.Cfg.Settings.AuditRecordOutput
			if deps.Cfg.Settings.AuditOutputMaxBytes > 0 {
				outputCap = deps.Cfg.Settings.AuditOutputMaxBytes
			}
		}
		auditEntry := buildAuditEntry(start, toolName, sessionID, serverName, argsRedacted, correlationID, resp, recordOutput, outputCap)
		if auditErr := deps.Audit.Record(auditEntry); auditErr != nil {
			fmt.Fprintf(getStderr(), "mcpserver: audit post-record failed for tool %q: %v\n", toolName, auditErr)
			auditFailResp := envelope.Err(envelope.CodeAuditFailed,
				"audit log write failed after action; outcome cannot be confirmed", false)
			result = envelopeToCallToolResult(auditFailResp)
			retErr = nil
		}
	}()

	// 2. Build per-request Deps: wire progress adapter from the MCP session.
	reqDeps := *deps // shallow copy so we can add per-request fields
	reqDeps.Progress = buildProgressFunc(ctx, req)
	reqDeps.SessionID = sessionID

	// 2.5 Per-server command policy (docs/design/command-policy.md §4).
	// Only tools that carry a top-level "server" field are evaluated here;
	// extractServerName returns "" for ssh_group_exec ("servers"/"tag") and
	// session_send (only "session_id"), so those are naturally skipped and
	// instead evaluate policy themselves per-target/per-session inside
	// internal/tools/group_exec.go and internal/tools/session.go.
	if serverName != "" {
		policy, perr := tools.PolicyForServer(deps, serverName)
		if perr != nil {
			resp = envelope.Err(envelope.CodeInternalError, "policy compile: "+perr.Error(), false)
			return envelopeToCallToolResult(resp), nil
		}
		if policy != nil {
			if denyErr := evaluateSingleServerPolicy(policy, toolName, rawArgs); denyErr != nil {
				deniedEntry := audit.Entry{
					Timestamp:     time.Now().UTC(),
					SessionID:     sessionID,
					Tool:          toolName,
					Server:        serverName,
					ArgsRedacted:  argsRedacted,
					Status:        "denied",
					CorrelationID: correlationID,
					ErrorCode:     envelope.CodePolicyDenied,
					Stderr:        denyErr.Error(),
				}
				if auditErr := deps.Audit.Record(deniedEntry); auditErr != nil {
					fmt.Fprintf(getStderr(), "mcpserver: audit denied-record failed for tool %q: %v\n", toolName, auditErr)
					resp = envelope.Err(envelope.CodeAuditFailed,
						"audit log unavailable; refusing to execute operation", false)
					return envelopeToCallToolResult(resp), nil
				}
				resp = envelope.Err(envelope.CodePolicyDenied, denyErr.Error(), false)
				return envelopeToCallToolResult(resp), nil
			}
		}
	}

	// 3. Pre-record (fail-closed) — destructive tools only.
	//    SDD §9.3: if the pending entry cannot be persisted we refuse to
	//    invoke the handler. Read-only tools (list_servers, audit_query,
	//    sftp_list, sftp_read, sftp_stat) skip this step to keep audit
	//    volume manageable.
	if isDestructive(toolName) {
		pendingEntry := audit.Entry{
			Timestamp:     time.Now().UTC(),
			SessionID:     sessionID,
			Tool:          toolName,
			Server:        serverName,
			ArgsRedacted:  argsRedacted,
			Status:        "pending",
			CorrelationID: correlationID,
		}
		if auditErr := deps.Audit.Record(pendingEntry); auditErr != nil {
			fmt.Fprintf(getStderr(), "mcpserver: audit pre-record failed for tool %q: %v\n", toolName, auditErr)
			auditFailResp := envelope.Err(envelope.CodeAuditFailed,
				"audit log unavailable; refusing to execute destructive operation", false)
			return envelopeToCallToolResult(auditFailResp), nil
		}
	}
	shouldPostAudit = true

	// 4. Invoke the tool handler.
	resp = handler(ctx, &reqDeps, rawArgs)
	return envelopeToCallToolResult(resp), nil
}

func requestSessionID(req *mcp.CallToolRequest, fallback string) string {
	if req != nil && req.Session != nil {
		if id := req.Session.ID(); id != "" {
			return id
		}
	}
	if fallback != "" {
		return fallback
	}
	return fallbackSessionID
}

func buildAuditEntry(start time.Time, toolName, sessionID, serverName, argsRedacted, correlationID string, resp envelope.Response, recordOutput bool, outputCap int) audit.Entry {
	exitCode := 0
	errorCode := ""
	if !resp.OK && resp.Error != nil {
		exitCode = 1
		errorCode = resp.Error.Code
	}

	auditEntry := audit.Entry{
		Timestamp:    time.Now().UTC(),
		SessionID:    sessionID,
		Tool:         toolName,
		Server:       serverName,
		ArgsRedacted: argsRedacted,
		ExitCode:     exitCode,
		DurationMs:   time.Since(start).Milliseconds(),
		ErrorCode:    errorCode,
	}
	if isDestructive(toolName) {
		auditEntry.Status = "completed"
		// session_send / ssh_group_exec evaluate the command policy inside
		// their own handler (the middleware gate at step 2.5 can't resolve a
		// session_id→server or a tag→servers fan-out), so a policy denial
		// reaches here as a normal POLICY_DENIED response. Stamp it "denied"
		// so it matches the middleware-gated ssh_exec denial record instead
		// of looking like a completed execution. docs/design/command-policy.md §3.5.
		if errorCode == envelope.CodePolicyDenied {
			auditEntry.Status = "denied"
		}
		auditEntry.CorrelationID = correlationID
	}

	// If the handler populated AuditMeta, use the richer fields.
	// These fields carry the real remote exit code, byte counts, and auth label
	// that the envelope-success/failure mapping cannot provide. SDD §9.2.
	if resp.Audit != nil {
		if resp.Audit.ExitCode != 0 || resp.OK {
			auditEntry.ExitCode = resp.Audit.ExitCode
		}
		if resp.Audit.BytesIn > 0 {
			auditEntry.BytesIn = resp.Audit.BytesIn
		}
		if resp.Audit.BytesOut > 0 {
			auditEntry.BytesOut = resp.Audit.BytesOut
		}
		if resp.Audit.AuthMode != "" {
			auditEntry.AuthMode = resp.Audit.AuthMode
		}
		if resp.Audit.ContentSHA256 != "" {
			auditEntry.ContentSHA256 = resp.Audit.ContentSHA256
		}
		if recordOutput {
			if resp.Audit.Stdout != "" {
				auditEntry.Stdout = capAndRedactOutput(resp.Audit.Stdout, outputCap)
			}
			if resp.Audit.Stderr != "" {
				auditEntry.Stderr = capAndRedactOutput(resp.Audit.Stderr, outputCap)
			}
		}
	}
	return auditEntry
}

// capAndRedactOutput applies safety.RedactSecret then truncates to maxBytes,
// appending a "…[truncated, N bytes total]" marker when clipped. maxBytes ≤ 0
// disables capping entirely. The truncation point is snapped backwards to a
// UTF-8 rune boundary so the truncated payload is always valid UTF-8 —
// otherwise the audit JSON encoder would replace the half-cut rune with
// U+FFFD and corrupt forensic replays of CJK / emoji output.
func capAndRedactOutput(s string, maxBytes int) string {
	if s == "" {
		return ""
	}
	redacted := string(safety.RedactSecret([]byte(s)))
	if maxBytes <= 0 || len(redacted) <= maxBytes {
		return redacted
	}
	cut := maxBytes
	// Snap back to a rune start. Continuation bytes are 10xxxxxx (0x80..0xBF).
	for cut > 0 && cut < len(redacted) && (redacted[cut]&0xC0) == 0x80 {
		cut--
	}
	return redacted[:cut] + fmt.Sprintf("\n…[truncated, %d bytes total]", len(redacted))
}

func redactAuditArgs(toolName string, raw json.RawMessage) string {
	raw = redactToolSpecificArgs(toolName, raw)
	return string(safety.RedactSecret(raw))
}

func redactToolSpecificArgs(toolName string, raw json.RawMessage) json.RawMessage {
	if toolName != "sftp_op" || len(raw) == 0 {
		return raw
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	if _, ok := m["content"]; !ok {
		return raw
	}
	m["content"] = json.RawMessage(`"***REDACTED***"`)
	m["content_redacted"] = json.RawMessage(`true`)
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// buildProgressFunc builds a ProgressFunc from the MCP session's NotifyProgress.
func buildProgressFunc(ctx context.Context, req *mcp.CallToolRequest) tools.ProgressFunc {
	if req.Session == nil {
		return nil
	}
	token := req.Params.GetProgressToken()
	if token == nil {
		return nil
	}
	return func(value any) {
		// Best-effort: errors from NotifyProgress are non-fatal.
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Message:       fmt.Sprintf("%v", value),
		})
	}
}

// envelopeToCallToolResult converts an envelope.Response to a mcp.CallToolResult.
// The full envelope ({ok, data?, error?}) is always emitted as a single
// TextContent payload so that LLM consumers see the contract documented in
// SDD §5.1 verbatim. IsError is also set on the MCP result so MCP-aware
// clients can short-circuit without parsing.
func envelopeToCallToolResult(resp envelope.Response) *mcp.CallToolResult {
	b, err := json.Marshal(resp)
	if err != nil {
		// Marshal of a well-formed Response cannot fail in practice;
		// surface it loudly if it ever does.
		b = []byte(`{"ok":false,"error":{"code":"INTERNAL_ERROR","message":"envelope marshal failed","retriable":false}}`)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(b)},
		},
		IsError: !resp.OK,
	}
}

// extractServerName tries to extract a "server" field from raw JSON arguments.
// Returns "" if not present or on any error.
func extractServerName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m struct {
		Server string `json:"server"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	return m.Server
}

// extractCommand tries to extract a "command" field from raw JSON arguments
// (ssh_exec). Returns "" if not present or on any error.
func extractCommand(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	return m.Command
}

// isReadOnlyTool reports whether the named tool is registered with
// Annotations.ReadOnlyHint == true (sftp_list / sftp_read / sftp_stat /
// list_servers / audit_query). Linear scan over the small (~20 entry)
// tools.All() list — cheap enough per-request to not warrant a cached map.
func isReadOnlyTool(name string) bool {
	for _, t := range tools.All() {
		if t.Name == name {
			return t.Annotations != nil && t.Annotations.ReadOnlyHint
		}
	}
	return false
}

// evaluateSingleServerPolicy judges a single-server tool invocation against
// an already-non-nil policy (docs/design/command-policy.md §4):
//   - read-only tools (sftp_list/read/stat, list_servers, audit_query)
//     always pass — Annotations.ReadOnlyHint is the source of truth;
//   - sftp_op / sftp_upload / tunnel have no command semantics to evaluate
//     and are denied outright under any non-nil policy (readonly or
//     restricted) — safety.Policy.DenyNonCommandWrites;
//   - ssh_exec's "command" field is evaluated line-by-line via
//     safety.Policy.EvaluateCommand;
//   - session_start's optional "command" (run immediately in PTY mode) is
//     evaluated the same way; a bare open (empty command) passes. Each
//     subsequent session_send command is evaluated on its own by
//     internal/tools/session.go, per SDD §4;
//   - any other single-server tool (ssh_quick_setup, ssh_persistent_setup,
//     etc.) is unaffected — command-policy.md scopes filtering to command
//     execution and non-command writes only.
func evaluateSingleServerPolicy(policy *safety.Policy, toolName string, rawArgs json.RawMessage) error {
	if isReadOnlyTool(toolName) {
		return nil
	}
	switch toolName {
	case "sftp_op", "sftp_upload", "tunnel":
		if policy.DenyNonCommandWrites() {
			return fmt.Errorf("%s: write operation not permitted under this server's command policy", toolName)
		}
	case "ssh_exec":
		return policy.EvaluateCommand(extractCommand(rawArgs))
	case "session_start":
		// PTY-mode session_start runs "command" immediately; a bare open
		// leaves it empty. EvaluateCommand permits an empty command, so
		// evaluating unconditionally is correct and fail-closed.
		if cmd := extractCommand(rawArgs); cmd != "" {
			return policy.EvaluateCommand(cmd)
		}
	}
	return nil
}

// getStderr returns os.Stderr. Defined as a function to allow test injection
// without changing the package's public API.
func getStderr() interface {
	Write([]byte) (int, error)
} {
	return stderrWriter
}
