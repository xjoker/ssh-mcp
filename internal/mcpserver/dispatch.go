// Package mcpserver — dispatch.go registers all tools.Tool descriptors with the
// MCP SDK server and wraps each handler with the middleware chain.
// SDD §4.3.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xjoker/mcp-ssh-bridge/internal/audit"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
	"github.com/xjoker/mcp-ssh-bridge/internal/tools"
)

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

// registerOne registers a single tool with the MCP SDK server.
func registerOne(mcpSrv *mcp.Server, t tools.Tool, deps *tools.Deps) error {
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

	// 1. Recover from panics — return INTERNAL_ERROR without exposing stack to client.
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			fmt.Fprintf(getStderr(), "mcpserver: PANIC in tool %q: %v\n%s\n", toolName, r, stack)
			errResp := envelope.Err(envelope.CodeInternalError,
				fmt.Sprintf("internal server error in tool %q", toolName), false)
			result = envelopeToCallToolResult(errResp)
			retErr = nil
		}
	}()

	// 2. Build per-request Deps: wire progress and elicit adapters from the
	//    MCP session available in req.Session.
	reqDeps := *deps // shallow copy so we can add per-request fields
	reqDeps.Progress = buildProgressFunc(ctx, req)
	reqDeps.Elicit = buildElicitFunc(req)

	// 3. Invoke the tool handler.
	rawArgs := req.Params.Arguments
	resp := handler(ctx, &reqDeps, rawArgs)

	// 4. Audit: record the completed call.
	//    Redact arguments before storage.
	argsRedacted := string(safety.RedactSecret(rawArgs))
	durationMs := time.Since(start).Milliseconds()

	exitCode := 0
	errorCode := ""
	if !resp.OK && resp.Error != nil {
		exitCode = 1
		errorCode = resp.Error.Code
	}

	// Determine server name from arguments best-effort (tool may not have one).
	serverName := extractServerName(rawArgs)

	auditEntry := audit.Entry{
		Timestamp:    time.Now().UTC(),
		SessionID:    deps.SessionID,
		Tool:         toolName,
		Server:       serverName,
		ArgsRedacted: argsRedacted,
		ExitCode:     exitCode,
		DurationMs:   durationMs,
		ErrorCode:    errorCode,
	}

	if auditErr := deps.Audit.Record(auditEntry); auditErr != nil {
		// Fail-closed: we cannot guarantee the audit trail is intact.
		// Log to stderr and return AUDIT_FAILED. The underlying tool action has
		// already completed at this point (unavoidable race), but we signal
		// the failure to the caller so the LLM can handle it.
		fmt.Fprintf(getStderr(), "mcpserver: audit.Record failed for tool %q: %v\n", toolName, auditErr)
		auditFailResp := envelope.Err(envelope.CodeAuditFailed,
			"audit log write failed; action may have been executed but cannot be confirmed", false)
		return envelopeToCallToolResult(auditFailResp), nil
	}

	return envelopeToCallToolResult(resp), nil
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

// buildElicitFunc builds an ElicitFunc from the MCP session.
func buildElicitFunc(req *mcp.CallToolRequest) tools.ElicitFunc {
	if req.Session == nil {
		return nil
	}
	return func(ctx context.Context, schema json.RawMessage, message string) (json.RawMessage, error) {
		result, err := req.Session.Elicit(ctx, &mcp.ElicitParams{
			Message:         message,
			RequestedSchema: schema,
		})
		if err != nil {
			return nil, fmt.Errorf("elicit: %w", err)
		}
		// Check if user declined.
		if result.Action != "accept" {
			return json.RawMessage(`{"confirm":false}`), nil
		}
		// Marshal the content map back to JSON for the tool handler.
		raw, err := json.Marshal(result.Content)
		if err != nil {
			return nil, fmt.Errorf("elicit: marshal response: %w", err)
		}
		return raw, nil
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

// getStderr returns os.Stderr. Defined as a function to allow test injection
// without changing the package's public API.
func getStderr() interface {
	Write([]byte) (int, error)
} {
	return stderrWriter
}
