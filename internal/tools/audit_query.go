// Package tools — audit_query tool (SDD §6.12).
package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/audit"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
)

func init() {
	Registered = append(Registered, toolAuditQuery())
}

// --------------------------------------------------------------------------
// Input / output types
// --------------------------------------------------------------------------

type auditQueryInput struct {
	Server     string `json:"server,omitempty"`
	Tool       string `json:"tool,omitempty"`
	Since      string `json:"since,omitempty"`       // RFC3339
	Until      string `json:"until,omitempty"`       // RFC3339
	ExitCode   *int   `json:"exit_code,omitempty"`
	ErrorsOnly bool   `json:"errors_only,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

type auditQueryOutput struct {
	Entries   []audit.Entry `json:"entries"`
	Count     int           `json:"count"`
	Truncated bool          `json:"truncated"`
}

// --------------------------------------------------------------------------
// Schema
// --------------------------------------------------------------------------

var auditQuerySchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "server":      { "type": "string", "description": "Filter by server name" },
    "tool":        { "type": "string", "description": "Filter by tool name" },
    "since":       { "type": "string", "format": "date-time", "description": "ISO 8601 / RFC3339 lower bound (inclusive)" },
    "until":       { "type": "string", "format": "date-time", "description": "ISO 8601 / RFC3339 upper bound (inclusive)" },
    "exit_code":   { "type": "integer", "description": "Filter by exact exit code" },
    "errors_only": { "type": "boolean", "default": false, "description": "Only return entries that have an error_code" },
    "limit":       { "type": "integer", "default": 100, "maximum": 1000, "description": "Maximum number of entries to return" }
  }
}`)

// --------------------------------------------------------------------------
// Tool descriptor
// --------------------------------------------------------------------------

func toolAuditQuery() Tool {
	return Tool{
		Name:        "audit_query",
		Description: "Query the bridge's append-only audit log. Returns entries in reverse-chronological order.",
		InputSchema: auditQuerySchema,
		Handle:      handleAuditQuery,
	}
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

func handleAuditQuery(_ context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input auditQueryInput
	if len(args) > 0 {
		if err := json.Unmarshal(args, &input); err != nil {
			return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
		}
	}

	// Build filter.
	f := audit.Filter{
		Server:    input.Server,
		Tool:      input.Tool,
		ErrorOnly: input.ErrorsOnly,
		ExitCodeEq: input.ExitCode,
	}

	// Parse since/until as RFC3339.
	if input.Since != "" {
		t, err := time.Parse(time.RFC3339, input.Since)
		if err != nil {
			return envelope.Err(envelope.CodeInvalidArgument,
				"invalid 'since' timestamp (expected RFC3339): "+err.Error(), false)
		}
		f.Since = t
	}
	if input.Until != "" {
		t, err := time.Parse(time.RFC3339, input.Until)
		if err != nil {
			return envelope.Err(envelope.CodeInvalidArgument,
				"invalid 'until' timestamp (expected RFC3339): "+err.Error(), false)
		}
		f.Until = t
	}

	// Apply limit bounds: default 100, max 1000.
	limit := input.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	f.Limit = limit

	entries, err := deps.Audit.Query(f)
	if err != nil {
		return envelope.Err(envelope.CodeInternalError,
			"audit query failed: "+err.Error(), true)
	}

	// truncated = true when the result count equals the requested limit
	// (indicating there may be more entries).
	truncated := len(entries) == limit

	return envelope.OK(auditQueryOutput{
		Entries:   entries,
		Count:     len(entries),
		Truncated: truncated,
	})
}
