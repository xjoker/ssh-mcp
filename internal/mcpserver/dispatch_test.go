package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xjoker/ssh-mcp/internal/audit"
	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/tools"
)

// SDD §5.1: every tool returns the unified envelope shape. The dispatcher
// MUST emit the full {ok, data?, error?} object as a single TextContent
// payload — not just the data on success.
func TestEnvelopeWrapsOnSuccess(t *testing.T) {
	resp := envelope.OK(map[string]any{"hello": "world", "n": 42})
	got := envelopeToCallToolResult(resp)

	if got.IsError {
		t.Fatalf("IsError=true on OK envelope")
	}
	tc, ok := got.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent")
	}
	var env struct {
		OK    bool           `json:"ok"`
		Data  map[string]any `json:"data"`
		Error any            `json:"error"`
	}
	if err := json.Unmarshal([]byte(tc.Text), &env); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, tc.Text)
	}
	if !env.OK {
		t.Errorf("ok field should be true; raw=%s", tc.Text)
	}
	if env.Error != nil {
		t.Errorf("error should be omitted on success; raw=%s", tc.Text)
	}
	if env.Data["hello"] != "world" {
		t.Errorf("data not wrapped; got %v", env.Data)
	}
}

func TestEnvelopeWrapsOnError(t *testing.T) {
	resp := envelope.Err(envelope.CodeAuthFailed, "bad creds", false)
	got := envelopeToCallToolResult(resp)

	if !got.IsError {
		t.Fatalf("IsError=false on error envelope")
	}
	tc := got.Content[0].(*mcp.TextContent)
	if !strings.Contains(tc.Text, `"ok":false`) {
		t.Errorf("missing ok:false: %s", tc.Text)
	}
	if !strings.Contains(tc.Text, `"code":"AUTH_FAILED"`) {
		t.Errorf("missing error code: %s", tc.Text)
	}
}

// SDD §9.3 / Codex C02: destructive tools MUST pre-record a "pending"
// entry. If the pre-record fails the handler MUST NOT be invoked and the
// caller MUST receive AUDIT_FAILED.

func TestIsDestructive(t *testing.T) {
	for _, name := range []string{"ssh_exec", "ssh_group_exec", "sftp_op", "session_send", "session_start", "session_close", "tunnel", "ssh_quick_setup"} {
		if !isDestructive(name) {
			t.Errorf("expected %q to be destructive", name)
		}
	}
	for _, name := range []string{"sftp_list", "sftp_read", "sftp_stat", "list_servers", "audit_query"} {
		if isDestructive(name) {
			t.Errorf("expected %q to be read-only", name)
		}
	}
}

func TestNewCorrelationIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newCorrelationID()
		if seen[id] {
			t.Fatalf("duplicate correlation id at iteration %d: %q", i, id)
		}
		seen[id] = true
		if len(id) != 16 {
			t.Errorf("expected 16-char hex, got %q", id)
		}
	}
}

// TestMiddlewareChain_AuditMetaEnrichment verifies that when a handler returns
// a Response with AuditMeta populated, the dispatcher copies ExitCode,
// BytesIn, BytesOut, and AuthMode into the audit entry. SDD §9.2 / M04.
func TestMiddlewareChain_AuditMetaEnrichment(t *testing.T) {
	auditDir := t.TempDir()
	auditLog, err := audit.New(auditDir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer auditLog.Close()

	cfg := &config.Config{
		Settings: config.Settings{},
		Servers:  map[string]config.ServerConfig{},
	}
	deps := &tools.Deps{
		Cfg:   cfg,
		Audit: auditLog,
	}

	// Fake handler: returns OK with AuditMeta carrying exit 0 + byte counts.
	fakeHandler := func(_ context.Context, _ *tools.Deps, _ json.RawMessage) envelope.Response {
		return envelope.OK("result").WithAudit(envelope.AuditMeta{
			ExitCode: 0,
			BytesOut: 512,
			BytesIn:  0,
			AuthMode: "key",
		})
	}

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{"server":"test-server"}`),
		},
	}

	_, middlewareErr := middlewareChain(context.Background(), req, "ssh_exec", fakeHandler, deps)
	if middlewareErr != nil {
		t.Fatalf("middlewareChain: %v", middlewareErr)
	}

	// Query the audit log and verify enriched fields.
	// Give the OS a moment to flush (fsync already happens in Record).
	time.Sleep(10 * time.Millisecond)

	entries, qErr := auditLog.Query(audit.Filter{Tool: "ssh_exec", Limit: 10})
	if qErr != nil {
		t.Fatalf("Query: %v", qErr)
	}

	// For destructive tool "ssh_exec" there will be 2 entries (pending + completed).
	// We want the "completed" one.
	var completed *audit.Entry
	for i := range entries {
		if entries[i].Status == "completed" {
			completed = &entries[i]
			break
		}
	}
	if completed == nil {
		// If no completed entry, use the only one (non-destructive path won't have pending).
		if len(entries) > 0 {
			completed = &entries[0]
		}
	}
	if completed == nil {
		t.Fatal("no audit entry found after middlewareChain")
	}

	if completed.BytesOut != 512 {
		t.Errorf("BytesOut: got %d, want 512", completed.BytesOut)
	}
	if completed.AuthMode != "key" {
		t.Errorf("AuthMode: got %q, want \"key\"", completed.AuthMode)
	}
	// ExitCode=0 on success; dispatcher keeps 0.
	if completed.ExitCode != 0 {
		t.Errorf("ExitCode: got %d, want 0", completed.ExitCode)
	}
}

func TestMiddlewareChain_RedactsSFTPOpContent(t *testing.T) {
	auditDir := t.TempDir()
	auditLog, err := audit.New(auditDir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer auditLog.Close()

	deps := &tools.Deps{
		Cfg:   &config.Config{Settings: config.Settings{}, Servers: map[string]config.ServerConfig{}},
		Audit: auditLog,
	}
	fakeHandler := func(_ context.Context, _ *tools.Deps, _ json.RawMessage) envelope.Response {
		return envelope.OK("ok")
	}
	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{"server":"s1","action":"write","path":"/tmp/x","content":"DO-NOT-LOG"}`),
		},
	}
	if _, err := middlewareChain(context.Background(), req, "sftp_op", fakeHandler, deps); err != nil {
		t.Fatalf("middlewareChain: %v", err)
	}

	entries, qErr := auditLog.Query(audit.Filter{Tool: "sftp_op", Limit: 10})
	if qErr != nil {
		t.Fatalf("Query: %v", qErr)
	}
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	for _, e := range entries {
		if strings.Contains(e.ArgsRedacted, "DO-NOT-LOG") {
			t.Fatalf("audit args leaked sftp content: %+v", entries)
		}
		if !strings.Contains(e.ArgsRedacted, "REDACTED") {
			t.Fatalf("audit args should show redaction marker, got %q", e.ArgsRedacted)
		}
	}
}

// TestMiddlewareChain_AuditMetaNilNoOverride verifies that when a handler
// does NOT set AuditMeta (nil), the dispatcher falls back to the envelope
// success/failure mapping: OK → exit 0, error → exit 1.
func TestMiddlewareChain_AuditMetaNilNoOverride(t *testing.T) {
	auditDir := t.TempDir()
	auditLog, err := audit.New(auditDir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer auditLog.Close()

	cfg := &config.Config{
		Settings: config.Settings{},
		Servers:  map[string]config.ServerConfig{},
	}
	deps := &tools.Deps{
		Cfg:   cfg,
		Audit: auditLog,
	}

	fakeHandler := func(_ context.Context, _ *tools.Deps, _ json.RawMessage) envelope.Response {
		// No WithAudit call — Audit field is nil.
		return envelope.Err(envelope.CodeInternalError, "boom", false)
	}

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{}`),
		},
	}

	_, middlewareErr := middlewareChain(context.Background(), req, "list_servers", fakeHandler, deps)
	if middlewareErr != nil {
		t.Fatalf("middlewareChain: %v", middlewareErr)
	}

	time.Sleep(10 * time.Millisecond)
	entries, qErr := auditLog.Query(audit.Filter{Tool: "list_servers", Limit: 10})
	if qErr != nil {
		t.Fatalf("Query: %v", qErr)
	}
	if len(entries) == 0 {
		t.Fatal("no audit entry found")
	}
	// Error response without AuditMeta → ExitCode should be 1 (envelope mapping).
	if entries[0].ExitCode != 1 {
		t.Errorf("ExitCode: got %d, want 1", entries[0].ExitCode)
	}
	if entries[0].AuthMode != "" {
		t.Errorf("AuthMode should be empty when AuditMeta is nil, got %q", entries[0].AuthMode)
	}
}

func TestMiddlewareChain_PanicWritesCompletionAudit(t *testing.T) {
	auditDir := t.TempDir()
	auditLog, err := audit.New(auditDir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer auditLog.Close()

	oldStderr := stderrWriter
	stderrWriter = io.Discard
	defer func() { stderrWriter = oldStderr }()

	deps := &tools.Deps{
		Cfg:       &config.Config{Settings: config.Settings{}, Servers: map[string]config.ServerConfig{}},
		Audit:     auditLog,
		SessionID: "sess-panic",
	}
	panicHandler := func(_ context.Context, _ *tools.Deps, _ json.RawMessage) envelope.Response {
		panic("boom")
	}
	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{"server":"prod"}`),
		},
	}

	got, err := middlewareChain(context.Background(), req, "ssh_exec", panicHandler, deps)
	if err != nil {
		t.Fatalf("middlewareChain: %v", err)
	}
	if got == nil || !got.IsError {
		t.Fatalf("expected MCP error result after panic, got %#v", got)
	}

	entries, qErr := auditLog.Query(audit.Filter{Tool: "ssh_exec", Limit: 10})
	if qErr != nil {
		t.Fatalf("Query: %v", qErr)
	}
	var pending, completed *audit.Entry
	for i := range entries {
		switch entries[i].Status {
		case "pending":
			pending = &entries[i]
		case "completed":
			completed = &entries[i]
		}
	}
	if pending == nil || completed == nil {
		t.Fatalf("expected pending and completed audit entries, got %+v", entries)
	}
	if completed.ErrorCode != envelope.CodeInternalError {
		t.Errorf("completed ErrorCode = %q, want %q", completed.ErrorCode, envelope.CodeInternalError)
	}
	if completed.SessionID != "sess-panic" {
		t.Errorf("SessionID = %q, want sess-panic", completed.SessionID)
	}
	if completed.CorrelationID == "" || completed.CorrelationID != pending.CorrelationID {
		t.Errorf("correlation mismatch: pending=%q completed=%q", pending.CorrelationID, completed.CorrelationID)
	}
}

// TestMiddlewareChain_PanicWritesAuditForReadOnlyTool verifies that a panic
// inside a non-destructive tool (which skips pre-record) still produces a
// completed audit entry. Without this, panics in read-only tools like
// sftp_list / audit_query would leave no debugging trail.
func TestMiddlewareChain_PanicWritesAuditForReadOnlyTool(t *testing.T) {
	if isDestructive("sftp_list") {
		t.Fatal("sftp_list is expected to be a read-only tool for this test")
	}

	auditDir := t.TempDir()
	auditLog, err := audit.New(auditDir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer auditLog.Close()

	oldStderr := stderrWriter
	stderrWriter = io.Discard
	defer func() { stderrWriter = oldStderr }()

	deps := &tools.Deps{
		Cfg:       &config.Config{Settings: config.Settings{}, Servers: map[string]config.ServerConfig{}},
		Audit:     auditLog,
		SessionID: "sess-ro-panic",
	}
	panicHandler := func(_ context.Context, _ *tools.Deps, _ json.RawMessage) envelope.Response {
		panic("boom-readonly")
	}
	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{"server":"prod"}`),
		},
	}

	got, err := middlewareChain(context.Background(), req, "sftp_list", panicHandler, deps)
	if err != nil {
		t.Fatalf("middlewareChain: %v", err)
	}
	if got == nil || !got.IsError {
		t.Fatalf("expected MCP error result after panic, got %#v", got)
	}

	entries, qErr := auditLog.Query(audit.Filter{Tool: "sftp_list", Limit: 10})
	if qErr != nil {
		t.Fatalf("Query: %v", qErr)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit entry (no pre-record for read-only tools), got %d: %+v", len(entries), entries)
	}
	entry := entries[0]
	if entry.ErrorCode != envelope.CodeInternalError {
		t.Errorf("ErrorCode = %q, want %q", entry.ErrorCode, envelope.CodeInternalError)
	}
	if entry.SessionID != "sess-ro-panic" {
		t.Errorf("SessionID = %q, want sess-ro-panic", entry.SessionID)
	}
	if entry.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", entry.ExitCode)
	}
}
