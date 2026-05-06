package tools

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/xjoker/ssh-mcp/internal/audit"
	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
)

func TestHandleAuditQuery_Basic(t *testing.T) {
	dir := t.TempDir()
	logger, err := audit.New(dir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()

	// Write two entries.
	t1 := time.Now().UTC().Add(-2 * time.Second)
	t2 := time.Now().UTC()
	if err := logger.Record(audit.Entry{
		Timestamp: t1, SessionID: "s1", Tool: "ssh_exec", Server: "prod",
		ExitCode: 0, DurationMs: 100,
	}); err != nil {
		t.Fatalf("record 1: %v", err)
	}
	if err := logger.Record(audit.Entry{
		Timestamp: t2, SessionID: "s1", Tool: "ssh_exec", Server: "prod",
		ExitCode: 1, DurationMs: 200, ErrorCode: "CONN_FAILED",
	}); err != nil {
		t.Fatalf("record 2: %v", err)
	}

	deps := &Deps{
		Cfg:   &config.Config{Settings: config.Settings{}},
		Audit: logger,
	}

	resp := handleAuditQuery(context.Background(), deps, json.RawMessage(`{}`))
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}

	raw, _ := json.Marshal(resp.Data)
	var out auditQueryOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 2 {
		t.Errorf("expected count=2, got %d", out.Count)
	}
	if len(out.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(out.Entries))
	}

	// entries are most-recent first
	if out.Entries[0].ExitCode != 1 {
		t.Errorf("first entry should be the most recent (exit_code=1), got %d", out.Entries[0].ExitCode)
	}
	if out.Entries[1].ExitCode != 0 {
		t.Errorf("second entry should be older (exit_code=0), got %d", out.Entries[1].ExitCode)
	}
}

func TestHandleAuditQuery_FilterByTool(t *testing.T) {
	dir := t.TempDir()
	logger, err := audit.New(dir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()

	now := time.Now().UTC()
	logger.Record(audit.Entry{Timestamp: now, Tool: "ssh_exec", Server: "s1", DurationMs: 1})
	logger.Record(audit.Entry{Timestamp: now.Add(time.Millisecond), Tool: "list_servers", Server: "s1", DurationMs: 1})

	deps := &Deps{
		Cfg:   &config.Config{Settings: config.Settings{}},
		Audit: logger,
	}
	resp := handleAuditQuery(context.Background(), deps, json.RawMessage(`{"tool":"list_servers"}`))
	if !resp.OK {
		t.Fatalf("expected OK: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Data)
	var out auditQueryOutput
	json.Unmarshal(raw, &out)

	if out.Count != 1 {
		t.Errorf("expected 1 entry for list_servers, got %d", out.Count)
	}
	if len(out.Entries) > 0 && out.Entries[0].Tool != "list_servers" {
		t.Errorf("wrong tool: %s", out.Entries[0].Tool)
	}
}

func TestHandleAuditQuery_ErrorsOnly(t *testing.T) {
	dir := t.TempDir()
	logger, err := audit.New(dir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()

	now := time.Now().UTC()
	logger.Record(audit.Entry{Timestamp: now, Tool: "ssh_exec", DurationMs: 1})
	logger.Record(audit.Entry{Timestamp: now.Add(time.Millisecond), Tool: "ssh_exec", ErrorCode: "CONN_FAILED", DurationMs: 1})

	deps := &Deps{Cfg: &config.Config{Settings: config.Settings{}}, Audit: logger}
	resp := handleAuditQuery(context.Background(), deps, json.RawMessage(`{"errors_only":true}`))
	if !resp.OK {
		t.Fatalf("expected OK: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Data)
	var out auditQueryOutput
	json.Unmarshal(raw, &out)

	if out.Count != 1 {
		t.Errorf("expected 1 error entry, got %d", out.Count)
	}
	if len(out.Entries) > 0 && out.Entries[0].ErrorCode != "CONN_FAILED" {
		t.Errorf("expected CONN_FAILED, got %s", out.Entries[0].ErrorCode)
	}
}

func TestHandleAuditQuery_Limit(t *testing.T) {
	dir := t.TempDir()
	logger, err := audit.New(dir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()

	// Write 5 entries.
	for i := 0; i < 5; i++ {
		logger.Record(audit.Entry{
			Timestamp: time.Now().UTC().Add(time.Duration(i) * time.Millisecond),
			Tool:      "ssh_exec", DurationMs: 1,
		})
	}

	deps := &Deps{Cfg: &config.Config{Settings: config.Settings{}}, Audit: logger}
	resp := handleAuditQuery(context.Background(), deps, json.RawMessage(`{"limit":3}`))
	if !resp.OK {
		t.Fatalf("expected OK: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Data)
	var out auditQueryOutput
	json.Unmarshal(raw, &out)

	if out.Count != 3 {
		t.Errorf("expected 3 entries (limited), got %d", out.Count)
	}
	if !out.Truncated {
		t.Errorf("expected truncated=true")
	}
}

func TestHandleAuditQuery_InvalidSince(t *testing.T) {
	dir := t.TempDir()
	logger, _ := audit.New(dir, 90)
	defer logger.Close()

	deps := &Deps{Cfg: &config.Config{Settings: config.Settings{}}, Audit: logger}
	resp := handleAuditQuery(context.Background(), deps, json.RawMessage(`{"since":"not-a-time"}`))
	if resp.OK {
		t.Error("expected error for invalid since")
	}
	if resp.Error.Code != envelope.CodeInvalidArgument {
		t.Errorf("expected INVALID_ARGUMENT, got %s", resp.Error.Code)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
