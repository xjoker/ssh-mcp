package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpen_ConfiguresWALAndPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-mcp.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	var journalMode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("journal mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want wal", journalMode)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat database: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("database mode = %04o, want 0600", got)
	}
}

func TestOpen_ImportsJSONLOnceAndPreservesSource(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "audit-2026-07-12.jsonl")
	line := `{"timestamp":"2026-07-12T10:00:00Z","session_id":"s-1","tool":"ssh_exec","server":"prod","duration_ms":12,"status":"completed"}` + "\n"
	if err := os.WriteFile(legacy, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "ssh-mcp.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entries, err := store.QueryAudit(AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("QueryAudit after import: %v", err)
	}
	if len(entries) != 1 || entries[0].Tool != "ssh_exec" {
		t.Fatalf("imported entries = %+v, want one ssh_exec", entries)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store, err = Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer store.Close()
	entries, err = store.QueryAudit(AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("QueryAudit after reopen: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("idempotent import entries = %d, want 1", len(entries))
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy JSONL was not retained: %v", err)
	}
}

func TestStore_RecordAuditQueriesMostRecentFirstAndFailsAfterClose(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ssh-mcp.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	for _, entry := range []AuditEntry{
		{Timestamp: base, Tool: "ssh_exec", Server: "prod", DurationMs: 3, Status: "pending"},
		{Timestamp: base.Add(time.Second), Tool: "ssh_exec", Server: "prod", DurationMs: 4, Status: "completed"},
	} {
		if err := store.RecordAudit(entry); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}

	entries, err := store.QueryAudit(AuditFilter{Server: "prod", Tool: "ssh_exec", Limit: 10})
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if len(entries) != 2 || !entries[0].Timestamp.After(entries[1].Timestamp) {
		t.Fatalf("entries = %+v, want descending timestamps", entries)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := store.RecordAudit(AuditEntry{Timestamp: base, Tool: "ssh_exec"}); err == nil {
		t.Fatal("RecordAudit after Close: expected error")
	}
}

func TestStore_QueryAuditZeroUntilExcludesFutureEntries(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ssh-mcp.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	if err := store.RecordAudit(AuditEntry{Timestamp: now, Tool: "ssh_exec"}); err != nil {
		t.Fatalf("RecordAudit current: %v", err)
	}
	if err := store.RecordAudit(AuditEntry{Timestamp: now.Add(time.Hour), Tool: "ssh_exec"}); err != nil {
		t.Fatalf("RecordAudit future: %v", err)
	}

	entries, err := store.QueryAudit(AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if len(entries) != 1 || !entries[0].Timestamp.Equal(now) {
		t.Fatalf("zero Until entries = %+v, want only current entry", entries)
	}
}

func TestStore_QueryAuditFiltersStatusAndPaginatesByCursor(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ssh-mcp.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	timestamp := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	for _, status := range []string{"completed", "failed", "completed"} {
		if err := store.RecordAudit(AuditEntry{Timestamp: timestamp, Tool: "ssh_exec", Status: status}); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}

	completed, err := store.QueryAudit(AuditFilter{Status: "completed", Until: timestamp.Add(time.Second), Limit: 10})
	if err != nil {
		t.Fatalf("QueryAudit completed: %v", err)
	}
	if len(completed) != 2 || completed[0].ID <= completed[1].ID {
		t.Fatalf("completed entries = %+v, want two descending IDs", completed)
	}

	firstPage, err := store.QueryAudit(AuditFilter{Until: timestamp.Add(time.Second), Limit: 1})
	if err != nil {
		t.Fatalf("QueryAudit first page: %v", err)
	}
	secondPage, err := store.QueryAudit(AuditFilter{
		Until:  timestamp.Add(time.Second),
		Limit:  1,
		Before: &AuditCursor{Timestamp: firstPage[0].Timestamp, ID: firstPage[0].ID},
	})
	if err != nil {
		t.Fatalf("QueryAudit second page: %v", err)
	}
	if len(secondPage) != 1 || secondPage[0].ID >= firstPage[0].ID {
		t.Fatalf("second page = %+v, want next older record", secondPage)
	}
}
