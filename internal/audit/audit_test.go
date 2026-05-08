package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helper: create a Logger in a temp dir with 90-day retention.
func newTestLogger(t *testing.T) (*Logger, string) {
	t.Helper()
	dir := t.TempDir()
	l, err := New(dir, 90)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, dir
}

// helper: build a minimal valid Entry with the given timestamp.
func makeEntry(ts time.Time, tool, server string) Entry {
	return Entry{
		Timestamp:  ts,
		SessionID:  "test-session",
		Tool:       tool,
		Server:     server,
		DurationMs: 1,
	}
}

// TestNew_DirPermissions verifies that the state directory is created with
// mode 0700 (S-8).
func TestNew_DirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	l, err := New(dir, 30)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	got := info.Mode().Perm()
	if got != 0700 {
		t.Errorf("dir mode = %04o, want 0700", got)
	}
}

// TestRecord_FilePermissions verifies that the audit file is created with
// mode 0600 (S-8).
func TestRecord_FilePermissions(t *testing.T) {
	l, dir := newTestLogger(t)

	e := makeEntry(time.Now().UTC(), "ssh_exec", "prod")
	if err := l.Record(e); err != nil {
		t.Fatalf("Record: %v", err)
	}

	today := time.Now().UTC().Format(dateLayout)
	path := filepath.Join(dir, filePrefix+today+fileSuffix)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	got := info.Mode().Perm()
	if got != 0600 {
		t.Errorf("file mode = %04o, want 0600", got)
	}
}

// TestRecord_QueryRoundTrip writes one entry and reads it back via Query.
func TestRecord_QueryRoundTrip(t *testing.T) {
	l, _ := newTestLogger(t)

	ts := time.Now().UTC().Truncate(time.Millisecond)
	e := Entry{
		Timestamp:  ts,
		SessionID:  "sess-abc",
		Tool:       "sftp_op",
		Server:     "web-01",
		AuthMode:   "agent",
		DurationMs: 42,
		BytesOut:   1024,
	}
	if err := l.Record(e); err != nil {
		t.Fatalf("Record: %v", err)
	}

	results, err := l.Query(Filter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Query returned %d entries, want 1", len(results))
	}

	got := results[0]
	if !got.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, ts)
	}
	if got.SessionID != e.SessionID {
		t.Errorf("SessionID = %q, want %q", got.SessionID, e.SessionID)
	}
	if got.Tool != e.Tool {
		t.Errorf("Tool = %q, want %q", got.Tool, e.Tool)
	}
	if got.Server != e.Server {
		t.Errorf("Server = %q, want %q", got.Server, e.Server)
	}
	if got.DurationMs != e.DurationMs {
		t.Errorf("DurationMs = %d, want %d", got.DurationMs, e.DurationMs)
	}
	if got.BytesOut != e.BytesOut {
		t.Errorf("BytesOut = %d, want %d", got.BytesOut, e.BytesOut)
	}
}

// TestRecord_MultipleOrder verifies that multiple records appear in append order.
func TestRecord_MultipleOrder(t *testing.T) {
	l, _ := newTestLogger(t)

	tools := []string{"tool_a", "tool_b", "tool_c"}
	base := time.Now().UTC()
	for i, tool := range tools {
		e := makeEntry(base.Add(time.Duration(i)*time.Millisecond), tool, "s1")
		if err := l.Record(e); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	results, err := l.Query(Filter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("Query returned %d entries, want 3", len(results))
	}

	// Query returns most-recent first.
	if results[0].Tool != "tool_c" {
		t.Errorf("results[0].Tool = %q, want tool_c", results[0].Tool)
	}
	if results[2].Tool != "tool_a" {
		t.Errorf("results[2].Tool = %q, want tool_a", results[2].Tool)
	}
}

// TestQuery_ReverseTimestampOrder injects two entries 1ms apart and verifies
// Query returns them newest-first.
func TestQuery_ReverseTimestampOrder(t *testing.T) {
	l, _ := newTestLogger(t)

	base := time.Now().UTC()
	earlier := makeEntry(base, "tool_x", "srv")
	later := makeEntry(base.Add(time.Millisecond), "tool_x", "srv")

	if err := l.Record(earlier); err != nil {
		t.Fatalf("Record earlier: %v", err)
	}
	if err := l.Record(later); err != nil {
		t.Fatalf("Record later: %v", err)
	}

	results, err := l.Query(Filter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) < 2 {
		t.Fatalf("expected >= 2 results, got %d", len(results))
	}
	if !results[0].Timestamp.After(results[1].Timestamp) {
		t.Errorf("expected results[0].Timestamp (%v) > results[1].Timestamp (%v)",
			results[0].Timestamp, results[1].Timestamp)
	}
}

// TestQuery_FilterServer verifies that Filter.Server restricts results.
func TestQuery_FilterServer(t *testing.T) {
	l, _ := newTestLogger(t)
	base := time.Now().UTC()

	for i, srv := range []string{"alpha", "beta", "alpha"} {
		if err := l.Record(makeEntry(base.Add(time.Duration(i)*time.Millisecond), "t", srv)); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	results, err := l.Query(Filter{Server: "alpha", Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results for Server=alpha, want 2", len(results))
	}
	for _, r := range results {
		if r.Server != "alpha" {
			t.Errorf("result has Server=%q, want alpha", r.Server)
		}
	}
}

// TestQuery_FilterTool verifies that Filter.Tool restricts results.
func TestQuery_FilterTool(t *testing.T) {
	l, _ := newTestLogger(t)
	base := time.Now().UTC()

	for i, tool := range []string{"ssh_exec", "sftp_op", "ssh_exec"} {
		if err := l.Record(makeEntry(base.Add(time.Duration(i)*time.Millisecond), tool, "s")); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	results, err := l.Query(Filter{Tool: "ssh_exec", Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results for Tool=ssh_exec, want 2", len(results))
	}
	for _, r := range results {
		if r.Tool != "ssh_exec" {
			t.Errorf("result has Tool=%q, want ssh_exec", r.Tool)
		}
	}
}

// TestQuery_FilterErrorOnly verifies that Filter.ErrorOnly restricts results.
func TestQuery_FilterErrorOnly(t *testing.T) {
	l, _ := newTestLogger(t)
	base := time.Now().UTC()

	ok := makeEntry(base, "tool", "s")
	ok.ErrorCode = ""
	errEntry := makeEntry(base.Add(time.Millisecond), "tool", "s")
	errEntry.ErrorCode = "CONN_FAILED"

	if err := l.Record(ok); err != nil {
		t.Fatalf("Record ok: %v", err)
	}
	if err := l.Record(errEntry); err != nil {
		t.Fatalf("Record err: %v", err)
	}

	results, err := l.Query(Filter{ErrorOnly: true, Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results for ErrorOnly, want 1", len(results))
	}
	if results[0].ErrorCode != "CONN_FAILED" {
		t.Errorf("ErrorCode = %q, want CONN_FAILED", results[0].ErrorCode)
	}
}

// TestQuery_Limit verifies that Limit truncates results.
func TestQuery_Limit(t *testing.T) {
	l, _ := newTestLogger(t)
	base := time.Now().UTC()

	for i := 0; i < 5; i++ {
		if err := l.Record(makeEntry(base.Add(time.Duration(i)*time.Millisecond), "t", "s")); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	results, err := l.Query(Filter{Limit: 3})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("got %d results, want 3", len(results))
	}
	if len(results) == 3 && !results[0].Timestamp.Equal(base.Add(4*time.Millisecond)) {
		t.Errorf("newest result = %s, want %s", results[0].Timestamp, base.Add(4*time.Millisecond))
	}
}

// TestQuery_MalformedJSONLSkipsLine verifies that malformed JSONL lines are
// skipped rather than aborting the entire query. A truncated line from a
// kill -9 should not poison historical log queries; valid entries before and
// after the bad line must still be returned.
func TestQuery_MalformedJSONLSkipsLine(t *testing.T) {
	dir := t.TempDir()
	today := time.Now().UTC().Format(dateLayout)
	path := filepath.Join(dir, filePrefix+today+fileSuffix)

	good1 := `{"timestamp":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","tool":"a","status":"success"}` + "\n"
	bad := "{not-json}\n"
	good2 := `{"timestamp":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","tool":"b","status":"success"}` + "\n"
	if err := os.WriteFile(path, []byte(good1+bad+good2), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	l, err := New(dir, 90)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	results, err := l.Query(Filter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (malformed line should be skipped)", len(results))
	}
}

// TestS5_AuditFailureBlocksCaller verifies that when the underlying file
// descriptor is closed (simulating a write failure), Record returns an error,
// signalling the caller must abort the operation. SDD S-5.
func TestS5_AuditFailureBlocksCaller(t *testing.T) {
	l, _ := newTestLogger(t)

	// Force close the internal file to simulate an I/O failure.
	l.mu.Lock()
	if l.file != nil {
		_ = l.file.Close()
	}
	l.mu.Unlock()

	e := makeEntry(time.Now().UTC(), "ssh_exec", "prod")
	err := l.Record(e)
	if err == nil {
		t.Error("expected Record to return error when file is closed, got nil")
	}
}

func TestNewRejectsNonPositiveRetentionWithoutDeleting(t *testing.T) {
	dir := t.TempDir()
	oldFile := filepath.Join(dir, "audit-2020-01-01.jsonl")
	if err := os.WriteFile(oldFile, []byte(`{}`+"\n"), 0600); err != nil {
		t.Fatalf("write old file: %v", err)
	}

	if _, err := New(dir, -1); err == nil {
		t.Fatal("expected New to reject negative retention")
	}
	if _, err := os.Stat(oldFile); err != nil {
		t.Fatalf("old audit file should not be deleted on invalid retention: %v", err)
	}
}

func TestRecordAfterCloseReturnsError(t *testing.T) {
	l, _ := newTestLogger(t)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err := l.Record(makeEntry(time.Now().UTC(), "ssh_exec", "prod"))
	if err == nil {
		t.Fatal("expected Record after Close to fail")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Fatalf("expected closed error, got %v", err)
	}
}

// TestS6_SecretsRedactedInLog verifies that secrets in ArgsRedacted are
// replaced before being written to disk. SDD S-6.
func TestS6_SecretsRedactedInLog(t *testing.T) {
	l, dir := newTestLogger(t)

	e := makeEntry(time.Now().UTC(), "ssh_exec", "prod")
	e.ArgsRedacted = `password=SECRET-MARKER-XYZ`

	if err := l.Record(e); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Verify through Query that the marker is gone.
	results, err := l.Query(Filter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if strings.Contains(results[0].ArgsRedacted, "SECRET-MARKER-XYZ") {
		t.Errorf("ArgsRedacted still contains secret marker: %q", results[0].ArgsRedacted)
	}
	if !strings.Contains(results[0].ArgsRedacted, "REDACTED") {
		t.Errorf("ArgsRedacted does not contain REDACTED: %q", results[0].ArgsRedacted)
	}

	// Also verify the raw file on disk does not contain the marker.
	today := time.Now().UTC().Format(dateLayout)
	raw, err := os.ReadFile(filepath.Join(dir, filePrefix+today+fileSuffix))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if strings.Contains(string(raw), "SECRET-MARKER-XYZ") {
		t.Errorf("raw log file on disk still contains secret marker")
	}
}

// TestS8_FileAndDirPermissions explicitly checks 0600 file and 0700 dir
// after Record. SDD S-8.
func TestS8_FileAndDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit-state")
	l, err := New(dir, 90)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	if err := l.Record(makeEntry(time.Now().UTC(), "test_tool", "srv")); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Directory mode.
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Errorf("dir mode = %04o, want 0700", dirInfo.Mode().Perm())
	}

	// File mode.
	today := time.Now().UTC().Format(dateLayout)
	fileInfo, err := os.Stat(filepath.Join(dir, filePrefix+today+fileSuffix))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if fileInfo.Mode().Perm() != 0600 {
		t.Errorf("file mode = %04o, want 0600", fileInfo.Mode().Perm())
	}
}

// TestNewReader_DoesNotTriggerRetention verifies that opening the directory
// in read-only mode for the CLI does NOT delete old files. The daemon owns
// retention; the CLI must never mutate the dir as a side-effect of a query.
func TestNewReader_DoesNotTriggerRetention(t *testing.T) {
	dir := t.TempDir()
	oldFile := filepath.Join(dir, "audit-2020-01-01.jsonl")
	if err := os.WriteFile(oldFile, []byte(`{}`+"\n"), 0600); err != nil {
		t.Fatalf("write old file: %v", err)
	}

	r, err := NewReader(dir)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer r.Close()

	if _, statErr := os.Stat(oldFile); statErr != nil {
		t.Errorf("NewReader must not delete old files: %v", statErr)
	}

	// Record on a read-only logger must fail (no file is open for writing).
	if err := r.Record(Entry{Tool: "x"}); err == nil {
		t.Error("Record on read-only logger should fail")
	}
}

// TestRetention verifies that files older than retentionDays are deleted on
// New. SDD §9.5.
func TestRetention(t *testing.T) {
	dir := t.TempDir()

	// Plant an old file.
	oldFile := filepath.Join(dir, "audit-2020-01-01.jsonl")
	if err := os.WriteFile(oldFile, []byte(`{}`+"\n"), 0600); err != nil {
		t.Fatalf("write old file: %v", err)
	}

	l, err := New(dir, 30)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	if _, statErr := os.Stat(oldFile); !os.IsNotExist(statErr) {
		t.Errorf("old audit file was not deleted by retention cleanup")
	}
}
