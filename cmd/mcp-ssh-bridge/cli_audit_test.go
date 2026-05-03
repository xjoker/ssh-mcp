package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/audit"
)

// TestParseSinceRelative checks relative time parsing.
func TestParseSinceRelative(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
	}{
		{"1h", false},
		{"24h", false},
		{"7d", false},
		{"30m", false},
		{"", false},
		{"2026-05-01T00:00:00Z", false},
		{"2026-05-01", false},
		{"notavalue", true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			_, err := parseSince(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("parseSince(%q): expected error, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("parseSince(%q): unexpected error: %v", tc.input, err)
			}
		})
	}
}

// TestParseSinceApproxDuration verifies that "1h" results in a time roughly
// 1 hour in the past.
func TestParseSinceApproxDuration(t *testing.T) {
	before := time.Now().UTC()
	got, err := parseSince("1h")
	after := time.Now().UTC()
	if err != nil {
		t.Fatal(err)
	}
	expected := before.Add(-time.Hour)
	if got.Before(expected.Add(-5*time.Second)) || got.After(after) {
		t.Errorf("parseSince(\"1h\") = %v, want approximately %v", got, expected)
	}
}

// TestAuditQueryIntegration writes two entries to a temp audit dir and verifies
// that auditQueryCmd returns them via --since 1h.
func TestAuditQueryIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("MCP_SSH_BRIDGE_AUDIT_DIR", tmpDir)

	// Write two entries via audit.New + Record.
	logger, err := audit.New(tmpDir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	entries := []audit.Entry{
		{
			Timestamp: time.Now().UTC().Add(-30 * time.Minute),
			Tool:      "ssh_exec",
			Server:    "web01",
			ExitCode:  0,
		},
		{
			Timestamp: time.Now().UTC().Add(-10 * time.Minute),
			Tool:      "sftp_op",
			Server:    "db01",
			ExitCode:  1,
			ErrorCode: "SFTP_ERR",
		},
	}
	for _, e := range entries {
		if err := logger.Record(e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	logger.Close()

	// Capture stdout.
	origStdout := os.Stdout
	r, w, pipErr := os.Pipe()
	if pipErr != nil {
		t.Fatal(pipErr)
	}
	os.Stdout = w

	code := auditQueryCmd([]string{"--since", "1h", "--limit", "100"})

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}

	if code != 0 {
		t.Fatalf("auditQueryCmd returned %d, want 0\nstdout:\n%s", code, buf.String())
	}

	out := buf.String()
	if !strings.Contains(out, "ssh_exec") {
		t.Errorf("output missing 'ssh_exec':\n%s", out)
	}
	if !strings.Contains(out, "sftp_op") {
		t.Errorf("output missing 'sftp_op':\n%s", out)
	}
}

// TestAuditQueryServerFilter verifies that --server filters results correctly.
func TestAuditQueryServerFilter(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("MCP_SSH_BRIDGE_AUDIT_DIR", tmpDir)

	logger, err := audit.New(tmpDir, 90)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	for _, e := range []audit.Entry{
		{Timestamp: time.Now().UTC(), Tool: "ssh_exec", Server: "web01"},
		{Timestamp: time.Now().UTC(), Tool: "ssh_exec", Server: "db01"},
	} {
		if err := logger.Record(e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	logger.Close()

	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	auditQueryCmd([]string{"--server", "web01", "--limit", "10"})

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	io.Copy(&buf, r) //nolint
	out := buf.String()

	if !strings.Contains(out, "web01") {
		t.Errorf("filtered output should contain 'web01':\n%s", out)
	}
	if strings.Contains(out, "db01") {
		t.Errorf("filtered output should NOT contain 'db01':\n%s", out)
	}
}
