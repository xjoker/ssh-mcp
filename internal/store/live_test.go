package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore_LiveStateFiltersReapsAndDeletesProcess(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ssh-mcp.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Second)
	entries := []LiveEntry{
		{
			ProcessID:     "process-a",
			ResourceType:  LiveResourceSession,
			ResourceID:    "session-1",
			Server:        "prod",
			Kind:          "shell",
			PID:           101,
			MCPClient:     "stdio",
			StartedAt:     now.Add(-time.Minute),
			LastHeartbeat: now,
		},
		{
			ProcessID:     "process-b",
			ResourceType:  LiveResourceTunnel,
			ResourceID:    "tunnel-1",
			Server:        "prod",
			Kind:          "local",
			PID:           202,
			MCPClient:     "stdio",
			StartedAt:     now.Add(-time.Minute),
			LastHeartbeat: now.Add(-10 * time.Second),
		},
	}
	if err := st.ReplaceProcessLive("process-a", entries[:1]); err != nil {
		t.Fatalf("ReplaceProcessLive process-a: %v", err)
	}
	if err := st.ReplaceProcessLive("process-b", entries[1:]); err != nil {
		t.Fatalf("ReplaceProcessLive process-b: %v", err)
	}

	active, err := st.ListLive(now.Add(-5 * time.Second))
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(active) != 1 || active[0].ResourceID != "session-1" {
		t.Fatalf("active live rows = %#v, want only session-1", active)
	}

	if err := st.ReapLive(now.Add(-5 * time.Second)); err != nil {
		t.Fatalf("ReapLive: %v", err)
	}
	all, err := st.ListLive(time.Time{})
	if err != nil {
		t.Fatalf("ListLive after ReapLive: %v", err)
	}
	if len(all) != 1 || all[0].ResourceID != "session-1" {
		t.Fatalf("live rows after reap = %#v, want only session-1", all)
	}

	if err := st.DeleteProcessLive("process-a"); err != nil {
		t.Fatalf("DeleteProcessLive: %v", err)
	}
	all, err = st.ListLive(time.Time{})
	if err != nil {
		t.Fatalf("ListLive after DeleteProcessLive: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("live rows after process delete = %#v, want none", all)
	}
}

func TestStore_ReplaceProcessLiveReplacesOnlyThatProcess(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ssh-mcp.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC()
	first := LiveEntry{
		ProcessID:     "process-a",
		ResourceType:  LiveResourceConnection,
		ResourceID:    "prod",
		Server:        "prod",
		Kind:          "pooled",
		PID:           101,
		MCPClient:     "stdio",
		StartedAt:     now,
		LastHeartbeat: now,
	}
	other := first
	other.ProcessID = "process-b"
	other.ResourceID = "staging"
	other.Server = "staging"
	if err := st.ReplaceProcessLive("process-a", []LiveEntry{first}); err != nil {
		t.Fatalf("ReplaceProcessLive first: %v", err)
	}
	if err := st.ReplaceProcessLive("process-b", []LiveEntry{other}); err != nil {
		t.Fatalf("ReplaceProcessLive other: %v", err)
	}

	replacement := first
	replacement.ResourceID = "prod-2"
	if err := st.ReplaceProcessLive("process-a", []LiveEntry{replacement}); err != nil {
		t.Fatalf("ReplaceProcessLive replacement: %v", err)
	}

	entries, err := st.ListLive(time.Time{})
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("live entry count = %d, want 2", len(entries))
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry.ProcessID+":"+entry.ResourceID] = true
	}
	if !seen["process-a:prod-2"] || !seen["process-b:staging"] {
		t.Fatalf("live entries = %#v, want replacement and other process", entries)
	}
}
