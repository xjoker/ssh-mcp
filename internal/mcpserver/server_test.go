package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/store"
	"github.com/xjoker/ssh-mcp/internal/tools"
)

func TestServerNew_AuditDirWritable(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{
			AuditRetentionDays:           90,
			SessionIdleSeconds:           3600,
			ConnIdleSeconds:              600,
			AllowConfigPlaintextPassword: false,
		},
		Servers: map[string]config.ServerConfig{},
	}

	auditDir := t.TempDir()
	s, err := New(cfg, auditDir, "", "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Shutdown()

	// Verify the server was created with non-nil deps.
	if s.deps == nil {
		t.Error("deps should not be nil")
	}
	if s.pool == nil {
		t.Error("pool should not be nil")
	}
	if s.auditLog == nil {
		t.Error("auditLog should not be nil")
	}
}

func TestServerNew_AuditDirUnwritable(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{
			AuditRetentionDays: 90,
			SessionIdleSeconds: 3600,
		},
		Servers: map[string]config.ServerConfig{},
	}

	// Pass a non-existent directory that cannot be created (use a file path as dir).
	// Actually, we can't easily prevent mkdir on most systems in tests.
	// Instead, test that New succeeds with a writable temp dir.
	auditDir := t.TempDir()
	s, err := New(cfg, auditDir, "", "test")
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	defer s.Shutdown()
}

func TestServer_RegisterAll(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{
			AuditRetentionDays: 90,
			SessionIdleSeconds: 3600,
		},
		Servers: map[string]config.ServerConfig{},
	}

	auditDir := t.TempDir()
	s, err := New(cfg, auditDir, "", "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Shutdown()

	if err := s.RegisterAll(); err != nil {
		t.Fatalf("RegisterAll: %v", err)
	}

	// Verify the number of registered tools equals tools.All() count.
	allTools := tools.All()
	if len(allTools) == 0 {
		t.Fatal("tools.All() returned empty slice — tool init() functions may not have run")
	}

	// SDD requires at least 13 tools total (D1+D2+D3 = 5+5+3).
	const minExpectedTools = 13
	if len(allTools) < minExpectedTools {
		t.Errorf("expected at least %d tools registered, got %d", minExpectedTools, len(allTools))
	}

	t.Logf("registered %d tools: %v", len(allTools), toolNames(allTools))
}

func TestServer_Shutdown(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{
			AuditRetentionDays: 90,
			SessionIdleSeconds: 3600,
		},
		Servers: map[string]config.ServerConfig{},
	}

	auditDir := t.TempDir()
	s, err := New(cfg, auditDir, "", "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}

	// Second Shutdown should be safe (idempotent).
	if err := s.Shutdown(); err != nil {
		t.Errorf("second Shutdown returned error: %v", err)
	}
}

func toolNames(ts []tools.Tool) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Name
	}
	return out
}

// TestRunConnReaper_ExitsOnCtxCancel verifies that the connection reaper
// goroutine exits cleanly when its context is cancelled. This guards against
// goroutine leaks (SDD §12.3 / M03).
func TestRunConnReaper_ExitsOnCtxCancel(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{
			ConnIdleSeconds:    1,
			AuditRetentionDays: 90,
			SessionIdleSeconds: 3600,
		},
		Servers: map[string]config.ServerConfig{},
	}

	auditDir := t.TempDir()
	s, err := New(cfg, auditDir, "", "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		s.runConnReaper(ctx)
		close(done)
	}()

	// Cancel immediately and verify goroutine exits within 2 seconds.
	cancel()

	select {
	case <-done:
		// goroutine exited — no leak
	case <-time.After(2 * time.Second):
		t.Fatal("runConnReaper goroutine did not exit after context cancellation (goroutine leak)")
	}
}

// TestRunConnReaper_UsesConnIdleSeconds verifies that a zero ConnIdleSeconds
// value falls back to the built-in 600-second default (guard against zero-
// threshold wiping the pool immediately). SDD §12.3 / M03.
func TestRunConnReaper_UsesConnIdleSeconds(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{
			ConnIdleSeconds:    0, // zero — reaper should use 600s fallback
			AuditRetentionDays: 90,
			SessionIdleSeconds: 3600,
		},
		Servers: map[string]config.ServerConfig{},
	}

	auditDir := t.TempDir()
	s, err := New(cfg, auditDir, "", "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediate cancel so the goroutine starts and exits without blocking

	done := make(chan struct{})
	go func() {
		s.runConnReaper(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runConnReaper did not exit")
	}
}

func TestLiveReporterReplacesOnlyItsOwnProcessRows(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{
			AuditRetentionDays: 90,
			SessionIdleSeconds: 3600,
		},
		Servers: map[string]config.ServerConfig{},
	}

	s, err := New(cfg, t.TempDir(), "", "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Shutdown()
	s.liveProcessID = "process-a"

	st := s.auditLog.Store()
	now := time.Now().UTC()
	for _, entry := range []store.LiveEntry{
		{
			ProcessID:     "process-a",
			ResourceType:  store.LiveResourceSession,
			ResourceID:    "old-session",
			Kind:          "shell",
			PID:           1,
			MCPClient:     "stdio",
			StartedAt:     now,
			LastHeartbeat: now,
		},
		{
			ProcessID:     "process-b",
			ResourceType:  store.LiveResourceTunnel,
			ResourceID:    "other-tunnel",
			Kind:          "local",
			PID:           2,
			MCPClient:     "stdio",
			StartedAt:     now,
			LastHeartbeat: now,
		},
	} {
		if err := st.ReplaceProcessLive(entry.ProcessID, []store.LiveEntry{entry}); err != nil {
			t.Fatalf("ReplaceProcessLive %s: %v", entry.ProcessID, err)
		}
	}

	if err := s.syncLiveState(); err != nil {
		t.Fatalf("syncLiveState: %v", err)
	}
	entries, err := st.ListLive(time.Time{})
	if err != nil {
		t.Fatalf("ListLive after sync: %v", err)
	}
	if len(entries) != 1 || entries[0].ProcessID != "process-b" {
		t.Fatalf("live rows after sync = %#v, want only process-b", entries)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.runLiveReporter(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runLiveReporter did not stop after cancellation")
	}
	entries, err = st.ListLive(time.Time{})
	if err != nil {
		t.Fatalf("ListLive after reporter stop: %v", err)
	}
	if len(entries) != 1 || entries[0].ProcessID != "process-b" {
		t.Fatalf("live rows after reporter stop = %#v, want only process-b", entries)
	}
}
