package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/xjoker/ssh-mcp/internal/config"
)

func TestNewDisplaysConfiguredServerAndSavesServerForm(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`
[settings]

[servers.existing]
host = "existing.example"
user = "deploy"
auth = "agent"
`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	model, err := New(Options{ConfigPath: configPath, AuditDir: filepath.Join(dir, "audit"), KnownHostsPath: filepath.Join(dir, "known_hosts")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if !strings.Contains(model.View().Content, "existing") {
		t.Fatalf("initial view = %q, want configured server", model.View().Content)
	}

	model.openAdd()
	values := []string{"new-server", "new.example", "deploy", "22", "agent", "readonly", "^uptime$", "", "staging"}
	for index, value := range values {
		model.form.fields[index].SetValue(value)
	}
	model.saveForm()
	if model.err != "" {
		t.Fatalf("save form error = %s", model.err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load saved config: %v", err)
	}
	server, ok := loaded.Servers["new-server"]
	if !ok || server.Mode != "readonly" || server.Description != "staging" {
		t.Fatalf("saved server = %+v, want form values", server)
	}
}
