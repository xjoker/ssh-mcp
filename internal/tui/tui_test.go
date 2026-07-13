package tui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

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
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	view := model.View().Content
	if !strings.Contains(view, "Machines") || !strings.Contains(view, "existing") {
		t.Fatalf("initial view = %q, want configured server", model.View().Content)
	}
	assertEnglishOnly(t, view)
	for _, forbidden := range []string{"Audit", "Live", "Trust", "Credentials", "Connect", "Test connection"} {
		if strings.Contains(view, forbidden) {
			t.Fatalf("machine manager unexpectedly exposes %q in %q", forbidden, view)
		}
	}

	model.openAdd()
	assertEnglishOnly(t, model.View().Content)
	values := []string{
		"new-server", "new.example", "deploy", "22", "agent", "", "", "", "", "staging",
	}
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
	if !ok || server.Description != "staging" {
		t.Fatalf("saved server = %+v, want form values", server)
	}
}

func TestMachineDeleteCreatesBackup(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`
[settings]

[servers.existing]
host = "existing.example"
user = "deploy"
auth = "agent"
`), 0600); err != nil {
		t.Fatal(err)
	}
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.openDeleteConfirmation()
	assertEnglishOnly(t, model.View().Content)
	model.executeConfirmation(model.confirmation)
	if model.err != "" {
		t.Fatalf("delete machine: %s", model.err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Servers["existing"]; ok {
		t.Fatal("deleted machine remains in config")
	}
	backups, err := filepath.Glob(configPath + ".backup-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("backup count = %d, want 1", len(backups))
	}
}

func TestMachineEditUpdatesConfiguration(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`
[settings]

[servers.existing]
host = "old.example"
user = "deploy"
auth = "agent"
allowed_paths = ["/srv/app"]
mode = "readonly"
allow_patterns = ["^uptime$"]
`), 0600); err != nil {
		t.Fatal(err)
	}
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.openEdit()
	model.form.fields[fieldHost].SetValue("new.example")
	model.form.fields[fieldDescription].SetValue("production")
	model.saveForm()
	if model.err != "" {
		t.Fatalf("edit machine: %s", model.err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	machine := loaded.Servers["existing"]
	if machine.Host != "new.example" || machine.Description != "production" {
		t.Fatalf("edited machine = %+v", machine)
	}
	if len(machine.AllowedPaths) != 1 || machine.AllowedPaths[0] != "/srv/app" {
		t.Fatalf("edit discarded unmanaged fields: %+v", machine.AllowedPaths)
	}
	if machine.Mode != "readonly" || len(machine.AllowPatterns) != 1 || machine.AllowPatterns[0] != "^uptime$" {
		t.Fatalf("edit discarded command policy: %+v", machine)
	}
}

func TestMachineAddPreservesConcurrentConfigurationChange(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "existing.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`
[settings]

[servers.existing]
host = "external.example"
user = "deploy"
auth = "agent"

[servers.external]
host = "new-from-disk.example"
user = "ops"
auth = "agent"
`), 0600); err != nil {
		t.Fatal(err)
	}

	model.openAdd()
	setFormValues(model, []string{"added", "added.example", "ops", "22", "agent", "", "", "", "", ""})
	model.saveForm()
	if model.err != "" {
		t.Fatalf("save form error = %s", model.err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Servers["existing"].Host != "external.example" {
		t.Fatal("add overwrote an external edit")
	}
	if _, ok := loaded.Servers["external"]; !ok {
		t.Fatal("add dropped an externally added machine")
	}
	if _, ok := loaded.Servers["added"]; !ok {
		t.Fatal("form machine was not added")
	}
}

func TestMachineEditUsesLatestUnmanagedFields(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "old.example"
user = "deploy"
auth = "agent"
allowed_paths = ["/old"]
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.openEdit()
	if err := os.WriteFile(configPath, []byte(`
[settings]

[servers.existing]
host = "old.example"
user = "deploy"
auth = "agent"
allowed_paths = ["/external"]
`), 0600); err != nil {
		t.Fatal(err)
	}
	model.form.fields[fieldHost].SetValue("edited.example")
	model.saveForm()
	if model.err != "" {
		t.Fatalf("save form error = %s", model.err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	server := loaded.Servers["existing"]
	if server.Host != "edited.example" || len(server.AllowedPaths) != 1 || server.AllowedPaths[0] != "/external" {
		t.Fatalf("saved server = %+v, want form edit plus latest unmanaged fields", server)
	}
}

func TestAuthenticationChangeDoesNotReactivateHiddenCredentialReferences(t *testing.T) {
	t.Run("key to password", func(t *testing.T) {
		configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "key"
key_path = "~/.ssh/id_ed25519"
key_passphrase = "keychain:legacy:old-key"
`)
		model, err := New(Options{ConfigPath: configPath})
		if err != nil {
			t.Fatal(err)
		}
		model.openEdit()
		model.form.fields[fieldAuth].SetValue("password")
		model.saveForm()
		if model.err != "" {
			t.Fatal(model.err)
		}
		loaded, err := config.Load(configPath)
		if err != nil {
			t.Fatal(err)
		}
		password := loaded.Servers["existing"].Password
		if password.Service != "ssh-mcp" || password.Account != "ssh-password:existing" {
			t.Fatalf("password reference = %+v, want fresh machine-scoped keychain reference", password)
		}
	})

	t.Run("password to key", func(t *testing.T) {
		configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "keychain:ssh-mcp:ssh-password:existing"
`)
		model, err := New(Options{ConfigPath: configPath})
		if err != nil {
			t.Fatal(err)
		}
		model.openEdit()
		model.form.fields[fieldAuth].SetValue("key")
		model.form.fields[fieldKeyPath].SetValue("~/.ssh/new_key")
		model.saveForm()
		if model.err != "" {
			t.Fatal(model.err)
		}
		loaded, err := config.Load(configPath)
		if err != nil {
			t.Fatal(err)
		}
		server := loaded.Servers["existing"]
		if !server.KeyPassphrase.IsZero() || !server.Password.IsZero() {
			t.Fatalf("credential references = key:%+v password:%+v, want both cleared", server.KeyPassphrase, server.Password)
		}
	})
}

func TestViewSanitizesTerminalControlCharacters(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "agent"
description = "safe"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	server := model.config.Servers["existing"]
	server.Description = "visible\x1b]52;c;payload\aend\nnext"
	model.config.Servers["existing"] = server
	model.options.ConfigPath = "config\x1b[2J.toml"
	model.list.SetItems(model.machineItems())
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	view := model.View().Content
	if strings.Contains(view, "config\x1b[2J") || strings.Contains(view, "visible\x1b]52") || strings.Contains(view, "payload\aend") || strings.Contains(view, "\nnext") {
		t.Fatalf("view contains terminal control sequence: %q", view)
	}
}

func TestReloadPreservesAppliedFilter(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.alpha]
host = "alpha.example"
user = "deploy"
auth = "agent"

[servers.beta]
host = "beta.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.list.SetFilterText("alpha")
	model.reload()
	items := model.list.VisibleItems()
	if len(items) != 1 || items[0].(row).key != "alpha" {
		t.Fatalf("visible items after reload = %+v, want filtered alpha", items)
	}
}

func TestMachineFormFitsEightyColumnTerminal(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "existing.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	model.openAdd()
	for _, line := range strings.Split(model.View().Content, "\n") {
		if width := lipgloss.Width(line); width > 80 {
			t.Fatalf("form line width = %d, want <= 80: %q", width, line)
		}
	}
}

func TestWindowResizeUpdatesBaseLayoutWhileFormIsOpen(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "existing.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	model.openAdd()
	model.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	model.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if got, want := model.list.Width(), 54; got != want {
		t.Fatalf("list width after closing resized form = %d, want %d", got, want)
	}
}

func writeTUIConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setFormValues(model *Model, values []string) {
	for index, value := range values {
		model.form.fields[index].SetValue(value)
	}
}

func assertEnglishOnly(t *testing.T, content string) {
	t.Helper()
	if match := regexp.MustCompile(`[\p{Han}]`).FindString(content); match != "" {
		t.Fatalf("UI contains non-English character %q in %q", match, content)
	}
}
