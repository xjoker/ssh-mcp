package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xjoker/ssh-mcp/internal/config"
)

func TestAddServer_RejectsDuplicateAndSetsName(t *testing.T) {
	cfg := mustLoad(t, minimalAgent)
	server := config.ServerConfig{
		Host: "staging.example.com",
		Port: 22,
		User: "deploy",
		Auth: "agent",
	}

	if err := config.AddServer(cfg, "staging", server); err != nil {
		t.Fatalf("AddServer: %v", err)
	}
	got := cfg.Servers["staging"]
	if got.Name != "staging" {
		t.Errorf("server Name = %q, want staging", got.Name)
	}
	if err := config.AddServer(cfg, "staging", server); err == nil {
		t.Fatal("AddServer duplicate: expected error")
	}
}

func TestBackup_CopiesConfigWithoutChangingSource(t *testing.T) {
	path := writeToml(t, minimalAgent)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read source config: %v", err)
	}

	backupPath, err := config.Backup(path)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if filepath.Dir(backupPath) != filepath.Dir(path) || !strings.HasPrefix(filepath.Base(backupPath), filepath.Base(path)+".backup-") {
		t.Fatalf("backup path = %q, want sibling timestamped backup", backupPath)
	}
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup config: %v", err)
	}
	if string(backup) != string(before) {
		t.Fatal("backup content differs from source")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read source after Backup: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("Backup changed source config")
	}
}

func TestUpsertRemoveAndSetServerPolicy(t *testing.T) {
	cfg := mustLoad(t, minimalAgent)
	server := config.ServerConfig{
		Host: "replacement.example.com",
		Port: 2222,
		User: "deploy",
		Auth: "agent",
	}

	if err := config.UpsertServer(cfg, "myserver", server); err != nil {
		t.Fatalf("UpsertServer: %v", err)
	}
	if got := cfg.Servers["myserver"].Host; got != "replacement.example.com" {
		t.Errorf("upserted host = %q", got)
	}
	if err := config.SetServerPolicy(cfg, "myserver", "restricted", []string{"^uptime$"}, []string{"reboot"}); err != nil {
		t.Fatalf("SetServerPolicy: %v", err)
	}
	got := cfg.Servers["myserver"]
	if got.Mode != "restricted" || len(got.AllowPatterns) != 1 || len(got.DenyPatterns) != 1 {
		t.Errorf("policy = %+v", got)
	}
	if err := config.RemoveServer(cfg, "myserver"); err != nil {
		t.Fatalf("RemoveServer: %v", err)
	}
	if _, ok := cfg.Servers["myserver"]; ok {
		t.Fatal("server remains after RemoveServer")
	}
	if err := config.RemoveServer(cfg, "myserver"); err == nil {
		t.Fatal("RemoveServer missing server: expected error")
	}
}

func TestSave_RoundTripsProxiesAndRejectsInvalidConfigWithoutReplacingFile(t *testing.T) {
	path := writeToml(t, `
[settings]

[servers.app]
host = "app.example.com"
user = "deploy"
auth = "agent"

[servers.jump]
host = "jump.example.com"
user = "deploy"
auth = "agent"

[proxies.edge]
type = "ssh"
server = "jump"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := config.SetServerPolicy(cfg, "app", "readonly", []string{"^uptime$"}, nil); err != nil {
		t.Fatalf("SetServerPolicy: %v", err)
	}
	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if _, ok := reloaded.Proxies["edge"]; !ok {
		t.Fatal("Save dropped proxy configuration")
	}
	if got := reloaded.Servers["app"].Mode; got != "readonly" {
		t.Errorf("saved policy mode = %q, want readonly", got)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before invalid Save: %v", err)
	}
	bad := reloaded.Servers["app"]
	bad.Host = ""
	reloaded.Servers["app"] = bad
	if err := config.Save(path, reloaded); err == nil {
		t.Fatal("Save invalid config: expected error")
	} else if !strings.Contains(err.Error(), "host is required") {
		t.Fatalf("Save invalid config error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after invalid Save: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("Save replaced config despite failed validation")
	}
}

func TestSave_RejectsConcurrentOnDiskChange(t *testing.T) {
	path := writeToml(t, minimalAgent)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	external := strings.Replace(minimalAgent, "example.com", "external.example.com", 1)
	if err := os.WriteFile(path, []byte(external), 0600); err != nil {
		t.Fatalf("external WriteFile: %v", err)
	}
	server := cfg.Servers["myserver"]
	server.Description = "local edit"
	if err := config.UpsertServer(cfg, "myserver", server); err != nil {
		t.Fatalf("UpsertServer: %v", err)
	}

	err = config.Save(path, cfg)
	if err == nil || !strings.Contains(err.Error(), "changed on disk") {
		t.Fatalf("Save error = %v, want changed-on-disk conflict", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if string(got) != external {
		t.Fatal("Save replaced a concurrent external change")
	}
}
