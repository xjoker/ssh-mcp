package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveWithPreCommit_RenameFailureRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := `[settings]

[servers.existing]
host = "existing.example.com"
port = 22
user = "deploy"
auth = "agent"
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddServer(cfg, "new", ServerConfig{
		Host: "new.example.com",
		Port: 22,
		User: "deploy",
		Auth: "agent",
	}); err != nil {
		t.Fatal(err)
	}

	previousReplace := replaceConfigFile
	replaceConfigFile = func(_, _ string) error { return errors.New("replace denied") }
	t.Cleanup(func() { replaceConfigFile = previousReplace })

	committedExternalState := false
	err = SaveWithPreCommit(path, cfg, func() error {
		committedExternalState = true
		return nil
	}, func() error {
		committedExternalState = false
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "replace denied") {
		t.Fatalf("SaveWithPreCommit error = %v", err)
	}
	if committedExternalState {
		t.Fatal("rename failure did not roll back the pre-commit operation")
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != original {
		t.Fatal("rename failure changed the config")
	}
}

func TestSaveWithPreCommit_UnlockFailureReportsCommitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := `[settings]

[servers.existing]
host = "existing.example.com"
port = 22
user = "deploy"
auth = "agent"
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddServer(cfg, "new", ServerConfig{
		Host: "new.example.com",
		Port: 22,
		User: "deploy",
		Auth: "agent",
	}); err != nil {
		t.Fatal(err)
	}

	previousAcquire := acquireConfigSaveLock
	acquireConfigSaveLock = func(string) (func() error, error) {
		return func() error { return errors.New("unlock failed") }, nil
	}
	t.Cleanup(func() { acquireConfigSaveLock = previousAcquire })

	err = SaveWithPreCommit(path, cfg, func() error { return nil }, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "unlock failed") {
		t.Fatalf("SaveWithPreCommit error = %v", err)
	}
	if !IsSaveCommitted(err) {
		t.Fatalf("SaveWithPreCommit error = %T, want committed error", err)
	}
	loaded, loadErr := Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, ok := loaded.Servers["new"]; !ok {
		t.Fatal("config was not committed before unlock failure")
	}
}
