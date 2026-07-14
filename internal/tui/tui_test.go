package tui

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/knownhosts"
)

type fakeWindowChanger struct {
	mu    sync.Mutex
	calls [][2]int
}

func (fake *fakeWindowChanger) WindowChange(height, width int) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls = append(fake.calls, [2]int{height, width})
	return nil
}

func (fake *fakeWindowChanger) snapshot() [][2]int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([][2]int(nil), fake.calls...)
}

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
	if !strings.Contains(view, "OPERATIONS CONSOLE") || !strings.Contains(view, "existing") {
		t.Fatalf("initial view = %q, want configured server", model.View().Content)
	}
	assertEnglishOnly(t, view)
	for _, forbidden := range []string{"Audit", "Live"} {
		if strings.Contains(view, forbidden) {
			t.Fatalf("machine manager unexpectedly exposes %q in %q", forbidden, view)
		}
	}
	for _, expected := range []string{"OPERATIONS CONSOLE", "ADDRESS", "AUTH", "Policy", "STATE", "actions"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("operations console missing %q in %q", expected, view)
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

type fakeCredentialStore struct {
	values      map[string][]byte
	deleteCalls []string
	statusErr   error
	setErr      error
	onSet       func()
}

func (store *fakeCredentialStore) Status(_ context.Context, ref config.CredRef) (credentialState, error) {
	if store.statusErr != nil {
		return credentialMissing, store.statusErr
	}
	if _, ok := store.values[ref.Service+"/"+ref.Account]; ok {
		return credentialStored, nil
	}
	return credentialMissing, nil
}

func (store *fakeCredentialStore) Set(service, account string, secret []byte) error {
	if store.setErr != nil {
		return store.setErr
	}
	if store.values == nil {
		store.values = make(map[string][]byte)
	}
	store.values[service+"/"+account] = append([]byte(nil), secret...)
	if store.onSet != nil {
		store.onSet()
	}
	return nil
}

func (store *fakeCredentialStore) Delete(service, account string) error {
	store.deleteCalls = append(store.deleteCalls, service+"/"+account)
	delete(store.values, service+"/"+account)
	return nil
}

func TestPasswordManagerStoresSecretInKeychainWithoutWritingPlaintext(t *testing.T) {
	const password = "correct horse battery staple"
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
	store := &fakeCredentialStore{}
	model.credentials = store
	model.openPasswordManager()
	model.credentialGenerations["existing"] = 7
	model.connectionGenerations["existing"] = 9
	model.connectionStates["existing"] = connectionState{phase: connectionReady}
	model.password.fields[0].SetValue(password)
	model.password.fields[1].SetValue(password)
	model.savePassword()
	if model.err != "" {
		t.Fatalf("save password: %s", model.err)
	}
	if model.credentialGenerations["existing"] <= 7 {
		t.Fatal("password save did not invalidate an in-flight credential check")
	}
	if model.connectionGenerations["existing"] <= 9 || model.connectionStates["existing"].phase != connectionUntested {
		t.Fatal("password save did not invalidate the previous connection result")
	}
	if got := string(store.values["ssh-mcp/ssh-password:existing"]); got != password {
		t.Fatalf("keychain value = %q, want supplied password", got)
	}
	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), password) || strings.Contains(model.View().Content, password) {
		t.Fatal("password leaked into config or rendered TUI")
	}
	if !strings.Contains(string(contents), "keychain:ssh-mcp:ssh-password:existing") {
		t.Fatalf("config missing canonical keychain reference: %s", contents)
	}
}

func TestPasswordManagerPreservesOriginalReferenceWhenConfigSaveFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce POSIX directory write permissions")
	}
	const password = "correct horse battery staple"
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "env:SSH_MCP_TEST_PASSWORD"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(configPath)
	store := &fakeCredentialStore{onSet: func() {
		if err := os.Chmod(directory, 0500); err != nil {
			t.Error(err)
		}
	}}
	model.credentials = store
	model.openPasswordManager()
	model.password.fields[0].SetValue(password)
	model.password.fields[1].SetValue(password)
	t.Cleanup(func() { _ = os.Chmod(directory, 0700) })

	model.savePassword()
	if !strings.Contains(model.err, "Password save failed:") {
		t.Fatalf("error = %q, want visible configuration save failure", model.err)
	}
	if got := string(store.values["ssh-mcp/ssh-password:existing"]); got != password {
		t.Fatalf("stored credential = %q, want newly supplied password", got)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Servers["existing"].Password.Raw; got != "env:SSH_MCP_TEST_PASSWORD" {
		t.Fatalf("password reference = %q, want original env reference", got)
	}
}

func TestPasswordManagerDoesNotChangeConfigWhenKeychainSetFails(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "env:SSH_MCP_TEST_PASSWORD"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.credentials = &fakeCredentialStore{setErr: errors.New("keychain unavailable")}
	model.openPasswordManager()
	model.password.fields[0].SetValue("replacement secret")
	model.password.fields[1].SetValue("replacement secret")
	model.savePassword()
	if !strings.Contains(model.err, "keychain unavailable") {
		t.Fatalf("error = %q, want keychain failure", model.err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Servers["existing"].Password.Raw; got != "env:SSH_MCP_TEST_PASSWORD" {
		t.Fatalf("password reference = %q, want original env reference", got)
	}
}

func TestPasswordManagerDoesNotOverwriteConcurrentConfigChange(t *testing.T) {
	const password = "replacement secret"
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "env:SSH_MCP_TEST_PASSWORD"
description = "original"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	var hookErr error
	store := &fakeCredentialStore{onSet: func() {
		latest, err := config.Load(configPath)
		if err != nil {
			hookErr = err
			return
		}
		machine := latest.Servers["existing"]
		machine.Description = "external update"
		if err := config.UpsertServer(latest, "existing", machine); err != nil {
			hookErr = err
			return
		}
		hookErr = config.Save(configPath, latest)
	}}
	model.credentials = store
	model.openPasswordManager()
	model.password.fields[0].SetValue(password)
	model.password.fields[1].SetValue(password)
	model.savePassword()
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if !strings.Contains(strings.ToLower(model.err), "changed") {
		t.Fatalf("error = %q, want concurrent-change failure", model.err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	machine := loaded.Servers["existing"]
	if machine.Description != "external update" || machine.Password.Raw != "env:SSH_MCP_TEST_PASSWORD" {
		t.Fatalf("machine after concurrent update = %+v, want external description and original credential reference", machine)
	}
	if got := string(store.values["ssh-mcp/ssh-password:existing"]); got != password {
		t.Fatalf("stored credential = %q, want newly supplied password", got)
	}
}

func TestPasswordManagerPreservesExistingCustomKeychainReference(t *testing.T) {
	const password = "replacement secret"
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "keychain:custom-service:custom-account"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeCredentialStore{}
	model.credentials = store
	model.openPasswordManager()
	model.password.fields[0].SetValue(password)
	model.password.fields[1].SetValue(password)
	model.savePassword()
	if model.err != "" {
		t.Fatalf("save password: %s", model.err)
	}
	if got := string(store.values["custom-service/custom-account"]); got != password {
		t.Fatalf("custom keychain value = %q, want supplied password", got)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	ref := loaded.Servers["existing"].Password
	if ref.Service != "custom-service" || ref.Account != "custom-account" {
		t.Fatalf("credential reference = %+v, want existing custom keychain reference", ref)
	}
}

func TestPasswordManagerDetectsConcurrentCustomKeychainReferenceChange(t *testing.T) {
	const password = "replacement secret"
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "keychain:custom-service:old-account"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	var hookErr error
	store := &fakeCredentialStore{onSet: func() {
		latest, err := config.Load(configPath)
		if err != nil {
			hookErr = err
			return
		}
		newRef, err := config.ParseCredRef("keychain:custom-service:new-account")
		if err != nil {
			hookErr = err
			return
		}
		machine := latest.Servers["existing"]
		machine.Password = newRef
		if err := config.UpsertServer(latest, "existing", machine); err != nil {
			hookErr = err
			return
		}
		hookErr = config.Save(configPath, latest)
	}}
	model.credentials = store
	model.openPasswordManager()
	model.password.fields[0].SetValue(password)
	model.password.fields[1].SetValue(password)
	model.savePassword()
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if !strings.Contains(strings.ToLower(model.err), "changed") {
		t.Fatalf("error = %q, want changed-reference failure", model.err)
	}
	if model.message != "" {
		t.Fatalf("success message = %q, want none after concurrent reference change", model.message)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	ref := loaded.Servers["existing"].Password
	if ref.Service != "custom-service" || ref.Account != "new-account" {
		t.Fatalf("credential reference = %+v, want concurrent new-account reference preserved", ref)
	}
	if got := string(store.values["custom-service/old-account"]); got != password {
		t.Fatalf("old account credential = %q, want supplied password retained without false success", got)
	}
}

func TestPasswordDeleteRequiresExplicitConfirmation(t *testing.T) {
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
	store := &fakeCredentialStore{values: map[string][]byte{"ssh-mcp/ssh-password:existing": []byte("secret")}}
	model.credentials = store
	model.openPasswordManager()
	model.Update(tea.KeyPressMsg{Code: 'd', Mod: tea.ModCtrl})
	if model.confirmation == nil || !strings.Contains(strings.ToLower(model.confirmation.prompt), "cannot be recovered") {
		t.Fatalf("confirmation = %+v, want explicit irreversible delete warning", model.confirmation)
	}
	if _, ok := store.values["ssh-mcp/ssh-password:existing"]; !ok {
		t.Fatal("Ctrl+D deleted the password before confirmation")
	}
	model.Update(tea.KeyPressMsg{Code: 'x', Text: "x"})
	if model.confirmation == nil {
		t.Fatal("an unrelated key dismissed the delete confirmation")
	}
	model.Update(tea.KeyPressMsg{Code: 'n', Text: "n"})
	if _, ok := store.values["ssh-mcp/ssh-password:existing"]; !ok {
		t.Fatal("cancelling deleted the password")
	}

	model.Update(tea.KeyPressMsg{Code: 'd', Mod: tea.ModCtrl})
	deleteGeneration := model.credentialGenerations["existing"]
	model.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	if _, ok := store.values["ssh-mcp/ssh-password:existing"]; ok {
		t.Fatal("confirmed delete retained the password")
	}
	if model.credentialGenerations["existing"] <= deleteGeneration {
		t.Fatal("password delete did not invalidate an in-flight credential check")
	}
}

func TestPasswordDeleteUsesCurrentConfiguredCredentialReference(t *testing.T) {
	t.Run("custom keychain reference", func(t *testing.T) {
		configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "keychain:custom-service:custom-account"
`)
		model, err := New(Options{ConfigPath: configPath})
		if err != nil {
			t.Fatal(err)
		}
		store := &fakeCredentialStore{values: map[string][]byte{
			"custom-service/custom-account": []byte("custom"),
			"ssh-mcp/ssh-password:existing": []byte("canonical-must-remain"),
		}}
		model.credentials = store
		model.openPasswordManager()
		model.Update(tea.KeyPressMsg{Code: 'd', Mod: tea.ModCtrl})
		model.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
		if got := strings.Join(store.deleteCalls, ","); got != "custom-service/custom-account" {
			t.Fatalf("Delete calls = %q, want configured custom keychain reference", got)
		}
		if _, ok := store.values["ssh-mcp/ssh-password:existing"]; !ok {
			t.Fatal("delete removed a guessed canonical keychain entry")
		}
	})

	for _, test := range []struct {
		name     string
		settings string
		password string
		wantText string
	}{
		{name: "environment", password: "env:SSH_TEST_PASSWORD", wantText: "externally managed"},
		{name: "plaintext", settings: "allow_config_plaintext_password = true", password: "plaintext:local-secret", wantText: "externally managed"},
		{name: "not stored", password: "", wantText: "not stored"},
	} {
		t.Run(test.name, func(t *testing.T) {
			passwordLine := ""
			authMode := "password"
			if test.password != "" {
				passwordLine = "password = \"" + test.password + "\""
			} else {
				authMode = "agent"
			}
			configPath := writeTUIConfig(t, "\n[settings]\n"+test.settings+"\n\n[servers.existing]\nhost = \"host.example\"\nuser = \"deploy\"\nauth = \""+authMode+"\"\n"+passwordLine+"\n")
			model, err := New(Options{ConfigPath: configPath})
			if err != nil {
				t.Fatal(err)
			}
			store := &fakeCredentialStore{values: map[string][]byte{"ssh-mcp/ssh-password:existing": []byte("must-remain")}}
			model.credentials = store
			if test.password == "" {
				model.password = &passwordState{machine: "existing"}
				model.openPasswordDeleteConfirmation()
			} else {
				model.openPasswordManager()
				model.Update(tea.KeyPressMsg{Code: 'd', Mod: tea.ModCtrl})
			}
			if model.confirmation != nil {
				model.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
			}
			if len(store.deleteCalls) != 0 {
				t.Fatalf("Delete calls = %v, want none", store.deleteCalls)
			}
			if !strings.Contains(strings.ToLower(model.err), test.wantText) {
				t.Fatalf("error = %q, want %q", model.err, test.wantText)
			}
			if _, ok := store.values["ssh-mcp/ssh-password:existing"]; !ok {
				t.Fatal("non-keychain delete removed a guessed canonical entry")
			}
		})
	}
}

func TestPasswordDeleteAbortsWhenCredentialReferenceChangesAfterConfirmation(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "keychain:old-service:old-account"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeCredentialStore{values: map[string][]byte{
		"old-service/old-account": []byte("old"),
		"new-service/new-account": []byte("new"),
	}}
	model.credentials = store
	model.openPasswordManager()
	model.openPasswordDeleteConfirmation()
	if model.confirmation == nil {
		t.Fatal("password delete confirmation was not opened")
	}

	latest, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	machine := latest.Servers["existing"]
	machine.Password, err = config.ParseCredRef("keychain:new-service:new-account")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.UpsertServer(latest, "existing", machine); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(configPath, latest); err != nil {
		t.Fatal(err)
	}

	model.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	if len(store.deleteCalls) != 0 {
		t.Fatalf("credential changed after confirmation but delete calls = %v", store.deleteCalls)
	}
	if !strings.Contains(strings.ToLower(model.err), "changed") {
		t.Fatalf("delete error = %q, want changed-reference explanation", model.err)
	}
}

func TestMachineActionMenuOffersOperationalAndManagementActions(t *testing.T) {
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
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model.openActionMenu()
	view := model.View().Content
	for _, expected := range []string{"Test connection", "Connect shell", "Edit machine", "Manage password", "Trust host key", "Delete machine"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("action menu missing %q in %q", expected, view)
		}
	}
	assertEnglishOnly(t, view)
}

func TestConnectionTestTransitionsFromTestingToReady(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.testConnection = func(context.Context, string, *config.Config) error { return nil }
	command := model.startConnectionTest("existing")
	if model.connectionStates["existing"].phase != connectionTesting {
		t.Fatal("connection state did not enter Testing")
	}
	message := command()
	model.Update(message)
	if model.connectionStates["existing"].phase != connectionReady {
		t.Fatalf("connection state = %+v, want Ready", model.connectionStates["existing"])
	}
}

func TestConnectionTestIgnoresOutOfOrderAndDeletedMachineResults(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.testConnection = func(context.Context, string, *config.Config) error { return errors.New("old failure") }
	oldCommand := model.startConnectionTest("existing")
	model.testConnection = func(context.Context, string, *config.Config) error { return nil }
	newCommand := model.startConnectionTest("existing")
	model.Update(newCommand())
	model.Update(oldCommand())
	if got := model.connectionStates["existing"].phase; got != connectionReady {
		t.Fatalf("connection state = %q, want newest Ready result", got)
	}
	delete(model.config.Servers, "existing")
	model.Update(connectionResultMsg{name: "existing", generation: model.connectionGenerations["existing"], err: errors.New("late failure")})
	if got := model.connectionStates["existing"].phase; got != connectionReady {
		t.Fatalf("deleted machine accepted a late result: %q", got)
	}
}

func TestMachineEditInvalidatesInFlightConnectionTest(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "old.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.testConnection = func(context.Context, string, *config.Config) error { return errors.New("old endpoint failed") }
	oldCommand := model.startConnectionTest("existing")
	model.openEdit()
	model.form.fields[fieldHost].SetValue("new.example")
	model.saveForm()
	if model.err != "" {
		t.Fatal(model.err)
	}
	model.Update(oldCommand())
	if got := model.connectionStates["existing"].phase; got != connectionUntested {
		t.Fatalf("connection state after stale result = %q, want Untested", got)
	}
}

func TestReloadInvalidatesInFlightConnectionTest(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "old.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.testConnection = func(context.Context, string, *config.Config) error { return nil }
	oldCommand := model.startConnectionTest("existing")

	latest, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	machine := latest.Servers["existing"]
	machine.Host = "new.example"
	if err := config.UpsertServer(latest, "existing", machine); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(configPath, latest); err != nil {
		t.Fatal(err)
	}

	model.reload()
	if model.err != "" {
		t.Fatal(model.err)
	}
	model.Update(oldCommand())
	if got := model.connectionStates["existing"].phase; got != connectionUntested {
		t.Fatalf("connection state after reload and stale result = %q, want Untested", got)
	}
}

func TestFormAndPasswordErrorsAreVisibleInTheirOverlays(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "keychain:ssh-mcp:ssh-password:existing"
`)

	t.Run("machine form", func(t *testing.T) {
		model, err := New(Options{ConfigPath: configPath})
		if err != nil {
			t.Fatal(err)
		}
		model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		model.openEdit()
		model.form.fields[fieldPort].SetValue("invalid")
		model.saveForm()
		view := model.View().Content
		if !strings.Contains(view, "Port must be an integer") {
			t.Fatalf("form error is not visible in overlay: %q", view)
		}
	})

	t.Run("password form", func(t *testing.T) {
		model, err := New(Options{ConfigPath: configPath})
		if err != nil {
			t.Fatal(err)
		}
		model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		model.openPasswordManager()
		model.password.fields[0].SetValue("one")
		model.password.fields[1].SetValue("two")
		model.savePassword()
		view := model.View().Content
		if !strings.Contains(view, "Passwords do not match") {
			t.Fatalf("password error is not visible in overlay: %q", view)
		}
	})
}

func TestConnectActionLeavesTUIForSelectedMachine(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	_, command := model.Update(tea.KeyPressMsg{Code: 'c', Text: "c"})
	if model.connectTarget != "existing" || command == nil {
		t.Fatalf("connect target = %q command=%v, want selected machine and quit command", model.connectTarget, command)
	}
}

func TestConnectionClosedMessageSanitizesTerminalControls(t *testing.T) {
	message := connectionClosedMessage(errors.New("dial bad\x1b]52;c;payload\a host\nnext"))
	if strings.ContainsAny(message, "\x1b\a\n") || !strings.Contains(message, "dial bad") {
		t.Fatalf("connection message = %q, want visible text without terminal controls", message)
	}
}

func TestTerminalResizeWatcherSendsOnlyChangesAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	processed := make(chan struct{}, 4)
	sizes := [][2]int{{80, 24}, {100, 30}, {100, 30}}
	index := 0
	getSize := func() (int, int, error) {
		size := sizes[index]
		index++
		processed <- struct{}{}
		return size[0], size[1], nil
	}
	remote := &fakeWindowChanger{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchTerminalResize(ctx, ticks, getSize, remote, 80, 24)
	}()

	for range sizes {
		ticks <- time.Now()
		<-processed
	}
	if got := remote.snapshot(); len(got) != 1 || got[0] != [2]int{30, 100} {
		t.Fatalf("WindowChange calls = %v, want one changed size [30 100]", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("resize watcher did not stop after cancellation")
	}
	time.Sleep(10 * time.Millisecond)
	if got := remote.snapshot(); len(got) != 1 {
		t.Fatalf("WindowChange calls after stop = %v, want no more calls", got)
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
auth = "password"
password = "keychain:ssh-mcp:ssh-password:existing"
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
	if !strings.Contains(model.message, "Stored credential was retained") {
		t.Fatalf("delete message = %q, want retained credential notice", model.message)
	}
}

func TestMachineDeleteAbortsWhenTargetChangesAfterConfirmation(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "old.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.openDeleteConfirmation()
	confirmation := model.confirmation

	latest, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	machine := latest.Servers["existing"]
	machine.Host = "replacement.example"
	if err := config.UpsertServer(latest, "existing", machine); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(configPath, latest); err != nil {
		t.Fatal(err)
	}

	model.executeConfirmation(confirmation)
	if !strings.Contains(strings.ToLower(model.err), "changed") {
		t.Fatalf("delete error = %q, want changed-target explanation", model.err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Servers["existing"].Host; got != "replacement.example" {
		t.Fatalf("replacement machine host = %q, want preserved replacement.example", got)
	}
	backups, err := filepath.Glob(configPath + ".backup-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("backup count = %d, want none before target identity is confirmed", len(backups))
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
	model.form.fields[fieldUser].SetValue("operator")
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
	if machine.Host != "new.example" || machine.User != "operator" || machine.Description != "production" {
		t.Fatalf("edited machine = %+v", machine)
	}
	if len(machine.AllowedPaths) != 1 || machine.AllowedPaths[0] != "/srv/app" {
		t.Fatalf("edit discarded unmanaged fields: %+v", machine.AllowedPaths)
	}
	if machine.Mode != "readonly" || len(machine.AllowPatterns) != 1 || machine.AllowPatterns[0] != "^uptime$" {
		t.Fatalf("edit discarded command policy: %+v", machine)
	}
}

func TestSelectedPasswordStatusReportsStoredAndMissing(t *testing.T) {
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
	store := &fakeCredentialStore{values: map[string][]byte{"ssh-mcp/ssh-password:existing": []byte("secret")}}
	model.credentials = store
	message := model.checkSelectedCredential()()
	model.Update(message)
	if got := model.credentialStates["existing"]; got != credentialStored {
		t.Fatalf("credential state = %q, want Stored", got)
	}
	delete(store.values, "ssh-mcp/ssh-password:existing")
	message = model.checkSelectedCredential()()
	model.Update(message)
	if got := model.credentialStates["existing"]; got != credentialMissing {
		t.Fatalf("credential state = %q, want Missing", got)
	}
}

func TestCredentialBackendFailureReportsUnavailableWithSanitizedDetail(t *testing.T) {
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
	model.credentials = &fakeCredentialStore{statusErr: errors.New("keychain unavailable\x1b[2J")}
	message := model.checkSelectedCredential()()
	model.Update(message)
	if got := model.credentialStates["existing"]; got != credentialUnavailable {
		t.Fatalf("credential state = %q, want Unavailable", got)
	}
	detail := model.credentialErrors["existing"]
	if !strings.Contains(detail, "keychain unavailable") || strings.Contains(detail, "\x1b[2J") {
		t.Fatalf("credential error detail = %q, want visible terminal-safe detail", detail)
	}
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	view := model.View().Content
	if !strings.Contains(view, "Unavailable") || strings.Contains(view, "\x1b[2J") {
		t.Fatalf("view = %q, want terminal-safe Unavailable state", view)
	}
}

func TestCredentialCheckIgnoresOutOfOrderOrChangedReferenceResults(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "password"
password = "keychain:first:account"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeCredentialStore{values: map[string][]byte{"second/account": []byte("secret")}}
	model.credentials = store
	oldCommand := model.checkSelectedCredential()
	server := model.config.Servers["existing"]
	server.Password, err = config.ParseCredRef("keychain:second:account")
	if err != nil {
		t.Fatal(err)
	}
	model.config.Servers["existing"] = server
	model.list.SetItems(model.machineItems())
	newCommand := model.checkSelectedCredential()
	model.Update(newCommand())
	model.Update(oldCommand())
	if got := model.credentialStates["existing"]; got != credentialStored {
		t.Fatalf("credential state = %q, want newest Stored result", got)
	}

	currentGeneration := model.credentialGenerations["existing"]
	model.Update(credentialResultMsg{name: "existing", generation: currentGeneration, ref: config.CredRef{Kind: config.CredRefKeychain, Service: "first", Account: "account"}, state: credentialMissing})
	if got := model.credentialStates["existing"]; got != credentialStored {
		t.Fatalf("changed reference accepted stale result: %q", got)
	}
}

func TestHostKeyVerificationBlocksMismatchAndAllowsExplicitUnknownFlow(t *testing.T) {
	setTestHome(t, t.TempDir())
	addr := "host.example:22"
	trusted := newTestHostKey(t)
	path, err := defaultKnownHostsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := knownhosts.Append(path, addr, trusted); err != nil {
		t.Fatal(err)
	}
	if err := verifyFetchedHostKey(addr, trusted); err != nil {
		t.Fatalf("trusted key rejected: %v", err)
	}
	if err := verifyFetchedHostKey(addr, newTestHostKey(t)); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("mismatched key error = %v, want hard block", err)
	}

	setTestHome(t, t.TempDir())
	if err := verifyFetchedHostKey("new.example:22", newTestHostKey(t)); !errors.Is(err, errHostKeyUnknown) {
		t.Fatalf("unknown key error = %v, want explicit confirmation state", err)
	}
}

func TestHostKeyConfirmationRejectsKeyChangedAfterPreview(t *testing.T) {
	setTestHome(t, t.TempDir())
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "new.example"
user = "deploy"
auth = "agent"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	addr := "new.example:22"
	previewKey := newTestHostKey(t)
	model.handleHostKeyResult(hostKeyResultMsg{name: "existing", addr: addr, key: previewKey})
	if model.confirmation == nil {
		t.Fatal("unknown preview did not open confirmation")
	}
	path, err := defaultKnownHostsPath()
	if err != nil {
		t.Fatal(err)
	}
	changedKey := newTestHostKey(t)
	if err := knownhosts.Append(path, addr, changedKey); err != nil {
		t.Fatal(err)
	}
	model.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	if !strings.Contains(strings.ToLower(model.err), "mismatch") {
		t.Fatalf("confirmation error = %q, want stale preview mismatch rejection", model.err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, bytes.TrimSpace(gossh.MarshalAuthorizedKey(previewKey))) {
		t.Fatal("stale preview key was appended after the host changed")
	}
}

func TestHostKeyResultCannotReplaceActivePasswordDeleteConfirmation(t *testing.T) {
	setTestHome(t, t.TempDir())
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "new.example"
user = "deploy"
auth = "password"
password = "keychain:ssh-mcp:ssh-password:existing"
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.openPasswordManager()
	model.openPasswordDeleteConfirmation()
	original := model.confirmation
	model.hostKeyGeneration = 4
	model.Update(hostKeyResultMsg{
		name:       "existing",
		addr:       "new.example:22",
		key:        newTestHostKey(t),
		generation: 4,
	})
	if model.confirmation != original || model.confirmation.kind != confirmationPasswordDelete {
		t.Fatalf("host-key result replaced active password confirmation: %+v", model.confirmation)
	}
	if model.pendingHostKey != nil {
		t.Fatal("ignored host-key result became pending trust state")
	}
}

func TestConsoleFitsSupportedTerminalSizes(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "existing.example"
user = "deploy"
auth = "agent"
`)
	for _, size := range []struct{ width, height int }{{120, 36}, {80, 24}, {40, 12}} {
		model, err := New(Options{ConfigPath: configPath})
		if err != nil {
			t.Fatal(err)
		}
		model.Update(tea.WindowSizeMsg{Width: size.width, Height: size.height})
		view := model.View().Content
		lines := strings.Split(view, "\n")
		if len(lines) > size.height {
			t.Fatalf("%dx%d console has %d lines", size.width, size.height, len(lines))
		}
		for _, line := range lines {
			if got := lipgloss.Width(line); got > size.width {
				t.Fatalf("%dx%d console line width = %d: %q", size.width, size.height, got, line)
			}
		}
		assertEnglishOnly(t, view)
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

func TestMachineFormShowsConditionalFieldsAndRoundTripsPolicyJSON(t *testing.T) {
	configPath := writeTUIConfig(t, `
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "key"
key_path = "~/.ssh/id_ed25519"
mode = "restricted"
allow_patterns = ["^echo (a,b)$", "^printf \",\"$"]
deny_patterns = ["danger,(one|two)"]
`)
	model, err := New(Options{ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	model.openEdit()
	if !containsInt(model.form.visibleFields(), fieldKeyPath) || !containsInt(model.form.visibleFields(), fieldAllowPatterns) || !containsInt(model.form.visibleFields(), fieldDenyPatterns) {
		t.Fatalf("visible fields = %v, want key and policy patterns", model.form.visibleFields())
	}
	if got := model.form.fields[fieldAllowPatterns].Value(); got != `["^echo (a,b)$","^printf \",\"$"]` {
		t.Fatalf("allow JSON = %q, want exact JSON array", got)
	}

	model.form.fields[fieldAuth].SetValue("agent")
	if containsInt(model.form.visibleFields(), fieldKeyPath) {
		t.Fatal("agent authentication exposed Key file")
	}
	model.form.fields[fieldAuth].SetValue("password")
	if containsInt(model.form.visibleFields(), fieldKeyPath) {
		t.Fatal("password authentication exposed Key file")
	}
	model.form.fields[fieldMode].SetValue("unrestricted")
	if containsInt(model.form.visibleFields(), fieldAllowPatterns) || containsInt(model.form.visibleFields(), fieldDenyPatterns) {
		t.Fatal("unrestricted policy exposed pattern fields")
	}
	model.form.fields[fieldAuth].SetValue("key")
	model.form.fields[fieldMode].SetValue("restricted")
	model.saveForm()
	if model.err != "" {
		t.Fatal(model.err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	server := loaded.Servers["existing"]
	if server.Mode != "restricted" || strings.Join(server.AllowPatterns, "|") != `^echo (a,b)$|^printf ","$` || strings.Join(server.DenyPatterns, "|") != "danger,(one|two)" {
		t.Fatalf("policy round-trip = mode:%q allow:%q deny:%q", server.Mode, server.AllowPatterns, server.DenyPatterns)
	}
}

func TestMachineFormNavigationSkipsHiddenFieldsAndModeIsSelector(t *testing.T) {
	form := newMachineForm(config.ServerConfig{Auth: "agent"}, "machine", true)
	form.fields[fieldAuth].Focus()
	form.fields[fieldName].Blur()
	model := &Model{form: form}
	model.moveFormFocus(false)
	if got := model.focusedField(); got != fieldDefaultDir {
		t.Fatalf("focus after Auth = %d, want Default directory and hidden Key file skipped", got)
	}
	form.fields[fieldMode].Focus()
	form.fields[fieldDefaultDir].Blur()
	model.cycleMode(1)
	if got := form.fields[fieldMode].Value(); got != "readonly" {
		t.Fatalf("mode after selector = %q, want readonly", got)
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
		if !strings.Contains(model.message, "Stored credential was retained") {
			t.Fatalf("save message = %q, want retained credential notice", model.message)
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
	if got, want := model.list.Width(), 76; got != want {
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

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func assertEnglishOnly(t *testing.T, content string) {
	t.Helper()
	if match := regexp.MustCompile(`[\p{Han}]`).FindString(content); match != "" {
		t.Fatalf("UI contains non-English character %q in %q", match, content)
	}
}

func newTestHostKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func setTestHome(t *testing.T, directory string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", directory)
		return
	}
	t.Setenv("HOME", directory)
}
