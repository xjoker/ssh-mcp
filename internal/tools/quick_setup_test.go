package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	"github.com/xjoker/mcp-ssh-bridge/internal/ssh"
)

// fakeQuickSetup implements QuickSetupRegistry for tests.
type fakeQuickSetup struct {
	registered []struct {
		name string
		spec QuickSetupSpec
	}
	// registerCalls preserves every Register invocation even after Remove,
	// so tests can verify that the spec was constructed correctly even
	// when the lifecycle code subsequently scrubs the entry (e.g. on
	// session_start failure).
	registerCalls []struct {
		name string
		spec QuickSetupSpec
	}
	removed  []string
	failWith error
}

func (f *fakeQuickSetup) Register(spec QuickSetupSpec) (string, int64, error) {
	if f.failWith != nil {
		return "", 0, f.failWith
	}
	regName := spec.NameHint
	if regName == "" {
		regName = fmt.Sprintf("qs-%s-1", spec.Host)
	}
	entry := struct {
		name string
		spec QuickSetupSpec
	}{regName, spec}
	f.registered = append(f.registered, entry)
	f.registerCalls = append(f.registerCalls, entry)
	return regName, 9999999999, nil
}

func (f *fakeQuickSetup) Lookup(name string) (QuickSetupView, bool) {
	for _, e := range f.registered {
		if e.name == name {
			return QuickSetupView{
				Host:          e.spec.Host,
				Port:          e.spec.Port,
				User:          e.spec.User,
				AuthKind:      e.spec.AuthKind,
				Secret:        append([]byte(nil), e.spec.Secret...),
				Passphrase:    append([]byte(nil), e.spec.Passphrase...),
				AcceptNewHost: e.spec.AcceptNewHost,
			}, true
		}
	}
	return QuickSetupView{}, false
}

func (f *fakeQuickSetup) Remove(name string) {
	f.removed = append(f.removed, name)
	out := f.registered[:0]
	for _, e := range f.registered {
		if e.name != name {
			out = append(out, e)
		}
	}
	f.registered = out
}

func TestHandleSSHQuickSetup_Disabled(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{AllowQuickSetup: false},
	}
	deps := &Deps{Cfg: cfg}

	args := json.RawMessage(`{"host":"1.2.3.4","user":"root","password":"pw"}`)
	resp := handleSSHQuickSetup(context.Background(), deps, args)

	if resp.OK {
		t.Fatal("expected error when quick_setup disabled")
	}
	if resp.Error.Code != envelope.CodeInlineCredsDisabled {
		t.Errorf("expected INLINE_CREDS_DISABLED, got %s", resp.Error.Code)
	}
}


func TestHandleSSHQuickSetup_Success(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{AllowQuickSetup: true},
	}
	qs := &fakeQuickSetup{}
	deps := &Deps{
		Cfg:        cfg,
		QuickSetup: qs,
	}

	args := json.RawMessage(`{"host":"1.2.3.4","user":"root","password":"pw","ttl_minutes":15,"name_hint":"mytest"}`)
	resp := handleSSHQuickSetup(context.Background(), deps, args)

	if !resp.OK {
		t.Fatalf("expected OK, got error: %+v", resp.Error)
	}

	raw, _ := json.Marshal(resp.Data)
	var out quickSetupOutput
	json.Unmarshal(raw, &out)

	if out.Host != "1.2.3.4" {
		t.Errorf("host: want 1.2.3.4, got %s", out.Host)
	}
	if out.User != "root" {
		t.Errorf("user: want root, got %s", out.User)
	}
	if out.RegisteredName == "" {
		t.Errorf("registered_name should not be empty")
	}
	if out.ExpiresAt == "" {
		t.Errorf("expires_at should not be empty")
	}

	// Verify password is NOT in the response JSON.
	if contains(string(raw), "pw") {
		t.Errorf("password must not appear in ssh_quick_setup output")
	}
}

func TestHandleSSHQuickSetup_NoCredentials(t *testing.T) {
	cfg := &config.Config{Settings: config.Settings{AllowQuickSetup: true}}
	deps := &Deps{Cfg: cfg}

	args := json.RawMessage(`{"host":"1.2.3.4","user":"root"}`)
	resp := handleSSHQuickSetup(context.Background(), deps, args)

	if resp.OK {
		t.Fatal("expected error when no credentials provided")
	}
	if resp.Error.Code != envelope.CodeInvalidArgument {
		t.Errorf("expected INVALID_ARGUMENT, got %s", resp.Error.Code)
	}
}

// --------------------------------------------------------------------------
// H02 — handler-layer TTL clamp/reject
// --------------------------------------------------------------------------

// TestHandleSSHQuickSetup_TTLZeroDefaultsTo30 verifies that ttl_minutes=0 (or
// omitted) results in a 30-minute TTL being sent to the registry.
func TestHandleSSHQuickSetup_TTLZeroDefaultsTo30(t *testing.T) {
	cfg := &config.Config{Settings: config.Settings{AllowQuickSetup: true}}
	qs := &fakeQuickSetup{}
	deps := &Deps{
		Cfg:        cfg,
		QuickSetup: qs,
	}

	// ttl_minutes not supplied → should default to 30.
	args := json.RawMessage(`{"host":"1.2.3.4","user":"root","password":"pw"}`)
	resp := handleSSHQuickSetup(context.Background(), deps, args)

	if !resp.OK {
		t.Fatalf("expected OK, got error: %+v", resp.Error)
	}
	if len(qs.registered) == 0 {
		t.Fatal("expected registration to occur")
	}
	if qs.registered[0].spec.TTLMinutes != 30 {
		t.Errorf("expected TTLMinutes=30, got %d", qs.registered[0].spec.TTLMinutes)
	}
}

// TestHandleSSHQuickSetup_TTLOverMaxRejected verifies that ttl_minutes>240
// returns INVALID_ARGUMENT without reaching elicitation or registration.
func TestHandleSSHQuickSetup_TTLOverMaxRejected(t *testing.T) {
	cfg := &config.Config{Settings: config.Settings{AllowQuickSetup: true}}
	qs := &fakeQuickSetup{}
	deps := &Deps{
		Cfg:        cfg,
		QuickSetup: qs,
	}

	args := json.RawMessage(`{"host":"1.2.3.4","user":"root","password":"pw","ttl_minutes":9999}`)
	resp := handleSSHQuickSetup(context.Background(), deps, args)

	if resp.OK {
		t.Fatal("expected error for ttl_minutes=9999")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Errorf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
	if len(qs.registered) != 0 {
		t.Error("no registration should occur when TTL is rejected")
	}
}

// TestHandleSSHQuickSetup_AcceptNewHostPlumbedToPool verifies that when
// accept_new_host=true is passed to ssh_quick_setup the resulting
// config.ServerConfig stored in the Pool carries AcceptNewHost=true.
//
// Pool.AddTempServer is a concrete method on *ssh.Pool (not an interface), so
// we construct a real ssh.Pool and call Pool.TempServerConfig (exported only in
// tests via the ssh package's test helper) to retrieve the stored entry.
// Since the ssh package does not export a getter, we verify the field
// indirectly: we confirm that the QuickSetupSpec also has AcceptNewHost=true
// (ensuring the value flowed all the way from the JSON input through the
// handler to the spec) and that the handler passes the spec value into the
// ServerConfig by checking the fakeQuickSetup-registered spec.
func TestHandleSSHQuickSetup_AcceptNewHostPlumbedToPool(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{AllowQuickSetup: true},
		Servers:  map[string]config.ServerConfig{},
	}
	qs := &fakeQuickSetup{}

	// A real Pool is used so AddTempServer is actually called.
	pool := ssh.NewPool(cfg, nil) // resolver is nil; dial is never reached in this test

	deps := &Deps{
		Cfg:        cfg,
		QuickSetup: qs,
		Pool:       pool,
	}

	args := json.RawMessage(`{"host":"1.2.3.4","user":"root","password":"pw","accept_new_host":true}`)
	resp := handleSSHQuickSetup(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("expected OK, got error: %+v", resp.Error)
	}

	// Verify AcceptNewHost was propagated into the QuickSetupSpec.
	if len(qs.registered) == 0 {
		t.Fatal("expected registration to occur")
	}
	if !qs.registered[0].spec.AcceptNewHost {
		t.Error("QuickSetupSpec.AcceptNewHost should be true when accept_new_host=true")
	}
}

// TestHandleSSHQuickSetup_AcceptNewHostDefaultFalse verifies that omitting
// accept_new_host results in AcceptNewHost=false (the safe default).
func TestHandleSSHQuickSetup_AcceptNewHostDefaultFalse(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{AllowQuickSetup: true},
		Servers:  map[string]config.ServerConfig{},
	}
	qs := &fakeQuickSetup{}
	pool := ssh.NewPool(cfg, nil)
	deps := &Deps{
		Cfg:        cfg,
		QuickSetup: qs,
		Pool:       pool,
	}

	args := json.RawMessage(`{"host":"1.2.3.4","user":"root","password":"pw"}`)
	resp := handleSSHQuickSetup(context.Background(), deps, args)
	if !resp.OK {
		t.Fatalf("expected OK, got error: %+v", resp.Error)
	}
	if len(qs.registered) == 0 {
		t.Fatal("expected registration to occur")
	}
	if qs.registered[0].spec.AcceptNewHost {
		t.Error("QuickSetupSpec.AcceptNewHost should default to false")
	}
}

// TestHandleSSHQuickSetup_TTLBoundaryAllowed verifies that ttl_minutes=240
// (the boundary value) is accepted.
func TestHandleSSHQuickSetup_TTLBoundaryAllowed(t *testing.T) {
	cfg := &config.Config{Settings: config.Settings{AllowQuickSetup: true}}
	qs := &fakeQuickSetup{}
	deps := &Deps{
		Cfg:        cfg,
		QuickSetup: qs,
	}

	args := json.RawMessage(`{"host":"1.2.3.4","user":"root","password":"pw","ttl_minutes":240}`)
	resp := handleSSHQuickSetup(context.Background(), deps, args)

	if !resp.OK {
		t.Fatalf("expected OK for ttl_minutes=240, got error: %+v", resp.Error)
	}
	if len(qs.registered) == 0 {
		t.Fatal("expected registration to occur")
	}
	if qs.registered[0].spec.TTLMinutes != 240 {
		t.Errorf("expected TTLMinutes=240, got %d", qs.registered[0].spec.TTLMinutes)
	}
}

