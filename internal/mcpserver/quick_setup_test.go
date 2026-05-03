package mcpserver

import (
	"testing"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/tools"
)

// --------------------------------------------------------------------------
// quickSetupRegistry tests
// --------------------------------------------------------------------------

func mkSpec(hint, host, user string, secret []byte, ttl int) tools.QuickSetupSpec {
	return tools.QuickSetupSpec{
		NameHint:   hint,
		Host:       host,
		Port:       22,
		User:       user,
		AuthKind:   "password",
		Secret:     secret,
		TTLMinutes: ttl,
	}
}

func TestQuickSetupRegistry_RegisterLookup(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	name, expiresAt, err := r.Register(mkSpec("mytest", "192.168.1.1", "admin", []byte("secret"), 30))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if name == "" {
		t.Error("registered name should not be empty")
	}
	if expiresAt == 0 {
		t.Error("expiresAt should be non-zero")
	}

	view, ok := r.Lookup(name)
	if !ok {
		t.Fatalf("Lookup(%q): not found", name)
	}
	if view.Host != "192.168.1.1" {
		t.Errorf("host: want 192.168.1.1, got %s", view.Host)
	}
	if view.Port != 22 {
		t.Errorf("port: want 22, got %d", view.Port)
	}
	if view.User != "admin" {
		t.Errorf("user: want admin, got %s", view.User)
	}
	if view.AuthKind != "password" {
		t.Errorf("auth kind: want password, got %s", view.AuthKind)
	}
	if string(view.Secret) != "secret" {
		t.Errorf("secret: want 'secret', got %q", string(view.Secret))
	}
}

func TestQuickSetupRegistry_LookupNotFound(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	_, ok := r.Lookup("nonexistent")
	if ok {
		t.Error("expected not found for unknown name")
	}
}

func TestQuickSetupRegistry_Expiry(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	name, _, err := r.Register(mkSpec("exptest", "1.2.3.4", "user", []byte("pw"), 1))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	r.mu.Lock()
	if e, ok := r.m[name]; ok {
		e.expiresAt = time.Now().Add(-1 * time.Minute)
	}
	r.mu.Unlock()

	_, ok := r.Lookup(name)
	if ok {
		t.Error("expected entry to be expired and not found")
	}
}

func TestQuickSetupRegistry_ReaperEvicts(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	name, _, err := r.Register(mkSpec("reaptest", "2.3.4.5", "ubuntu", []byte("key"), 1))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	r.mu.Lock()
	if e, ok := r.m[name]; ok {
		e.expiresAt = time.Now().Add(-2 * time.Minute)
	}
	r.mu.Unlock()

	r.reapExpired()

	r.mu.Lock()
	_, stillPresent := r.m[name]
	r.mu.Unlock()

	if stillPresent {
		t.Error("entry should have been evicted by reapExpired()")
	}
}

func TestQuickSetupRegistry_Disambiguation(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	n1, _, _ := r.Register(mkSpec("same", "h1", "u", []byte("s"), 5))
	n2, _, _ := r.Register(mkSpec("same", "h2", "u", []byte("s"), 5))

	if n1 == n2 {
		t.Errorf("expected distinct names for duplicate hints: got %q twice", n1)
	}
}

func TestQuickSetupRegistry_SanitiseName(t *testing.T) {
	cases := []struct {
		hint     string
		host     string
		expected string
	}{
		{"", "192.168.1.1", "qs-192-168-1-1"},
		{"My Server", "h", "my-server"},
		{"UPPER", "h", "upper"},
		{"a.b.c", "h", "a-b-c"},
		{"", "host.example.com", "qs-host-example-com"},
	}
	for _, c := range cases {
		got := sanitiseName(c.hint, c.host)
		if got != c.expected {
			t.Errorf("sanitiseName(%q, %q): want %q, got %q", c.hint, c.host, c.expected, got)
		}
	}
}

func TestQuickSetupRegistry_SecretZeroedOnEvict(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	secret := []byte("topsecret")
	name, _, err := r.Register(mkSpec("", "host", "user", secret, 1))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	view, ok := r.Lookup(name)
	if !ok {
		t.Fatal("entry not found after register")
	}
	if string(view.Secret) != "topsecret" {
		t.Errorf("secret copy wrong: %q", string(view.Secret))
	}

	r.mu.Lock()
	if e, ok := r.m[name]; ok {
		e.expiresAt = time.Now().Add(-time.Minute)
	}
	r.mu.Unlock()
	r.reapExpired()

	if string(view.Secret) != "topsecret" {
		t.Error("caller's secret copy should not be zeroed when entry is evicted")
	}

	_, ok = r.Lookup(name)
	if ok {
		t.Error("entry should be gone after eviction")
	}
}

func TestSanitiseNameLongInput(t *testing.T) {
	got := sanitiseName("a-very-long-name-that-exceeds-32-characters-definitely", "h")
	if len(got) > 32 {
		t.Errorf("expected len ≤ 32, got %d (%q)", len(got), got)
	}
}

// SDD §6.13 / Codex H02: registering with auth=key + passphrase preserves
// both fields so the credResolver can later build a working signer.
func TestQuickSetupRegistry_KeyWithPassphrase(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	name, _, err := r.Register(tools.QuickSetupSpec{
		NameHint:      "kp",
		Host:          "h",
		Port:          22,
		User:          "u",
		AuthKind:      "key",
		Secret:        []byte("FAKE-PEM"),
		Passphrase:    []byte("PASS-PHRASE"),
		AcceptNewHost: true,
		TTLMinutes:    5,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	view, ok := r.Lookup(name)
	if !ok {
		t.Fatal("not found")
	}
	if view.AuthKind != "key" {
		t.Errorf("AuthKind: want key, got %s", view.AuthKind)
	}
	if string(view.Secret) != "FAKE-PEM" {
		t.Errorf("Secret: want FAKE-PEM, got %s", view.Secret)
	}
	if string(view.Passphrase) != "PASS-PHRASE" {
		t.Errorf("Passphrase: want PASS-PHRASE, got %s", view.Passphrase)
	}
	if !view.AcceptNewHost {
		t.Error("AcceptNewHost not preserved")
	}
}

func TestQuickSetupRegistry_RegisterRejectsBadInput(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	if _, _, err := r.Register(tools.QuickSetupSpec{AuthKind: "password", Secret: nil, TTLMinutes: 5}); err == nil {
		t.Error("expected empty-secret rejection")
	}
	if _, _, err := r.Register(tools.QuickSetupSpec{AuthKind: "weird", Secret: []byte("x"), TTLMinutes: 5}); err == nil {
		t.Error("expected unknown auth kind rejection")
	}
}
