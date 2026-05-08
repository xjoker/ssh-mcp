package mcpserver

import (
	"strings"
	"testing"
	"time"

	"github.com/xjoker/ssh-mcp/internal/tools"
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
	r := newQuickSetupRegistry(nil, nil)
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
	r := newQuickSetupRegistry(nil, nil)
	defer r.Close()

	_, ok := r.Lookup("nonexistent")
	if ok {
		t.Error("expected not found for unknown name")
	}
}

func TestQuickSetupRegistry_Expiry(t *testing.T) {
	r := newQuickSetupRegistry(nil, nil)
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
	r := newQuickSetupRegistry(nil, nil)
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
	r := newQuickSetupRegistry(nil, nil)
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
		{"My Server", "h", "qs-my-server"},
		{"UPPER", "h", "qs-upper"},
		{"a.b.c", "h", "qs-a-b-c"},
		{"", "host.example.com", "qs-host-example-com"},
		{"qs-existing", "h", "qs-existing"},
	}
	for _, c := range cases {
		got := sanitiseName(c.hint, c.host)
		if got != c.expected {
			t.Errorf("sanitiseName(%q, %q): want %q, got %q", c.hint, c.host, c.expected, got)
		}
	}
}

func TestQuickSetupRegistry_SecretZeroedOnEvict(t *testing.T) {
	r := newQuickSetupRegistry(nil, nil)
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
	r := newQuickSetupRegistry(nil, nil)
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
	r := newQuickSetupRegistry(nil, nil)
	defer r.Close()

	if _, _, err := r.Register(tools.QuickSetupSpec{AuthKind: "password", Secret: nil, TTLMinutes: 5}); err == nil {
		t.Error("expected empty-secret rejection")
	}
	if _, _, err := r.Register(tools.QuickSetupSpec{AuthKind: "weird", Secret: []byte("x"), TTLMinutes: 5}); err == nil {
		t.Error("expected unknown auth kind rejection")
	}
}

// SDD §13 / Codex R2-C02: quick_setup must not allocate a name that
// shadows a static server.
func TestQuickSetupRegistry_StaticNameCollisionDisambiguates(t *testing.T) {
	staticNames := map[string]struct{}{
		"qs-myhost":   {},
		"qs-myhost-2": {},
	}
	r := newQuickSetupRegistry(staticNames, nil)
	defer r.Close()

	name, _, err := r.Register(mkSpec("myhost", "h", "u", []byte("x"), 5))
	if err != nil {
		t.Fatal(err)
	}
	// Must skip qs-myhost AND qs-myhost-2 (which is *also* static)
	// and land on qs-myhost-3 or later.
	if _, taken := staticNames[name]; taken {
		t.Fatalf("registered name %q collides with a static server", name)
	}
}

// onEvict callback must fire on every eviction so the SSH pool can drop
// the temp entry in lock-step.
func TestQuickSetupRegistry_OnEvictFiresOnReap(t *testing.T) {
	var evicted []string
	r := newQuickSetupRegistry(nil, func(name string) { evicted = append(evicted, name) })
	defer r.Close()

	name, _, err := r.Register(mkSpec("ev", "h", "u", []byte("x"), 1))
	if err != nil {
		t.Fatal(err)
	}
	// Force expiry then reap.
	r.mu.Lock()
	r.m[name].expiresAt = time.Now().Add(-time.Minute)
	r.mu.Unlock()
	r.reapExpired()

	if len(evicted) != 1 || evicted[0] != name {
		t.Errorf("expected onEvict([%q]), got %v", name, evicted)
	}
}

func TestQuickSetupRegistry_OnEvictRunsOutsideLock(t *testing.T) {
	var r *quickSetupRegistry
	r = newQuickSetupRegistry(nil, func(string) {
		locked := make(chan struct{})
		go func() {
			r.mu.Lock()
			r.mu.Unlock()
			close(locked)
		}()
		select {
		case <-locked:
		case <-time.After(200 * time.Millisecond):
			t.Error("onEvict appears to run while registry mutex is held")
		}
	})
	defer r.Close()

	name, _, err := r.Register(mkSpec("lock", "h", "u", []byte("x"), 1))
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.m[name].expiresAt = time.Now().Add(-time.Minute)
	r.mu.Unlock()

	_, _ = r.Lookup(name)
}

func TestQuickSetupRegistry_OnEvictFiresOnClose(t *testing.T) {
	var evicted []string
	r := newQuickSetupRegistry(nil, func(name string) { evicted = append(evicted, name) })

	name, _, _ := r.Register(mkSpec("clo", "h", "u", []byte("x"), 5))
	r.Close()

	if len(evicted) == 0 || evicted[0] != name {
		t.Errorf("expected onEvict to fire on Close, got %v", evicted)
	}
}

// All sanitised names start with "qs-" so they live in a fixed namespace.
func TestSanitiseName_AlwaysQSPrefix(t *testing.T) {
	for _, in := range []string{"prod", "Production-DB", "internal_node-1", "", "x"} {
		got := sanitiseName(in, "h")
		if !strings.HasPrefix(got, "qs-") {
			t.Errorf("sanitiseName(%q) = %q; missing qs- prefix", in, got)
		}
	}
}

// --------------------------------------------------------------------------
// H02 — registry-level TTL guard
// --------------------------------------------------------------------------

// TestQuickSetupRegistry_TTLZeroRejected: TTLMinutes=0 must be rejected by the
// registry (defence-in-depth; the handler layer has already defaulted it to 30,
// but future callers must not be able to register a secret with no expiry).
func TestQuickSetupRegistry_TTLZeroRejected(t *testing.T) {
	r := newQuickSetupRegistry(nil, nil)
	defer r.Close()

	_, _, err := r.Register(tools.QuickSetupSpec{
		AuthKind:   "password",
		Secret:     []byte("pw"),
		TTLMinutes: 0,
	})
	if err == nil {
		t.Error("expected error for TTLMinutes=0")
	}
}

// TestQuickSetupRegistry_TTLOverMaxRejected: TTLMinutes>240 must be rejected.
func TestQuickSetupRegistry_TTLOverMaxRejected(t *testing.T) {
	r := newQuickSetupRegistry(nil, nil)
	defer r.Close()

	_, _, err := r.Register(tools.QuickSetupSpec{
		AuthKind:   "password",
		Secret:     []byte("pw"),
		TTLMinutes: 9999,
	})
	if err == nil {
		t.Error("expected error for TTLMinutes=9999")
	}
}

// TestQuickSetupRegistry_TTLBoundariesAllowed: TTLMinutes=1 and TTLMinutes=240
// are both within the allowed range and must succeed.
func TestQuickSetupRegistry_TTLBoundariesAllowed(t *testing.T) {
	r := newQuickSetupRegistry(nil, nil)
	defer r.Close()

	for _, ttl := range []int{1, 240} {
		_, _, err := r.Register(tools.QuickSetupSpec{
			NameHint:   "boundary",
			Host:       "h",
			Port:       22,
			User:       "u",
			AuthKind:   "password",
			Secret:     []byte("pw"),
			TTLMinutes: ttl,
		})
		if err != nil {
			t.Errorf("TTLMinutes=%d should be allowed, got error: %v", ttl, err)
		}
	}
}

// TestQuickSetupRegistry_ReuseSameHostPortUser locks in the b1201c7 dedup
// behaviour: a second Register() call for the same (host, port, user) tuple
// must return the existing canonical name and refresh the secret/TTL in
// place — never allocate a new -2 / -3 / ... suffix. This prevents the AI
// from triggering a fresh confirmation dialog for every tool call on the
// same server.
func TestQuickSetupRegistry_ReuseSameHostPortUser(t *testing.T) {
	r := newQuickSetupRegistry(nil, nil)
	defer r.Close()

	name1, exp1, err := r.Register(mkSpec("box", "10.0.0.1", "root", []byte("pw1"), 30))
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}

	// Sleep a tick so we can verify TTL is *refreshed* (later) on the second
	// call, not preserved.
	time.Sleep(20 * time.Millisecond)

	name2, exp2, err := r.Register(mkSpec("box", "10.0.0.1", "root", []byte("pw2"), 30))
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}

	if name1 != name2 {
		t.Fatalf("dedup broken: second Register returned %q, want same as first %q", name2, name1)
	}
	if exp2 < exp1 {
		t.Errorf("TTL should be refreshed forward, got exp1=%d exp2=%d", exp1, exp2)
	}

	// Only one entry in the map.
	r.mu.Lock()
	count := len(r.m)
	r.mu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 entry after dedup, got %d", count)
	}

	// Secret was refreshed to "pw2".
	view, ok := r.Lookup(name2)
	if !ok {
		t.Fatalf("Lookup(%q) after refresh: not found", name2)
	}
	if string(view.Secret) != "pw2" {
		t.Errorf("secret not refreshed; want pw2, got %q", view.Secret)
	}
}

// TestQuickSetupRegistry_DistinctTuplesGetDistinctNames is the negative twin
// of the dedup test: differing host, port, or user must NOT collapse onto an
// existing entry. Catches regressions where someone over-eagerly broadens
// the dedup match to e.g. host-only.
func TestQuickSetupRegistry_DistinctTuplesGetDistinctNames(t *testing.T) {
	r := newQuickSetupRegistry(nil, nil)
	defer r.Close()

	base, _, err := r.Register(mkSpec("box", "10.0.0.1", "root", []byte("pw"), 30))
	if err != nil {
		t.Fatalf("Register base: %v", err)
	}

	cases := []struct {
		label string
		spec  tools.QuickSetupSpec
	}{
		{"different user", mkSpec("box", "10.0.0.1", "alice", []byte("pw"), 30)},
		{"different host", mkSpec("box", "10.0.0.2", "root", []byte("pw"), 30)},
		{
			"different port",
			tools.QuickSetupSpec{
				NameHint:   "box",
				Host:       "10.0.0.1",
				Port:       2222,
				User:       "root",
				AuthKind:   "password",
				Secret:     []byte("pw"),
				TTLMinutes: 30,
			},
		},
	}

	for _, tc := range cases {
		got, _, err := r.Register(tc.spec)
		if err != nil {
			t.Errorf("%s: Register: %v", tc.label, err)
			continue
		}
		if got == base {
			t.Errorf("%s: should NOT collapse onto base name %q", tc.label, base)
		}
	}
}
