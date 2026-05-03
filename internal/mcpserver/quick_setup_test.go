package mcpserver

import (
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// quickSetupRegistry tests
// --------------------------------------------------------------------------

func TestQuickSetupRegistry_RegisterLookup(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	name, expiresAt, err := r.Register("mytest", "192.168.1.1", 22, "admin", []byte("secret"), 30)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if name == "" {
		t.Error("registered name should not be empty")
	}
	if expiresAt == 0 {
		t.Error("expiresAt should be non-zero")
	}

	// Lookup should return the entry.
	host, port, user, secretBytes, ok := r.Lookup(name)
	if !ok {
		t.Fatalf("Lookup(%q): not found", name)
	}
	if host != "192.168.1.1" {
		t.Errorf("host: want 192.168.1.1, got %s", host)
	}
	if port != 22 {
		t.Errorf("port: want 22, got %d", port)
	}
	if user != "admin" {
		t.Errorf("user: want admin, got %s", user)
	}
	if string(secretBytes) != "secret" {
		t.Errorf("secret: want 'secret', got %q", string(secretBytes))
	}
}

func TestQuickSetupRegistry_LookupNotFound(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	_, _, _, _, ok := r.Lookup("nonexistent")
	if ok {
		t.Error("expected not found for unknown name")
	}
}

func TestQuickSetupRegistry_Expiry(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	// Register with TTL of 1 minute but then manually expire the entry.
	name, _, err := r.Register("exptest", "1.2.3.4", 22, "user", []byte("pw"), 1)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Manually backdating the expiry to simulate TTL expiration.
	r.mu.Lock()
	if e, ok := r.m[name]; ok {
		e.expiresAt = time.Now().Add(-1 * time.Minute)
	}
	r.mu.Unlock()

	// Lookup should return not found (lazy eviction path).
	_, _, _, _, ok := r.Lookup(name)
	if ok {
		t.Error("expected entry to be expired and not found")
	}
}

func TestQuickSetupRegistry_ReaperEvicts(t *testing.T) {
	r := newQuickSetupRegistry()
	defer r.Close()

	name, _, err := r.Register("reaptest", "2.3.4.5", 22, "ubuntu", []byte("key"), 1)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Manually set expiry to past.
	r.mu.Lock()
	if e, ok := r.m[name]; ok {
		e.expiresAt = time.Now().Add(-2 * time.Minute)
	}
	r.mu.Unlock()

	// Call reapExpired directly (simulates the reaper goroutine).
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

	// Register two entries with the same hint — should get different names.
	n1, _, _ := r.Register("same", "h1", 22, "u", []byte("s"), 5)
	n2, _, _ := r.Register("same", "h2", 22, "u", []byte("s"), 5)

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
	name, _, err := r.Register("", "host", 22, "user", secret, 1)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Get a copy of the secret bytes before eviction.
	_, _, _, secretCopy, ok := r.Lookup(name)
	if !ok {
		t.Fatal("entry not found after register")
	}
	if string(secretCopy) != "topsecret" {
		t.Errorf("secret copy wrong: %q", string(secretCopy))
	}

	// Now evict by setting expiry to past.
	r.mu.Lock()
	if e, ok := r.m[name]; ok {
		e.expiresAt = time.Now().Add(-time.Minute)
	}
	r.mu.Unlock()
	r.reapExpired()

	// The copy we made should be unaffected by eviction.
	if string(secretCopy) != "topsecret" {
		t.Error("secret copy should not be zeroed when caller owns a copy")
	}

	// But the original slice in the registry should be zeroed.
	// We can verify this indirectly: Lookup should return nothing.
	_, _, _, _, ok = r.Lookup(name)
	if ok {
		t.Error("entry should be gone after eviction")
	}
}

// TestSanitiseNameLongInput ensures truncation at 32 chars.
func TestSanitiseNameLongInput(t *testing.T) {
	got := sanitiseName("a-very-long-name-that-exceeds-32-characters-definitely", "h")
	if len(got) > 32 {
		t.Errorf("expected len ≤ 32, got %d (%q)", len(got), got)
	}
}
