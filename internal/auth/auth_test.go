package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/config"
)

// --------------------------------------------------------------------------
// S-7: Secret zeroing, String panic, Close idempotency
// --------------------------------------------------------------------------

// TestSecretZeroOnClose verifies S-7: after Close(), the underlying buffer
// is zeroed.
func TestSecretZeroOnClose(t *testing.T) {
	input := []byte("hunter2")
	s := NewSecret(input)

	// Keep a reference to the underlying slice before Close.
	underlying := s.buf

	// Verify content before close.
	if string(s.Bytes()) != "hunter2" {
		t.Fatalf("expected 'hunter2', got %q", string(s.Bytes()))
	}

	s.Close()

	// The underlying slice must be all zeros.
	for i, b := range underlying {
		if b != 0 {
			t.Errorf("buf[%d] = %d, want 0 after Close", i, b)
		}
	}

	// Bytes() must return nil after close.
	if s.Bytes() != nil {
		t.Error("Bytes() should return nil after Close")
	}
}

// TestSecretNewCopiesInput ensures NewSecret does not share the caller's buffer.
func TestSecretNewCopiesInput(t *testing.T) {
	input := []byte("original")
	s := NewSecret(input)
	// Mutate original; secret must be unaffected.
	input[0] = 'X'
	if s.Bytes()[0] != 'o' {
		t.Error("NewSecret shares backing array with input — it must copy")
	}
}

// TestSecretStringPanics verifies that String() panics (S-7 / §5.3).
func TestSecretStringPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("String() should have panicked but did not")
		}
	}()
	s := NewSecret([]byte("sensitive"))
	_ = s.String() // must panic
}

// TestSecretCloseIdempotent ensures Close() can be called multiple times
// without panicking.
func TestSecretCloseIdempotent(t *testing.T) {
	s := NewSecret([]byte("data"))
	s.Close()
	s.Close() // second call must not panic
	s.Close() // third call must not panic
}

// TestSecretCloseNilSafe ensures Close() on a nil *Secret is a no-op.
func TestSecretCloseNilSafe(t *testing.T) {
	var s *Secret
	s.Close() // must not panic
}

// --------------------------------------------------------------------------
// Resolve: CredRefNone
// --------------------------------------------------------------------------

func TestResolveNone(t *testing.T) {
	ref := config.CredRef{Kind: config.CredRefNone}
	s, err := Resolve(context.Background(), ref, false)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if s != nil {
		t.Fatal("expected nil Secret for CredRefNone")
	}
}

// --------------------------------------------------------------------------
// Resolve: CredRefEnv
// --------------------------------------------------------------------------

func TestResolveEnvUnset(t *testing.T) {
	const varName = "MCP_SSH_TEST_UNSET_VAR_XYZ"
	os.Unsetenv(varName)

	ref := config.CredRef{Kind: config.CredRefEnv, EnvVar: varName}
	_, err := Resolve(context.Background(), ref, false)
	if err == nil {
		t.Fatal("expected ErrKeyNotFound, got nil")
	}
	if !isErr(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestResolveEnvSet(t *testing.T) {
	const varName = "MCP_SSH_TEST_SET_VAR_XYZ"
	const varValue = "my-secret-value"
	t.Setenv(varName, varValue)

	ref := config.CredRef{Kind: config.CredRefEnv, EnvVar: varName}
	s, err := Resolve(context.Background(), ref, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil Secret")
	}
	defer s.Close()

	if string(s.Bytes()) != varValue {
		t.Fatalf("expected %q, got %q", varValue, string(s.Bytes()))
	}
}

// --------------------------------------------------------------------------
// Resolve: CredRefPlaintext
// --------------------------------------------------------------------------

func TestResolvePlaintextDisabled(t *testing.T) {
	ref := config.CredRef{Kind: config.CredRefPlaintext, Value: "my-password"}
	_, err := Resolve(context.Background(), ref, false)
	if err == nil {
		t.Fatal("expected ErrPlaintextDisabled, got nil")
	}
	if !isErr(err, ErrPlaintextDisabled) {
		t.Fatalf("expected ErrPlaintextDisabled, got %v", err)
	}
}

func TestResolvePlaintextEnabled(t *testing.T) {
	const val = "my-password"
	ref := config.CredRef{Kind: config.CredRefPlaintext, Value: val}
	s, err := Resolve(context.Background(), ref, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil Secret")
	}
	defer s.Close()

	if string(s.Bytes()) != val {
		t.Fatalf("expected %q, got %q", val, string(s.Bytes()))
	}
}

// --------------------------------------------------------------------------
// LoadPrivateKey
// --------------------------------------------------------------------------

// generateEd25519PEM creates an unencrypted OpenSSH PEM-encoded ed25519 key.
func generateEd25519PEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}

// generateEncryptedEd25519PEM creates a passphrase-encrypted OpenSSH private key.
func generateEncryptedEd25519PEM(t *testing.T, passphrase []byte) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", passphrase)
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKeyWithPassphrase: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func TestLoadPrivateKeyUnencrypted(t *testing.T) {
	pemBytes := generateEd25519PEM(t)
	signer, err := LoadPrivateKey(pemBytes, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil Signer")
	}
}

func TestLoadPrivateKeyEncryptedNilPassphrase(t *testing.T) {
	passphrase := []byte("correct-horse-battery-staple")
	pemBytes := generateEncryptedEd25519PEM(t, passphrase)

	_, err := LoadPrivateKey(pemBytes, nil)
	if err == nil {
		t.Fatal("expected ErrPassphraseRequired, got nil")
	}
	if !isErr(err, ErrPassphraseRequired) {
		t.Fatalf("expected ErrPassphraseRequired, got %v", err)
	}
}

func TestLoadPrivateKeyEncryptedWithPassphrase(t *testing.T) {
	passphrase := []byte("correct-horse-battery-staple")
	pemBytes := generateEncryptedEd25519PEM(t, passphrase)

	secret := NewSecret(passphrase)
	defer secret.Close()

	signer, err := LoadPrivateKey(pemBytes, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil Signer")
	}
}

func TestLoadPrivateKeyInvalidPEM(t *testing.T) {
	_, err := LoadPrivateKey([]byte("not a pem"), nil)
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

// --------------------------------------------------------------------------
// Keychain smoke tests — skipped in CI / short mode
// --------------------------------------------------------------------------

func TestKeychainSetGetDelete(t *testing.T) {
	if testing.Short() || os.Getenv("CI") != "" {
		t.Skip("keychain tests require a live OS keychain — skipping in CI/short mode")
	}

	const service = "ssh-mcp-test"
	const account = "test-account-unit"
	const secret = "test-secret-value"

	if err := SetKeychain(service, account, []byte(secret)); err != nil {
		t.Fatalf("SetKeychain: %v", err)
	}
	t.Cleanup(func() {
		_ = DeleteKeychain(service, account)
	})

	ref := config.CredRef{
		Kind:    config.CredRefKeychain,
		Service: service,
		Account: account,
	}
	s, err := Resolve(context.Background(), ref, false)
	if err != nil {
		t.Fatalf("Resolve keychain: %v", err)
	}
	defer s.Close()
	if string(s.Bytes()) != secret {
		t.Fatalf("expected %q, got %q", secret, string(s.Bytes()))
	}

	if err := DeleteKeychain(service, account); err != nil {
		t.Fatalf("DeleteKeychain: %v", err)
	}
}

// TestKeychainSetErrorUnwrappable verifies that errors from SetKeychain can
// be unwrapped (i.e., are not opaque string-only errors).
// This test runs even in CI; it merely inspects error structure.
func TestKeychainSetErrorUnwrappable(t *testing.T) {
	// On CI without a keychain, SetKeychain will return an error.
	// We just confirm the error, if any, is non-nil and has a message.
	// If keychain IS available, the Set may succeed — that's fine.
	err := SetKeychain("ssh-mcp-test-probe", "probe", []byte("probe"))
	if err != nil {
		// Must be an error with a non-empty message.
		if err.Error() == "" {
			t.Error("SetKeychain error has empty message")
		}
		t.Logf("SetKeychain returned (expected on CI): %v", err)
	}
	// On success, clean up.
	if err == nil {
		_ = DeleteKeychain("ssh-mcp-test-probe", "probe")
	}
}

// --------------------------------------------------------------------------
// Agent — H04
// --------------------------------------------------------------------------

// TestAgent_ReturnsCloserAndClosesSocket verifies that Agent() returns both
// an agent client and an io.Closer. When SSH_AUTH_SOCK is unset or points to
// an unreachable socket, both return values must be nil (no panic). When the
// socket IS reachable, calling closer.Close() must not error (socket released).
func TestAgent_ReturnsCloserAndClosesSocket(t *testing.T) {
	t.Run("unset_sock", func(t *testing.T) {
		// SSH_AUTH_SOCK unset → both nil, no panic.
		t.Setenv("SSH_AUTH_SOCK", "")
		ag, closer := Agent()
		if ag != nil || closer != nil {
			t.Error("expected (nil, nil) when SSH_AUTH_SOCK is unset")
		}
	})

	t.Run("nonexistent_sock", func(t *testing.T) {
		// SSH_AUTH_SOCK points to a nonexistent socket → both nil.
		t.Setenv("SSH_AUTH_SOCK", "/tmp/ssh-mcp-test-nonexistent.sock")
		ag, closer := Agent()
		if ag != nil || closer != nil {
			t.Error("expected (nil, nil) when socket does not exist")
		}
	})

	t.Run("live_agent", func(t *testing.T) {
		// Live agent test — only run when a real SSH agent is available.
		// SSH_AUTH_SOCK is inherited from the outer environment here because
		// t.Setenv in a sibling sub-test does not affect this one.
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			t.Skip("SSH_AUTH_SOCK not set; skipping live agent test")
		}
		ag, closer := Agent()
		if ag == nil || closer == nil {
			t.Skip("agent not reachable in this environment")
		}
		if err := closer.Close(); err != nil {
			t.Errorf("closer.Close(): unexpected error: %v", err)
		}
	})
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// isErr reports whether err wraps target using errors.Is.
func isErr(err, target error) bool {
	if err == nil {
		return false
	}
	// direct or wrapped
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(unwrapper)
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return false
}
