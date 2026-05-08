// Package auth resolves CredRef values into live secrets and provides
// SSH agent and private-key helpers. See SDD §5.3, §8.1–§8.4.
package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"

	keyring "github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/xjoker/ssh-mcp/internal/config"
)

// --------------------------------------------------------------------------
// Sentinel errors — SDD §5.3
// --------------------------------------------------------------------------

var (
	// ErrKeychainUnavailable is returned when the OS keychain backend is not
	// available or accessible (e.g., no secret service on headless Linux).
	ErrKeychainUnavailable = errors.New("auth: keychain unavailable")

	// ErrKeyNotFound is returned when the requested key does not exist in the
	// keychain or the environment variable is unset / empty.
	ErrKeyNotFound = errors.New("auth: key not found")

	// ErrPlaintextDisabled is returned by Resolve when ref.Kind ==
	// CredRefPlaintext and allowPlaintext == false.
	ErrPlaintextDisabled = errors.New("auth: plaintext credentials are disabled")

	// ErrPassphraseRequired is returned by LoadPrivateKey when the key is
	// encrypted but no passphrase was supplied.
	ErrPassphraseRequired = errors.New("auth: passphrase required for encrypted key")
)

// --------------------------------------------------------------------------
// Secret — SDD §5.3, §8.2
// --------------------------------------------------------------------------

// Secret wraps a byte slice containing sensitive material. The zero value
// is not usable; always obtain via NewSecret.
//
// Contract:
//   - Bytes() is the only way to access the contents; the returned slice
//     must not be retained beyond the immediate call.
//   - String() panics to prevent accidental fmt.Sprintf leaks.
//   - Close() zeros the underlying buffer; it is idempotent.
type Secret struct {
	buf    []byte
	closed bool
}

// NewSecret copies b into a new Secret. The caller's slice is not shared.
func NewSecret(b []byte) *Secret {
	cp := make([]byte, len(b))
	copy(cp, b)
	return &Secret{buf: cp}
}

// Bytes returns the underlying byte slice. The caller must not retain the
// slice across a Close call.
func (s *Secret) Bytes() []byte {
	if s == nil || s.closed {
		return nil
	}
	return s.buf
}

// String panics intentionally to prevent secrets from being logged via
// fmt.Sprintf("%v", secret) or similar.
func (s *Secret) String() string {
	panic("auth: Secret.String() called — secrets must not be stringified")
}

// Close zeros the underlying buffer and marks the secret as closed.
// Subsequent calls are safe (no-op). SDD §8.2.
func (s *Secret) Close() {
	if s == nil || s.closed {
		return
	}
	buf := s.buf
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
	s.buf = nil
	s.closed = true
}

// --------------------------------------------------------------------------
// Resolve — SDD §8.1
// --------------------------------------------------------------------------

// Resolve resolves a CredRef to a *Secret. Returns nil, nil for CredRefNone.
//
// Sentinel errors:
//   - ErrKeychainUnavailable — backend not reachable
//   - ErrKeyNotFound         — entry absent in keychain or env var unset
//   - ErrPlaintextDisabled   — allowPlaintext=false and ref is plaintext
func Resolve(_ context.Context, ref config.CredRef, allowPlaintext bool) (*Secret, error) {
	switch ref.Kind {
	case config.CredRefNone:
		return nil, nil

	case config.CredRefKeychain:
		val, err := keyring.Get(ref.Service, ref.Account)
		if err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				return nil, fmt.Errorf("%w: keychain %s/%s", ErrKeyNotFound, ref.Service, ref.Account)
			}
			// Any other keyring error (dbus unavailable, SecItemCopyMatching
			// failure, etc.) is treated as backend unavailability.
			if isKeychainUnavailable(err) {
				return nil, fmt.Errorf("%w: %v", ErrKeychainUnavailable, err)
			}
			return nil, fmt.Errorf("%w: %v", ErrKeychainUnavailable, err)
		}
		return NewSecret([]byte(val)), nil

	case config.CredRefEnv:
		val := os.Getenv(ref.EnvVar)
		if val == "" {
			return nil, fmt.Errorf("%w: env var %q is unset or empty", ErrKeyNotFound, ref.EnvVar)
		}
		return NewSecret([]byte(val)), nil

	case config.CredRefPlaintext:
		if !allowPlaintext {
			return nil, ErrPlaintextDisabled
		}
		return NewSecret([]byte(ref.Value)), nil

	default:
		return nil, fmt.Errorf("auth: unknown CredRefKind %d", ref.Kind)
	}
}

// isKeychainUnavailable heuristically classifies a keyring error as a
// backend-unavailability issue rather than a missing-entry issue.
// go-keyring does not export rich error types beyond ErrNotFound, so we
// fall back to string inspection for known patterns.
func isKeychainUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	unavailableKeywords := []string{
		"not implemented",
		"unavailable",
		"not supported",
		"no such interface",
		"dbus",
		"secret service",
		"org.freedesktop",
	}
	for _, kw := range unavailableKeywords {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return true // conservative: treat unknown keyring errors as unavailable
}

// --------------------------------------------------------------------------
// Keychain helpers — SDD §5.3
// --------------------------------------------------------------------------

// SetKeychain stores secret under (service, account) in the OS keychain.
func SetKeychain(service, account string, secret []byte) error {
	if err := keyring.Set(service, account, string(secret)); err != nil {
		return fmt.Errorf("auth: SetKeychain %s/%s: %w", service, account, err)
	}
	return nil
}

// DeleteKeychain removes the entry for (service, account) from the OS
// keychain. Returns ErrKeyNotFound if the entry does not exist.
func DeleteKeychain(service, account string) error {
	if err := keyring.Delete(service, account); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("%w: keychain %s/%s", ErrKeyNotFound, service, account)
		}
		return fmt.Errorf("auth: DeleteKeychain %s/%s: %w", service, account, err)
	}
	return nil
}

// ListKeychain returns the accounts stored under service. go-keyring does
// not expose a native list operation across all backends; this returns an
// error on all platforms for MVP. Callers should handle this gracefully.
func ListKeychain(service string) ([]string, error) {
	return nil, fmt.Errorf("auth: ListKeychain(%q): keychain list not supported on this backend", service)
}

// --------------------------------------------------------------------------
// Agent — SDD §5.3, §8.3
// --------------------------------------------------------------------------

// Agent returns an ssh-agent client connected to SSH_AUTH_SOCK and the
// underlying net.Conn as an io.Closer. Both are nil if SSH_AUTH_SOCK is
// unset or the connection fails. Callers MUST call closer.Close() when the
// agent client is no longer needed to release the file descriptor (H04).
func Agent() (agent.ExtendedAgent, io.Closer) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil
	}
	return agent.NewClient(conn), conn
}

// --------------------------------------------------------------------------
// LoadPrivateKey — SDD §5.3, §8.1
// --------------------------------------------------------------------------

// LoadPrivateKey parses a PEM-encoded private key. If the key is encrypted,
// passphrase is used to decrypt it. Returns ErrPassphraseRequired when the
// key is encrypted but passphrase == nil.
func LoadPrivateKey(pemBytes []byte, passphrase *Secret) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err == nil {
		return signer, nil
	}

	var passErr *ssh.PassphraseMissingError
	if !errors.As(err, &passErr) {
		return nil, fmt.Errorf("auth: LoadPrivateKey: %w", err)
	}

	// Key is encrypted.
	if passphrase == nil {
		return nil, ErrPassphraseRequired
	}

	signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase.Bytes())
	if err != nil {
		return nil, fmt.Errorf("auth: LoadPrivateKey: %w", err)
	}
	return signer, nil
}
