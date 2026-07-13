package knownhosts

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestListAndRemovePreservesOtherAndHashedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testPublicKey(t)
	lineA := gossh.MarshalAuthorizedKey(key)
	contents := "example.test " + string(lineA) + "\n" +
		"|1|aGFzaGVkLXNhbHQ=|aGFzaGVkLWhhc2g= " + string(lineA) + "\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := List(path)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 || entries[1].Hosts[0] != "[hashed]" {
		t.Fatalf("entries = %#v, want normal and hashed entries", entries)
	}
	if err := Remove(path, entries[0]); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	remaining, err := List(path)
	if err != nil {
		t.Fatalf("List after Remove: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Hosts[0] != "[hashed]" {
		t.Fatalf("remaining entries = %#v, want only hashed entry", remaining)
	}
}

func TestAppendAddsConfirmedHostKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testPublicKey(t)
	if err := Append(path, "example.test:22", key); err != nil {
		t.Fatalf("Append: %v", err)
	}
	entries, err := List(path)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Fingerprint != gossh.FingerprintSHA256(key) {
		t.Fatalf("entries = %#v, want appended key fingerprint", entries)
	}
}

func TestRevokeReplacesExactKnownHostsEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testPublicKey(t)
	if err := Append(path, "example.test:22", key); err != nil {
		t.Fatalf("Append: %v", err)
	}
	entries, err := List(path)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := Revoke(path, entries[0]); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, err := List(path)
	if err != nil {
		t.Fatalf("List after Revoke: %v", err)
	}
	if len(revoked) != 1 || !revoked[0].Revoked || revoked[0].Fingerprint != gossh.FingerprintSHA256(key) {
		t.Fatalf("revoked entries = %#v, want one revoked entry", revoked)
	}
}

func TestRevokeRejectsMarkedKnownHostsEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testPublicKey(t)
	contents := "@cert-authority example.test " + string(gossh.MarshalAuthorizedKey(key))
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	entries, err := List(path)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := Revoke(path, entries[0]); err == nil {
		t.Fatal("Revoke marked entry: expected error")
	}
}

func TestFetchHostKeyReturnsKeyWithoutAuthenticating(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	signer := testSigner(t)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		serverConfig := &gossh.ServerConfig{NoClientAuth: true}
		serverConfig.AddHostKey(signer)
		_, _, _, _ = gossh.NewServerConn(connection, serverConfig)
	}()

	key, err := FetchHostKey(listener.Addr().String())
	if err != nil {
		t.Fatalf("FetchHostKey: %v", err)
	}
	if got, want := gossh.FingerprintSHA256(key), gossh.FingerprintSHA256(signer.PublicKey()); got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
}

func testPublicKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	return testSigner(t).PublicKey()
}

func testSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}
