package knownhosts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	sshknownhosts "golang.org/x/crypto/ssh/knownhosts"
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

func TestAppendIsIdempotentForSameHostKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testPublicKey(t)
	for range 2 {
		if err := Append(path, "example.test:22", key); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	entries, err := List(path)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v, want one entry", entries)
	}
}

func TestAppendIsIdempotentForDefaultPortHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testPublicKey(t)
	for range 2 {
		if err := Append(path, "example.test", key); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	entries, err := List(path)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v, want one entry", entries)
	}
}

func TestAppendRejectsMismatchedHostKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	trusted := testPublicKey(t)
	if err := Append(path, "example.test:22", trusted); err != nil {
		t.Fatalf("Append trusted: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Append(path, "example.test:22", testPublicKey(t)); err == nil {
		t.Fatal("Append mismatch: expected error")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("Append mismatch modified known_hosts")
	}
}

func TestCheckReportsTrustedUnknownMismatchAndRevoked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testPublicKey(t)
	other := testPublicKey(t)
	if status, err := Check(path, "example.test:22", key); err != nil || status != StatusUnknown {
		t.Fatalf("missing Check = %q, %v; want unknown, nil", status, err)
	}
	if err := Append(path, "example.test", key); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if status, err := Check(path, "example.test:22", key); err != nil || status != StatusTrusted {
		t.Fatalf("matching Check = %q, %v; want trusted, nil", status, err)
	}
	if status, err := Check(path, "example.test:22", other); err != nil || status != StatusMismatch {
		t.Fatalf("mismatch Check = %q, %v; want mismatch, nil", status, err)
	}
	entries, err := List(path)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := Revoke(path, entries[0]); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if status, err := Check(path, "example.test:22", key); err != nil || status != StatusMismatch {
		t.Fatalf("revoked Check = %q, %v; want mismatch, nil", status, err)
	}
}

func TestCheckRejectsMalformedKnownHostsAndSupportsHashedNonDefaultPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testPublicKey(t)
	if err := os.WriteFile(path, []byte("not a valid known_hosts line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(path, "example.test:22", key); err == nil {
		t.Fatal("malformed known_hosts: expected error")
	}
	hashedPath := filepath.Join(t.TempDir(), "known_hosts")
	line := sshknownhosts.Line([]string{sshknownhosts.HashHostname("[example.test]:2222")}, key)
	if err := os.WriteFile(hashedPath, []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if status, err := Check(hashedPath, "example.test:2222", key); err != nil || status != StatusTrusted {
		t.Fatalf("non-22 Check = %q, %v; want trusted, nil", status, err)
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
	authAttempts := make(chan string, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		serverConfig := &gossh.ServerConfig{
			AuthLogCallback: func(_ gossh.ConnMetadata, method string, _ error) {
				authAttempts <- method
			},
			PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return nil, errors.New("authentication must not be attempted")
			},
		}
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
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SSH server did not finish after FetchHostKey returned")
	}
	select {
	case method := <-authAttempts:
		t.Fatalf("FetchHostKey attempted userauth method %q", method)
	default:
	}
}

func TestFetchHostKeyHandshakeHasTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		<-release
	}()

	started := time.Now()
	if _, err := fetchHostKeyContext(context.Background(), listener.Addr().String(), 50*time.Millisecond); err == nil {
		t.Fatal("FetchHostKey handshake stall: expected timeout")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FetchHostKey handshake timeout took %s, want under 1s", elapsed)
	}
}

func TestFetchHostKeyTimeoutIsTotalDialAndHandshakeBudget(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dial := func(context.Context, string, string) (net.Conn, error) {
		time.Sleep(100 * time.Millisecond)
		return client, nil
	}
	started := time.Now()
	if _, err := fetchHostKeyContextWithDial(context.Background(), "example.test:22", 120*time.Millisecond, dial); err == nil {
		t.Fatal("FetchHostKey stalled handshake: expected timeout")
	}
	if elapsed := time.Since(started); elapsed > 180*time.Millisecond {
		t.Fatalf("FetchHostKey total timeout took %s, want one 120ms budget", elapsed)
	}
}

func TestAppendSerializesConcurrentProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	release, err := acquireKnownHostsLock(path)
	if err != nil {
		t.Fatalf("acquireKnownHostsLock: %v", err)
	}
	defer func() { _ = release() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type helper struct {
		command *exec.Cmd
		ready   string
		output  strings.Builder
		done    chan error
	}
	helpers := make([]helper, 2)
	for index := range helpers {
		helpers[index].ready = filepath.Join(t.TempDir(), "ready")
		helpers[index].done = make(chan error, 1)
		helpers[index].command = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppendLockHelperProcess$")
		helpers[index].command.Env = append(os.Environ(),
			"SSH_MCP_KNOWN_HOSTS_LOCK_HELPER=1",
			"SSH_MCP_KNOWN_HOSTS_PATH="+path,
			"SSH_MCP_KNOWN_HOSTS_READY="+helpers[index].ready,
		)
		helpers[index].command.Stdout = &helpers[index].output
		helpers[index].command.Stderr = &helpers[index].output
		if err := helpers[index].command.Start(); err != nil {
			t.Fatalf("start helper %d: %v", index, err)
		}
		go func(index int) {
			helpers[index].done <- helpers[index].command.Wait()
		}(index)
	}
	for index := range helpers {
		waitForKnownHostsFile(t, ctx, helpers[index].ready)
	}
	for index := range helpers {
		select {
		case err := <-helpers[index].done:
			t.Fatalf("helper %d bypassed held lock: %v\n%s", index, err, helpers[index].output.String())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := release(); err != nil {
		t.Fatalf("release initial lock: %v", err)
	}
	release = func() error { return nil }

	successes := 0
	mismatches := 0
	for index := range helpers {
		err := <-helpers[index].done
		output := helpers[index].output.String()
		if err == nil {
			successes++
		} else if strings.Contains(output, "host key mismatch") {
			mismatches++
		} else {
			t.Fatalf("helper %d failed: %v\n%s", index, err, output)
		}
	}
	if successes != 1 || mismatches != 1 {
		t.Fatalf("concurrent appends: successes=%d mismatches=%d, want one each", successes, mismatches)
	}
	entries, err := List(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v, want one trusted key", entries)
	}
}

func TestKnownHostsWritersAcquireCrossProcessLock(t *testing.T) {
	original := acquireKnownHostsFileLock
	t.Cleanup(func() { acquireKnownHostsFileLock = original })
	lockCalls := 0
	releaseCalls := 0
	acquireKnownHostsFileLock = func(string) (func() error, error) {
		lockCalls++
		return func() error {
			releaseCalls++
			return nil
		}, nil
	}

	appendPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := Append(appendPath, "append.example:22", testPublicKey(t)); err != nil {
		t.Fatal(err)
	}

	for _, operation := range []string{"revoke", "remove"} {
		path := filepath.Join(t.TempDir(), "known_hosts")
		key := testPublicKey(t)
		line := sshknownhosts.Line([]string{operation + ".example:22"}, key) + "\n"
		if err := os.WriteFile(path, []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
		entries, err := List(path)
		if err != nil || len(entries) != 1 {
			t.Fatalf("List(%s) = %#v, %v", operation, entries, err)
		}
		if operation == "revoke" {
			err = Revoke(path, entries[0])
		} else {
			err = Remove(path, entries[0])
		}
		if err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
	}
	if lockCalls != 3 || releaseCalls != 3 {
		t.Fatalf("lock calls=%d releases=%d, want 3 each", lockCalls, releaseCalls)
	}
}

func TestAppendLockHelperProcess(t *testing.T) {
	if os.Getenv("SSH_MCP_KNOWN_HOSTS_LOCK_HELPER") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("SSH_MCP_KNOWN_HOSTS_READY"), []byte("ready"), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := Append(os.Getenv("SSH_MCP_KNOWN_HOSTS_PATH"), "example.test:22", testPublicKey(t)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func waitForKnownHostsFile(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for helper readiness: %v", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
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
