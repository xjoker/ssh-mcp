package tools

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/knownhosts"
	"github.com/xjoker/ssh-mcp/internal/ssh"
)

func TestSSHHostScanDirectReportsUnknownWithoutWritingKnownHosts(t *testing.T) {
	addr, key, closeServer := startHostScanServer(t)
	defer closeServer()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	resp := handleSSHHostScanAtPath(minDeps(true), json.RawMessage(`{"host":"`+host+`","port":`+port+`}`), path)
	if !resp.OK {
		t.Fatalf("scan = %+v", resp.Error)
	}
	out := decodeHostScan(t, resp.Data)
	if out.KnownHostsStatus != "unknown" || out.TrustCommand != "ssh-mcp trust --host "+host+" --port "+port {
		t.Fatalf("output = %+v", out)
	}
	if out.KeyType != key.Type() || out.FingerprintSHA256 != gossh.FingerprintSHA256(key) {
		t.Fatalf("key output = %+v", out)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scan wrote known_hosts: %v", err)
	}
}

func TestSSHHostScanCancellationInterruptsHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		close(accepted)
		<-release
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-accepted
		cancel()
	}()
	started := time.Now()
	resp := handleSSHHostScanAtPathContext(ctx, minDeps(true), json.RawMessage(`{"host":"`+host+`","port":`+port+`}`), filepath.Join(t.TempDir(), "known_hosts"))
	if resp.OK {
		t.Fatal("cancelled scan unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancelled scan took %s, want under 1s", elapsed)
	}
}

func TestSSHHostScanKnownHostsStatusesAndInputValidation(t *testing.T) {
	addr, key, closeServer := startHostScanServer(t)
	defer closeServer()
	host, port, _ := net.SplitHostPort(addr)
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := knownhosts.Append(path, net.JoinHostPort(host, port), key); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	resp := handleSSHHostScanAtPath(minDeps(true), json.RawMessage(`{"host":"`+host+`","port":`+port+`}`), path)
	if !resp.OK {
		t.Fatalf("trusted scan = %+v", resp.Error)
	}
	if out := decodeHostScan(t, resp.Data); out.KnownHostsStatus != "trusted" || out.TrustCommand != "" {
		t.Fatalf("trusted output = %+v", out)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("known_hosts changed: %v", err)
	}
	for _, raw := range []string{
		`{}`, `{"server":"x","host":"example.test"}`, `{"server":"x","port":22}`,
		`{"host":"bad;host"}`, `{"host":"example.test","port":65536}`,
	} {
		if got := handleSSHHostScanAtPath(minDeps(true), json.RawMessage(raw), path); got.OK {
			t.Fatalf("%s: expected invalid input", raw)
		}
	}
	mismatchPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := knownhosts.Append(mismatchPath, net.JoinHostPort(host, port), testHostScanKey(t)); err != nil {
		t.Fatal(err)
	}
	mismatch := handleSSHHostScanAtPath(minDeps(true), json.RawMessage(`{"host":"`+host+`","port":`+port+`}`), mismatchPath)
	if !mismatch.OK {
		t.Fatalf("mismatch scan = %+v", mismatch.Error)
	}
	if out := decodeHostScan(t, mismatch.Data); out.KnownHostsStatus != "mismatch" || out.TrustCommand != "" || out.VerificationHint == "" {
		t.Fatalf("mismatch output = %+v", out)
	}
}

func TestSSHHostScanResolvesConfiguredAndTemporaryAlias(t *testing.T) {
	deps := minDeps(true)
	deps.Cfg = &config.Config{Servers: map[string]config.ServerConfig{"cfg": {Host: "127.0.0.1", Port: 2222}, "shadow": {Host: "static.test", Port: 2200}}}
	if host, port, err := resolveHostScanTarget(deps, hostScanInput{Server: "CFG"}); err != nil || host != "127.0.0.1" || port != 2222 {
		t.Fatalf("config = %q,%d,%v", host, port, err)
	}
	pool := ssh.NewPool(deps.Cfg, nil)
	deps.Pool = pool
	pool.AddTempServer("tmp", config.ServerConfig{Host: "::1", Port: 2200}, time.Time{})
	pool.AddTempServer("shadow", config.ServerConfig{Host: "temp.test", Port: 2201}, time.Time{})
	if host, port, err := resolveHostScanTarget(deps, hostScanInput{Server: "TMP"}); err != nil || host != "::1" || port != 2200 {
		t.Fatalf("temp = %q,%d,%v", host, port, err)
	}
	if host, port, err := resolveHostScanTarget(deps, hostScanInput{Server: "SHADOW"}); err != nil || host != "temp.test" || port != 2201 {
		t.Fatalf("shadow = %q,%d,%v", host, port, err)
	}
	if host, port, err := resolveHostScanTarget(deps, hostScanInput{Host: "::1"}); err != nil || host != "::1" || port != 22 {
		t.Fatalf("IPv6 direct = %q,%d,%v", host, port, err)
	}
}

func TestHostScanTargetValidationSupportsIPv6ZoneAndAbsoluteFQDN(t *testing.T) {
	for _, host := range []string{"fe80::1%en0", "fe80::1%3", "fe80::1%eth0.100", "host.example."} {
		if _, _, err := resolveHostScanTarget(nil, hostScanInput{Host: host}); err != nil {
			t.Fatalf("%q rejected: %v", host, err)
		}
	}
	for _, host := range []string{"-bad.example", "bad..example", "bad host", "bad;host", "fe80::1%en0;touch", "fe80::1%en0 bad", "fe80::1%en0$HOME", "fe80::1%en0`id`", "fe80::1%en0\\x"} {
		if _, _, err := resolveHostScanTarget(nil, hostScanInput{Host: host}); err == nil {
			t.Fatalf("%q accepted", host)
		}
	}
}

func TestSSHHostScanSchemaIsClosedAndExclusive(t *testing.T) {
	text := string(sshHostScanSchema)
	for _, want := range []string{`"additionalProperties":false`, `"oneOf"`, `"not"`, `"minLength":1`} {
		if !strings.Contains(text, want) {
			t.Fatalf("schema missing %s: %s", want, text)
		}
	}
}

func TestScanTrustCommandUsesParametersWithoutYes(t *testing.T) {
	if got, want := scanTrustCommand("::1", 22), "ssh-mcp trust --host ::1 --port 22"; got != want || strings.Contains(got, "--yes") {
		t.Fatalf("trust command = %q, want %q without --yes", got, want)
	}
}

func TestHostKeyUnknownHintsAreIdentical(t *testing.T) {
	const want = "First connection to an unknown host. Run ssh_host_scan first for the same server alias or host+port to inspect the SHA256 fingerprint, then have the user manually trust the host and retry. Do not retry or bypass host-key verification."
	err := &wrappedErr{"HOST_KEY_UNKNOWN for host: not in known_hosts"}
	if got := mapSSHConnErr(err).Error.Hint; got != want {
		t.Fatalf("conn hint = %q", got)
	}
	if got := mapSessionError(err).Error.Hint; got != want {
		t.Fatalf("session hint = %q", got)
	}
}

func TestSSHHostScanDescriptorAnnotations(t *testing.T) {
	tool := toolSSHHostScan()
	if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint || tool.Annotations.IdempotentHint || !tool.Annotations.OpenWorldHint {
		t.Fatalf("annotations = %+v", tool.Annotations)
	}
	if !strings.Contains(tool.Description, "before authentication") || !strings.Contains(tool.Description, "Never reads credentials") || !strings.Contains(tool.Description, "writes known_hosts") {
		t.Fatalf("description = %q", tool.Description)
	}
}

func decodeHostScan(t *testing.T, data any) hostScanOutput {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var out hostScanOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func startHostScanServer(t *testing.T) (string, gossh.PublicKey, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	privateKey := testHostScanPrivateKey(t)
	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				cfg := &gossh.ServerConfig{PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
					return nil, errors.New("authentication must not be attempted")
				}}
				cfg.AddHostKey(signer)
				_, _, _, _ = gossh.NewServerConn(c, cfg)
			}()
		}
	}()
	return listener.Addr().String(), signer.PublicKey(), func() { _ = listener.Close(); <-done }
}

func testHostScanKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	signer, err := gossh.NewSignerFromKey(testHostScanPrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}
func testHostScanPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
