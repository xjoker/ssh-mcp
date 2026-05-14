package ssh

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xjoker/ssh-mcp/internal/config"
)

// --------------------------------------------------------------------------
// HTTP CONNECT proxy chain integration
// --------------------------------------------------------------------------

// fakeHTTPConnectProxy listens on ln and answers each CONNECT with 200 OK,
// then transparently splices bytes between the client connection and an
// upstream TCP dial of the requested target. This is what a real HTTP
// CONNECT proxy does after the handshake.
//
// optAuth, when non-empty, requires `Proxy-Authorization: Basic <optAuth>`
// (matching the production internal/proxy/http.go header); missing or
// mismatched → 407 and the connection is closed without splicing.
//
// Returns a channel that emits the target requested by each accepted
// CONNECT so tests can verify the chain forwarded the right target.
func fakeHTTPConnectProxy(t *testing.T, ln net.Listener, optAuth string) (targets <-chan string) {
	t.Helper()
	ch := make(chan string, 4)
	go func() {
		defer close(ch)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeCONNECT(c, optAuth, ch)
		}
	}()
	return ch
}

func handleFakeCONNECT(c net.Conn, optAuth string, ch chan<- string) {
	defer c.Close()
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 2 || parts[0] != "CONNECT" {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	target := parts[1]
	var authHdr string
	for {
		hl, err := br.ReadString('\n')
		if err != nil || hl == "\r\n" || hl == "\n" {
			break
		}
		// internal/proxy/http.go emits Proxy-Authorization; accept both
		// header names to keep the helper usable for other tests.
		ln := strings.ToLower(hl)
		switch {
		case strings.HasPrefix(ln, "proxy-authorization:"):
			authHdr = strings.TrimSpace(hl[len("proxy-authorization:"):])
		case strings.HasPrefix(ln, "authorization:"):
			authHdr = strings.TrimSpace(hl[len("authorization:"):])
		}
	}
	if optAuth != "" && authHdr != "Basic "+optAuth {
		_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
		return
	}
	// Dial the upstream target so bytes can flow through after 200 OK.
	upstream, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()
	ch <- target
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// If the client buffered extra bytes past the response headers (it
	// won't for HTTP CONNECT-then-app-data, but defensively), drain them
	// into the upstream first.
	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		_, _ = br.Read(buf)
		_, _ = upstream.Write(buf)
	}
	// Bidirectional splice. Either direction's EOF tears down both.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = copyBytes(upstream, c)
		_ = upstream.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = copyBytes(c, upstream)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}

// copyBytes is a tiny io.Copy without importing io (avoids polluting the
// test file's imports — `bufio` already gave us readers, this is one-shot).
func copyBytes(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total + int64(n), werr
			}
			total += int64(n)
		}
		if err != nil {
			return total, err
		}
	}
}

// fakeTCPEcho accepts TCP and echoes — used as the chain's "target" so we
// can verify bytes flow end-to-end through the proxies.
func fakeTCPEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write(buf[:n])
				}
			}(c)
		}
	}()
	return ln
}

// TestDialViaChain_HTTPProxyEndToEnd verifies that buildChainWrappers +
// Chain.DialContext successfully tunnel a TCP byte stream through a single
// HTTP CONNECT proxy to the target. The SSH handshake itself is NOT exercised
// (the echo server doesn't speak SSH) — we test only the dial route up to
// the point where it would normally call sshHandshake.
func TestDialViaChain_HTTPProxyEndToEnd(t *testing.T) {
	// Set up echo target.
	target := fakeTCPEcho(t)
	defer target.Close()
	targetAddr := target.Addr().String()

	// Set up HTTP CONNECT proxy.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()
	proxyHost, proxyPortStr, _ := net.SplitHostPort(proxyLn.Addr().String())
	var proxyPort int
	fmt.Sscanf(proxyPortStr, "%d", &proxyPort)

	gotTargets := fakeHTTPConnectProxy(t, proxyLn, "")

	// Build cfg with [proxies.h] + a server that references it.
	srv := config.ServerConfig{
		Name:       "viachain",
		Host:       strings.Split(targetAddr, ":")[0],
		User:       "testuser",
		Auth:       "password",
		ProxyChain: []string{"h"},
	}
	// Parse target port.
	_, tPortStr, _ := net.SplitHostPort(targetAddr)
	var tPort int
	fmt.Sscanf(tPortStr, "%d", &tPort)
	srv.Port = tPort

	cfg := &config.Config{
		Servers: map[string]config.ServerConfig{srv.Name: srv},
		Proxies: map[string]config.ProxyConfig{
			"h": {Name: "h", Type: "http", Host: proxyHost, Port: proxyPort},
		},
	}

	p := NewPool(cfg, &fakeResolver{})

	// Build the chain wrappers and dial directly — we avoid dialViaChain
	// because we don't want to run sshHandshake against an echo server.
	wrappers, err := p.buildChainWrappers(context.Background(), srv, map[string]struct{}{})
	if err != nil {
		t.Fatalf("buildChainWrappers: %v", err)
	}
	if len(wrappers) != 1 {
		t.Fatalf("expected 1 wrapper, got %d", len(wrappers))
	}

	// Walk the chain manually with a base dialer.
	base := proxyDialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	})
	chain := wrappers[0](base)

	conn, err := chain.DialContext(context.Background(), "tcp", targetAddr)
	if err != nil {
		t.Fatalf("chain DialContext: %v", err)
	}
	defer conn.Close()

	// Verify the proxy saw the right target.
	select {
	case got := <-gotTargets:
		if got != targetAddr {
			t.Errorf("proxy saw target %q, want %q", got, targetAddr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never received CONNECT")
	}

	// Verify bytes flow end-to-end.
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ping\n" {
		t.Errorf("read got %q want %q", buf[:n], "ping\n")
	}
}

// TestDialViaChain_HTTPProxyBasicAuth verifies that user/password resolved
// via CredRef are sent as Authorization: Basic.
func TestDialViaChain_HTTPProxyBasicAuth(t *testing.T) {
	target := fakeTCPEcho(t)
	defer target.Close()
	targetAddr := target.Addr().String()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()
	proxyHost, proxyPortStr, _ := net.SplitHostPort(proxyLn.Addr().String())
	var proxyPort int
	fmt.Sscanf(proxyPortStr, "%d", &proxyPort)

	wantAuth := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	gotTargets := fakeHTTPConnectProxy(t, proxyLn, wantAuth)

	_, tPortStr, _ := net.SplitHostPort(targetAddr)
	var tPort int
	fmt.Sscanf(tPortStr, "%d", &tPort)

	srv := config.ServerConfig{
		Name:       "auth-srv",
		Host:       strings.Split(targetAddr, ":")[0],
		Port:       tPort,
		User:       "testuser",
		Auth:       "password",
		ProxyChain: []string{"auth-proxy"},
	}
	cfg := &config.Config{
		Settings: config.Settings{AllowConfigPlaintextPassword: true},
		Servers:  map[string]config.ServerConfig{srv.Name: srv},
		Proxies: map[string]config.ProxyConfig{
			"auth-proxy": {
				Name:     "auth-proxy",
				Type:     "http",
				Host:     proxyHost,
				Port:     proxyPort,
				User:     "alice",
				Password: config.CredRef{Kind: config.CredRefPlaintext, Value: "s3cret"},
			},
		},
	}

	p := NewPool(cfg, &fakeResolver{})
	wrappers, err := p.buildChainWrappers(context.Background(), srv, map[string]struct{}{})
	if err != nil {
		t.Fatalf("buildChainWrappers: %v", err)
	}

	base := proxyDialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	})
	chain := wrappers[0](base)

	conn, err := chain.DialContext(context.Background(), "tcp", targetAddr)
	if err != nil {
		t.Fatalf("chain DialContext (expected 200 with valid auth): %v", err)
	}
	defer conn.Close()

	select {
	case <-gotTargets:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never accepted auth + CONNECT")
	}
}

// TestDialViaChain_TwoHopsHTTP verifies that a chain with two HTTP proxies
// stacks correctly — proxy A receives the request to dial proxy B, and
// proxy B receives the request to dial the final target.
func TestDialViaChain_TwoHopsHTTP(t *testing.T) {
	target := fakeTCPEcho(t)
	defer target.Close()
	targetAddr := target.Addr().String()

	// Inner proxy: receives "CONNECT <targetAddr>".
	innerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("inner listen: %v", err)
	}
	defer innerLn.Close()
	innerHost, innerPortStr, _ := net.SplitHostPort(innerLn.Addr().String())
	var innerPort int
	fmt.Sscanf(innerPortStr, "%d", &innerPort)
	innerSeen := fakeHTTPConnectProxy(t, innerLn, "")

	// Outer proxy: receives "CONNECT <innerProxyAddr>".
	outerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("outer listen: %v", err)
	}
	defer outerLn.Close()
	outerHost, outerPortStr, _ := net.SplitHostPort(outerLn.Addr().String())
	var outerPort int
	fmt.Sscanf(outerPortStr, "%d", &outerPort)
	outerSeen := fakeHTTPConnectProxy(t, outerLn, "")

	_, tPortStr, _ := net.SplitHostPort(targetAddr)
	var tPort int
	fmt.Sscanf(tPortStr, "%d", &tPort)

	srv := config.ServerConfig{
		Name:       "twohop",
		Host:       strings.Split(targetAddr, ":")[0],
		Port:       tPort,
		User:       "testuser",
		Auth:       "password",
		ProxyChain: []string{"outer", "inner"}, // outer→inner→target
	}
	cfg := &config.Config{
		Servers: map[string]config.ServerConfig{srv.Name: srv},
		Proxies: map[string]config.ProxyConfig{
			"outer": {Name: "outer", Type: "http", Host: outerHost, Port: outerPort},
			"inner": {Name: "inner", Type: "http", Host: innerHost, Port: innerPort},
		},
	}

	p := NewPool(cfg, &fakeResolver{})

	wrappers, err := p.buildChainWrappers(context.Background(), srv, map[string]struct{}{})
	if err != nil {
		t.Fatalf("buildChainWrappers: %v", err)
	}
	if len(wrappers) != 2 {
		t.Fatalf("expected 2 wrappers, got %d", len(wrappers))
	}

	base := proxyDialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	})
	// Chain order: outer wraps base, inner wraps outer-wrapped.
	d := wrappers[0](base)
	d = wrappers[1](d)

	conn, err := d.DialContext(context.Background(), "tcp", targetAddr)
	if err != nil {
		t.Fatalf("chain DialContext: %v", err)
	}
	defer conn.Close()

	expectInnerAddr := net.JoinHostPort(innerHost, innerPortStr)
	expectTargetAddr := targetAddr

	select {
	case got := <-outerSeen:
		if got != expectInnerAddr {
			t.Errorf("outer proxy saw target %q, want %q (inner proxy)", got, expectInnerAddr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("outer proxy never received CONNECT")
	}
	select {
	case got := <-innerSeen:
		if got != expectTargetAddr {
			t.Errorf("inner proxy saw target %q, want %q (echo target)", got, expectTargetAddr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inner proxy never received CONNECT")
	}
}

// TestBuildChainWrappers_UnknownProxy verifies that a chain referencing a
// proxy name that doesn't exist in cfg.Proxies fails closed with a clear
// error. This is the runtime guard backstopping the config-layer check.
func TestBuildChainWrappers_UnknownProxy(t *testing.T) {
	srv := config.ServerConfig{
		Name:       "x",
		ProxyChain: []string{"ghost"},
	}
	cfg := &config.Config{
		Servers: map[string]config.ServerConfig{"x": srv},
		Proxies: map[string]config.ProxyConfig{},
	}
	p := NewPool(cfg, &fakeResolver{})
	_, err := p.buildChainWrappers(context.Background(), srv, map[string]struct{}{})
	if err == nil {
		t.Fatal("expected error for unknown proxy name")
	}
	if !strings.Contains(err.Error(), "unknown proxy") {
		t.Errorf("expected 'unknown proxy' in error, got: %v", err)
	}
}

// TestBuildChainWrappers_UnknownType verifies that an unsupported proxy
// type is rejected at wrapper-build time even if it slipped past config.
func TestBuildChainWrappers_UnknownType(t *testing.T) {
	srv := config.ServerConfig{
		Name:       "x",
		ProxyChain: []string{"weird"},
	}
	cfg := &config.Config{
		Servers: map[string]config.ServerConfig{"x": srv},
		Proxies: map[string]config.ProxyConfig{
			"weird": {Name: "weird", Type: "vpn"},
		},
	}
	p := NewPool(cfg, &fakeResolver{})
	_, err := p.buildChainWrappers(context.Background(), srv, map[string]struct{}{})
	if err == nil {
		t.Fatal("expected error for unknown proxy type")
	}
	if !strings.Contains(err.Error(), "unknown proxy type") {
		t.Errorf("expected 'unknown proxy type' in error, got: %v", err)
	}
}

// TestDialViaChain_HTTPProxyFailsClosedOnPolicyDeny verifies that an HTTP
// proxy returning 407 propagates as a dial error (the chain does NOT silently
// bypass the proxy or fall back to direct connection).
func TestDialViaChain_HTTPProxyFailsClosedOnPolicyDeny(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()
	proxyHost, proxyPortStr, _ := net.SplitHostPort(proxyLn.Addr().String())
	var proxyPort int
	fmt.Sscanf(proxyPortStr, "%d", &proxyPort)

	// Require auth "x" but supply none — proxy will return 407.
	_ = fakeHTTPConnectProxy(t, proxyLn, "x")

	srv := config.ServerConfig{
		Name:       "denied",
		Host:       "10.0.0.1",
		Port:       22,
		User:       "u",
		Auth:       "password",
		ProxyChain: []string{"p"},
	}
	cfg := &config.Config{
		Servers: map[string]config.ServerConfig{srv.Name: srv},
		Proxies: map[string]config.ProxyConfig{
			"p": {Name: "p", Type: "http", Host: proxyHost, Port: proxyPort},
		},
	}
	p := NewPool(cfg, &fakeResolver{})
	wrappers, err := p.buildChainWrappers(context.Background(), srv, map[string]struct{}{})
	if err != nil {
		t.Fatalf("buildChainWrappers: %v", err)
	}
	base := proxyDialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	})
	chain := wrappers[0](base)

	_, err = chain.DialContext(context.Background(), "tcp", "10.0.0.1:22")
	if err == nil {
		t.Fatal("expected dial error when proxy returns 407, got nil")
	}
	if !strings.Contains(err.Error(), "407") && !strings.Contains(err.Error(), "Proxy Authentication") {
		t.Errorf("expected 407/Proxy Authentication in error, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// proxyDialerFunc — minimal local adapter to bridge net.Dialer to
// internal/proxy.Dialer without importing the package in the test file
// (which would create a cycle if the test file lived alongside internal/proxy).
// We define it once and let the tests reuse it.
// --------------------------------------------------------------------------

type proxyDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f proxyDialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// Sanity: make sure errors.Is plumbing works for chain errors when we want
// to detect a specific proxy failure in higher-level callers down the line.
func TestDialViaChain_ErrorWrappedWithServerName(t *testing.T) {
	srv := config.ServerConfig{
		Name:       "missing-proxy-srv",
		ProxyChain: []string{"nope"},
	}
	cfg := &config.Config{
		Servers: map[string]config.ServerConfig{srv.Name: srv},
		Proxies: map[string]config.ProxyConfig{},
	}
	p := NewPool(cfg, &fakeResolver{})
	_, err := p.buildChainWrappers(context.Background(), srv, map[string]struct{}{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), srv.Name) {
		t.Errorf("error should mention server name %q for diagnostics, got: %v", srv.Name, err)
	}
	// Future-proofing: not asserting errors.Is here because the wrapping
	// is fmt.Errorf-based; only assert the textual scaffolding the AI sees.
	_ = errors.New
}
