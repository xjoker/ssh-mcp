package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Chain tests
// ---------------------------------------------------------------------------

// TestChain_Empty verifies that Chain with no hops returns the base dialer
// unchanged (same interface value — verified by a sentinel side-effect).
func TestChain_Empty(t *testing.T) {
	called := false
	base := DialerFunc(func(_ context.Context, _, _ string) (net.Conn, error) {
		called = true
		return nil, nil
	})
	result := Chain(base, nil)

	// Verify it is the exact same Dialer by invoking it and checking the
	// sentinel that only the original base sets.
	_, _ = result.DialContext(context.Background(), "tcp", "x:1")
	if !called {
		t.Fatal("Chain(base, nil) did not return base — sentinel not set")
	}
}

// TestChain_OrderOuterToInner verifies that hops are applied so the outermost
// hop (hops[0]) is reached first and the innermost (hops[len-1]) last.
//
// Call order expected: hopB.DialContext → hopA.DialContext → base.DialContext
// (B wraps A which wraps base; when we Dial, we enter B first, which calls A,
// which calls base).
func TestChain_OrderOuterToInner(t *testing.T) {
	var order []string
	var mu sync.Mutex
	record := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}

	base := DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		record("base")
		return &net.TCPConn{}, nil
	})

	// hopA wraps base: when Dialing, records "A" then calls parent.
	wrapA := func(parent Dialer) Dialer {
		return DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			record("A")
			return parent.DialContext(ctx, network, addr)
		})
	}

	// hopB wraps whatever is passed as parent: records "B" then calls parent.
	wrapB := func(parent Dialer) Dialer {
		return DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			record("B")
			return parent.DialContext(ctx, network, addr)
		})
	}

	// Chain(base, [wrapA, wrapB]):
	//   d0 = base
	//   d1 = wrapA(base)   → A wraps base
	//   d2 = wrapB(d1)     → B wraps (A wraps base)
	// Calling d2.DialContext records B, then A, then base.
	chained := Chain(base, []Wrapper{wrapA, wrapB})

	if _, err := chained.DialContext(context.Background(), "tcp", "target:1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()

	want := []string{"B", "A", "base"}
	if len(got) != len(want) {
		t.Fatalf("call order: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("order[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP CONNECT fake proxy helpers
// ---------------------------------------------------------------------------

// startFakeHTTPProxy starts a fake HTTP CONNECT proxy on a random local port.
// handler is called after the 200 OK is written; it receives the client conn
// and the CONNECT target string.  The listener is closed when t.Cleanup runs.
func startFakeHTTPProxy(t *testing.T, handler func(conn net.Conn, target string)) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHTTPCONNECT(conn, handler, http.StatusOK, "")
		}
	}()
	return ln
}

// startFakeHTTPProxyWithStatus is like startFakeHTTPProxy but replies with a
// custom status instead of 200.
func startFakeHTTPProxyWithStatus(t *testing.T, statusCode int, statusText string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHTTPCONNECT(conn, nil, statusCode, statusText)
		}
	}()
	return ln
}

// serveHTTPCONNECT reads one CONNECT request and replies with the given status.
// If status == 200 and handler != nil, handler is called with the raw conn.
func serveHTTPCONNECT(conn net.Conn, handler func(net.Conn, string), statusCode int, statusText string) {
	defer func() {
		if statusCode != http.StatusOK {
			_ = conn.Close()
		}
	}()

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	// Drain remaining headers.
	var authHeader string
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" {
			break
		}
		if strings.HasPrefix(h, "Proxy-Authorization:") {
			authHeader = strings.TrimSpace(strings.TrimPrefix(h, "Proxy-Authorization:"))
		}
		_ = authHeader // stored for use in handler if needed
	}

	target := ""
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		target = parts[1]
	}

	if statusCode == http.StatusOK {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if handler != nil {
			handler(conn, target)
		}
	} else {
		msg := statusText
		if msg == "" {
			msg = http.StatusText(statusCode)
		}
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n\r\n", statusCode, msg)
	}
}

// startFakeHTTPProxyCapturing starts a proxy that captures the raw Authorization
// header value and stores it via a pointer.
func startFakeHTTPProxyCapturing(t *testing.T, capturedAuth *string, mu *sync.Mutex) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				// Drain request line.
				_, _ = br.ReadString('\n')
				for {
					h, err := br.ReadString('\n')
					if err != nil || h == "\r\n" {
						break
					}
					if strings.HasPrefix(h, "Proxy-Authorization:") {
						val := strings.TrimSpace(strings.TrimPrefix(h, "Proxy-Authorization:"))
						mu.Lock()
						*capturedAuth = val
						mu.Unlock()
					}
				}
				_, _ = fmt.Fprint(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				// echo back
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln
}

// ---------------------------------------------------------------------------
// HTTP CONNECT tests
// ---------------------------------------------------------------------------

// TestHTTPConnect_Success starts a fake proxy, dials through it, writes "ping",
// reads back "ping" from a simple echo handler.
func TestHTTPConnect_Success(t *testing.T) {
	ln := startFakeHTTPProxy(t, func(conn net.Conn, _ string) {
		// Echo handler: reflect everything back.
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	})

	cfg := HTTPConfig{Addr: ln.Addr().String()}
	w := NewHTTPConnect(cfg)
	base := DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	})
	d := w(base)

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want %q", buf, "ping")
	}
}

// TestHTTPConnect_AuthBasic verifies that the correct Basic auth header is sent.
func TestHTTPConnect_AuthBasic(t *testing.T) {
	var (
		captured string
		mu       sync.Mutex
	)
	ln := startFakeHTTPProxyCapturing(t, &captured, &mu)

	cfg := HTTPConfig{
		Addr:     ln.Addr().String(),
		User:     "alice",
		Password: "s3cr3t",
	}
	d := NewHTTPConnect(cfg)(DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}))

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()

	mu.Lock()
	auth := captured
	mu.Unlock()

	// Header looks like: Basic <base64(user:password)>
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("Authorization header %q does not start with 'Basic '", auth)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if string(decoded) != "alice:s3cr3t" {
		t.Fatalf("decoded credentials %q, want %q", decoded, "alice:s3cr3t")
	}
}

// TestHTTPConnect_NonSuccess verifies that a non-200 response returns an error
// containing the status line.
func TestHTTPConnect_NonSuccess(t *testing.T) {
	ln := startFakeHTTPProxyWithStatus(t, 407, "Proxy Authentication Required")

	cfg := HTTPConfig{Addr: ln.Addr().String()}
	d := NewHTTPConnect(cfg)(DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}))

	_, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Fatalf("error %q does not contain '407'", err.Error())
	}
}

// TestHTTPConnect_ContextCancel verifies that cancelling the context during
// the CONNECT round-trip causes DialContext to return promptly.
func TestHTTPConnect_ContextCancel(t *testing.T) {
	// A proxy that blocks after accepting the connection: never writes 200.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without responding.
			go func() {
				time.Sleep(10 * time.Second)
				_ = conn.Close()
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())

	cfg := HTTPConfig{Addr: ln.Addr().String(), Timeout: 5 * time.Second}
	d := NewHTTPConnect(cfg)(DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}))

	done := make(chan error, 1)
	go func() {
		_, e := d.DialContext(ctx, "tcp", "example.com:80")
		done <- e
	}()

	// Cancel almost immediately.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case dialErr := <-done:
		if dialErr == nil {
			t.Fatal("expected error after context cancel, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DialContext did not return after context cancel")
	}
}

// TestHTTPConnect_OverTLS verifies that HTTP CONNECT works over a TLS proxy
// connection using a self-signed certificate with InsecureSkipVerify.
func TestHTTPConnect_OverTLS(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}

	// Start a TLS listener.
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsCfgServer := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln := tls.NewListener(rawLn, tlsCfgServer)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHTTPCONNECT(conn, func(c net.Conn, _ string) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}, http.StatusOK, "")
		}
	}()

	clientTLS := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	cfg := HTTPConfig{
		Addr:      ln.Addr().String(),
		UseTLS:    true,
		TLSConfig: clientTLS,
	}
	d := NewHTTPConnect(cfg)(DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}))

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello-tls")
	if _, err = conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

// ---------------------------------------------------------------------------
// SOCKS5 fake proxy helpers
// ---------------------------------------------------------------------------

// socks5Method constants.
const (
	socks5NoAuth       = byte(0x00)
	socks5UserPassAuth = byte(0x02)
	socks5NoAcceptable = byte(0xFF)
	socks5Version      = byte(0x05)
	socks5CmdConnect   = byte(0x01)
	socks5AddrDomain   = byte(0x03)
)

// startFakeSOCKS5 starts a fake SOCKS5 server. If requireAuth is true, only
// method 0x02 (username/password) is accepted using wantUser/wantPass.
func startFakeSOCKS5(t *testing.T, requireAuth bool, wantUser, wantPass string, handler func(net.Conn)) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5(conn, requireAuth, wantUser, wantPass, handler)
		}
	}()
	return ln
}

// serveSOCKS5 handles one SOCKS5 connection (simplified, IPv4/domain only).
func serveSOCKS5(conn net.Conn, requireAuth bool, wantUser, wantPass string, handler func(net.Conn)) {
	defer conn.Close()

	// Greeting: read version + nmethods + methods.
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != socks5Version {
		return
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Choose method.
	if requireAuth {
		found := false
		for _, m := range methods {
			if m == socks5UserPassAuth {
				found = true
				break
			}
		}
		if !found {
			_, _ = conn.Write([]byte{socks5Version, socks5NoAcceptable})
			return
		}
		_, _ = conn.Write([]byte{socks5Version, socks5UserPassAuth})

		// Sub-negotiation: version(1) + ulen(1) + user + plen(1) + pass
		authBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, authBuf); err != nil {
			return
		}
		// authBuf[0] = sub-version (0x01), authBuf[1] = ulen
		ulen := int(authBuf[1])
		user := make([]byte, ulen)
		if _, err := io.ReadFull(conn, user); err != nil {
			return
		}
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenBuf); err != nil {
			return
		}
		pass := make([]byte, int(plenBuf[0]))
		if _, err := io.ReadFull(conn, pass); err != nil {
			return
		}
		if string(user) != wantUser || string(pass) != wantPass {
			_, _ = conn.Write([]byte{0x01, 0x01}) // failure
			return
		}
		_, _ = conn.Write([]byte{0x01, 0x00}) // success
	} else {
		// No-auth.
		_, _ = conn.Write([]byte{socks5Version, socks5NoAuth})
	}

	// Request: VER CMD RSV ATYP ...
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != socks5Version || hdr[1] != socks5CmdConnect {
		return
	}

	// Parse address (we only need to consume it; we won't actually dial).
	switch hdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4+2)
		_, _ = io.ReadFull(conn, addr)
	case socks5AddrDomain:
		lenBuf := make([]byte, 1)
		_, _ = io.ReadFull(conn, lenBuf)
		domainPort := make([]byte, int(lenBuf[0])+2)
		_, _ = io.ReadFull(conn, domainPort)
	case 0x04: // IPv6
		addr := make([]byte, 16+2)
		_, _ = io.ReadFull(conn, addr)
	}

	// Reply: success, bound to 0.0.0.0:0.
	_, _ = conn.Write([]byte{
		socks5Version, 0x00, 0x00,
		0x01,                   // IPv4
		0x00, 0x00, 0x00, 0x00, // 0.0.0.0
		0x00, 0x00, // port 0
	})

	if handler != nil {
		handler(conn)
	}
}

// ---------------------------------------------------------------------------
// SOCKS5 tests
// ---------------------------------------------------------------------------

// TestSOCKS5_NoAuth verifies that a SOCKS5 proxy requiring no authentication
// can be dialled and used for echo.
func TestSOCKS5_NoAuth(t *testing.T) {
	ln := startFakeSOCKS5(t, false, "", "", func(conn net.Conn) {
		// Echo.
		_, _ = io.Copy(conn, conn)
	})

	cfg := SOCKS5Config{Addr: ln.Addr().String()}
	d := NewSOCKS5(cfg)(DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}))

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err = conn.Write([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hi" {
		t.Fatalf("got %q, want %q", buf, "hi")
	}
}

// TestSOCKS5_Auth verifies that SOCKS5 user/password authentication (method
// 0x02) is negotiated and accepted when credentials are provided.
func TestSOCKS5_Auth(t *testing.T) {
	ln := startFakeSOCKS5(t, true, "bob", "hunter2", func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
	})

	cfg := SOCKS5Config{
		Addr:     ln.Addr().String(),
		User:     "bob",
		Password: "hunter2",
	}
	d := NewSOCKS5(cfg)(DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}))

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	msg := []byte("socks5-auth-test")
	if _, err = conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

// ---------------------------------------------------------------------------
// TLS self-signed certificate helper
// ---------------------------------------------------------------------------

// generateSelfSignedCert returns a tls.Certificate with an ECDSA P-256 key.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Build tls.Certificate from raw DER bytes.
	cert, err := tls.X509KeyPair(
		pemEncode("CERTIFICATE", certDER),
		pemEncode("EC PRIVATE KEY", privDER),
	)
	return cert, err
}

// pemEncode wraps DER bytes in a minimal PEM block (no pem package needed).
func pemEncode(typ string, der []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	sb.WriteString("-----BEGIN ")
	sb.WriteString(typ)
	sb.WriteString("-----\n")
	// Wrap at 64 chars per line.
	for len(enc) > 64 {
		sb.WriteString(enc[:64])
		sb.WriteByte('\n')
		enc = enc[64:]
	}
	if len(enc) > 0 {
		sb.WriteString(enc)
		sb.WriteByte('\n')
	}
	sb.WriteString("-----END ")
	sb.WriteString(typ)
	sb.WriteString("-----\n")
	return []byte(sb.String())
}
