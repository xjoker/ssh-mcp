package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const defaultConnectTimeout = 30 * time.Second

// HTTPConfig holds the parameters for an HTTP CONNECT proxy.
type HTTPConfig struct {
	// Addr is the proxy address in "host:port" form, e.g. "proxy.corp:8080".
	Addr string

	// User and Password are optional Basic-auth credentials.
	User     string
	Password string

	// UseTLS upgrades the connection to the proxy server itself with TLS
	// (i.e. an "https" proxy). The target CONNECT tunnel is still plain TCP
	// from the proxy's perspective.
	UseTLS bool

	// TLSConfig is used when UseTLS is true. If nil, a default config with
	// ServerName derived from Addr is used.
	TLSConfig *tls.Config

	// Timeout bounds the CONNECT round-trip (dial to proxy + read 200 OK).
	// Defaults to 30 s when zero.
	Timeout time.Duration
}

// NewHTTPConnect returns a Wrapper that implements HTTP CONNECT proxying.
func NewHTTPConnect(cfg HTTPConfig) Wrapper {
	return func(parent Dialer) Dialer {
		return DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return httpConnectDial(ctx, cfg, parent, addr)
		})
	}
}

// httpConnectDial performs the HTTP CONNECT handshake and returns a net.Conn
// that is positioned right after the "200 Connection Established" response.
func httpConnectDial(ctx context.Context, cfg HTTPConfig, parent Dialer, target string) (net.Conn, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultConnectTimeout
	}

	// Apply CONNECT timeout as a context deadline (honouring any tighter
	// deadline already set by the caller).
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 1. Dial the proxy server itself via the parent dialer.
	conn, err := parent.DialContext(dialCtx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("http proxy: dial %s: %w", cfg.Addr, err)
	}

	// ctx-watcher: if the parent context (or dialCtx) is cancelled while we
	// are doing the CONNECT handshake, close the conn to unblock any blocking
	// Read/Write call (http.ReadResponse, tls.Handshake, etc.).
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-dialCtx.Done():
			_ = conn.Close()
		case <-watchDone:
		}
	}()

	// 2. Optionally upgrade to TLS (https proxy).
	if cfg.UseTLS {
		tlsCfg := cfg.TLSConfig
		if tlsCfg == nil {
			host := cfg.Addr
			if h, _, err2 := net.SplitHostPort(cfg.Addr); err2 == nil {
				host = h
			}
			tlsCfg = &tls.Config{ServerName: host} //nolint:gosec // caller controls cfg
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err = tlsConn.HandshakeContext(dialCtx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("http proxy: TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	// 3. Send the CONNECT request.
	req, err := buildConnectRequest(target, cfg.User, cfg.Password)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy: build request: %w", err)
	}
	if _, err = conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy: write CONNECT: %w", err)
	}

	// 4. Read the response status line + headers. Use bufio.Reader so we can
	//    read until \r\n\r\n without over-consuming bytes that belong to the
	//    tunnel payload.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy: read response: %w", err)
	}
	// Drain headers; body must be closed to allow connection reuse semantics,
	// but for CONNECT the body is empty (no content after the blank line).
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy: CONNECT %s: %s", target, resp.Status)
	}

	// 5. Any bytes the bufio.Reader already pulled from conn (beyond the
	//    response headers) must be prepended back to the readable stream.
	//    This is important when the remote end sends data immediately after
	//    the 200 response (rare but valid).
	if br.Buffered() > 0 {
		buffered := make([]byte, br.Buffered())
		if _, err = io.ReadFull(br, buffered); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("http proxy: drain buffer: %w", err)
		}
		return &prefixedConn{Conn: conn, r: bytes.NewReader(buffered)}, nil
	}

	return conn, nil
}

// buildConnectRequest serialises an HTTP CONNECT request to a byte slice.
func buildConnectRequest(target, user, password string) ([]byte, error) {
	var sb strings.Builder
	sb.WriteString("CONNECT ")
	sb.WriteString(target)
	sb.WriteString(" HTTP/1.1\r\nHost: ")
	sb.WriteString(target)
	sb.WriteString("\r\n")
	if user != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		sb.WriteString("Proxy-Authorization: Basic ")
		sb.WriteString(creds)
		sb.WriteString("\r\n")
	}
	sb.WriteString("Proxy-Connection: keep-alive\r\n\r\n")
	return []byte(sb.String()), nil
}

// prefixedConn is a net.Conn that prepends an in-memory buffer to Read calls.
// It is returned when the bufio.Reader consumed bytes past the HTTP headers.
type prefixedConn struct {
	net.Conn
	r *bytes.Reader
}

// Read reads from the prefix buffer first, then falls through to the
// underlying conn once the prefix is exhausted.
func (c *prefixedConn) Read(b []byte) (int, error) {
	if c.r.Len() > 0 {
		return c.r.Read(b)
	}
	return c.Conn.Read(b)
}
