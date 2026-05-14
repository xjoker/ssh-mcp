// Package proxy provides chainable network dialers for tunnelling connections
// through HTTP CONNECT and SOCKS5 proxies. Proxy wrappers are composable via
// Chain so that multi-hop topologies (e.g. SOCKS5 → HTTP CONNECT → target)
// can be expressed as a simple slice of Wrappers applied in outer-to-inner
// order.
//
// SSH-level proxy support (ProxyJump, SSH-over-SSH) is NOT in this package —
// it lives in internal/ssh to avoid circular dependencies with internal/ssh.Pool.
package proxy

import (
	"context"
	"net"
)

// Dialer abstracts a network dialer. The base dialer is net.Dialer; proxy
// wrappers wrap a parent Dialer to insert their protocol's handshake.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialerFunc lets you use a closure as a Dialer (useful for tests and the
// base net.Dialer{}.DialContext).
type DialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialContext implements Dialer.
func (f DialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// Wrapper is the factory shape: given a parent Dialer, produce a new Dialer
// that uses the parent to reach the proxy itself. This lets callers build
// hops without knowing the parent yet.
type Wrapper func(parent Dialer) Dialer
