package proxy

import (
	"context"
	"net"

	xproxy "golang.org/x/net/proxy"
)

// SOCKS5Config holds the parameters for a SOCKS5 proxy.
type SOCKS5Config struct {
	// Addr is the proxy address in "host:port" form, e.g. "socks5.corp:1080".
	Addr string

	// User and Password are optional authentication credentials.
	// When both are empty, the NO-AUTH method (0x00) is negotiated.
	User     string
	Password string
}

// NewSOCKS5 returns a Wrapper that dials through a SOCKS5 proxy.
//
// The implementation delegates to golang.org/x/net/proxy.SOCKS5, which
// handles the SOCKS5 handshake (method negotiation, optional
// username/password auth, and CONNECT command).
//
// Context cancellation: if the underlying proxy.Dialer implements the
// xproxy.ContextDialer extension interface (available since
// golang.org/x/net v0.20), DialContext is called directly. Otherwise the
// blocking Dial call is run in a goroutine and the connection is closed
// when ctx is cancelled.
func NewSOCKS5(cfg SOCKS5Config) Wrapper {
	return func(parent Dialer) Dialer {
		return DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socks5Dial(ctx, cfg, parent, network, addr)
		})
	}
}

// dialerAdapter wraps our Dialer into the xproxy.Dialer interface that
// golang.org/x/net/proxy.SOCKS5 expects as its fourth argument.
type dialerAdapter struct {
	d Dialer
}

// Dial implements xproxy.Dialer using a background context.
func (a dialerAdapter) Dial(network, addr string) (net.Conn, error) {
	return a.d.DialContext(context.Background(), network, addr)
}

func socks5Dial(ctx context.Context, cfg SOCKS5Config, parent Dialer, network, addr string) (net.Conn, error) {
	var auth *xproxy.Auth
	if cfg.User != "" {
		auth = &xproxy.Auth{
			User:     cfg.User,
			Password: cfg.Password,
		}
	}

	// Build the x/net SOCKS5 dialer, supplying our parent as the underlying
	// transport (so the SOCKS5 connection itself flows through the parent).
	d, err := xproxy.SOCKS5("tcp", cfg.Addr, auth, dialerAdapter{parent})
	if err != nil {
		return nil, err
	}

	// Prefer the context-aware path when available.
	if cd, ok := d.(xproxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}

	// Fallback: run blocking Dial in a goroutine, close conn on ctx cancel.
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, e := d.Dial(network, addr)
		ch <- result{c, e}
	}()

	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		// Drain the goroutine result so it doesn't leak.
		go func() {
			if r := <-ch; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}
