// proxychain.go wires the generic internal/proxy chain into the SSH dial
// path. The chain is built from a server's ProxyChain (a list of named
// [proxies.<name>] entries) and used in place of the direct TCP dial.
//
// SDD §12.4-bis (proxy chain). Coexistence rules:
//   - ProxyChain takes precedence when set (config layer already enforces
//     that ProxyChain and ProxyJump are mutually exclusive).
//   - ProxyJump remains supported as a single-entry SSH-only chain.
package ssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/auth"
	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/proxy"
	"github.com/xjoker/ssh-mcp/internal/safety"
)

// dialViaChain implements ProxyChain: build a chain of proxy.Wrappers from
// the server's chain references, dial the final target through the chain,
// then complete the SSH handshake to the target.
//
// The chain order is outer-to-inner: ProxyChain[0] is the proxy reachable
// from the local host; ProxyChain[N-1] sits closest to the target and is
// the one that finally connects to <srv.Host:port>.
func (p *Pool) dialViaChain(
	ctx context.Context,
	srv config.ServerConfig,
	targetAddr string,
	targetCfg *gossh.ClientConfig,
	authLabel string,
	visited map[string]struct{},
) (*Client, error) {
	wrappers, err := p.buildChainWrappers(ctx, srv, visited)
	if err != nil {
		return nil, err
	}

	// Base dialer = system TCP dialer. Mirrors realDialer's TCP half so the
	// dialerFunc-injection used by tests (p.dialer = fake) still works for
	// the no-chain path; the chain path is its own dial route by design.
	base := proxy.DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	})
	chain := proxy.Chain(base, wrappers)

	conn, err := chain.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("server %q: proxy chain dial %s: %w", srv.Name, targetAddr, err)
	}

	inner, err := sshHandshake(ctx, conn, targetAddr, targetCfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("server %q: proxy chain SSH handshake to %s: %w", srv.Name, targetAddr, err)
	}
	return newClientWithAuthMode(inner, srv.Name, authLabel), nil
}

// buildChainWrappers translates a server's ProxyChain []string into
// concrete proxy.Wrappers, looking each name up in cfg.Proxies and
// converting per Type. The visited map is forwarded into any embedded SSH
// proxy node so recursive proxy_chain → proxy_chain → … is cycle-guarded
// at runtime in addition to the config-layer cycle check.
func (p *Pool) buildChainWrappers(
	ctx context.Context,
	srv config.ServerConfig,
	visited map[string]struct{},
) ([]proxy.Wrapper, error) {
	if p.cfg == nil {
		return nil, fmt.Errorf("server %q: proxy chain configured but pool has no config reference", srv.Name)
	}
	allowPlain := p.cfg.Settings.AllowConfigPlaintextPassword

	wrappers := make([]proxy.Wrapper, 0, len(srv.ProxyChain))
	for _, name := range srv.ProxyChain {
		lk := strings.ToLower(name)
		pc, ok := p.lookupProxy(lk)
		if !ok {
			return nil, fmt.Errorf("server %q: unknown proxy %q in proxy_chain (no matching [proxies.%s] table); if it was just added to config.toml, run list_servers with refresh=true", srv.Name, name, lk)
		}
		w, err := p.buildProxyWrapper(ctx, pc, allowPlain, visited)
		if err != nil {
			return nil, fmt.Errorf("server %q: proxy %q: %w", srv.Name, name, err)
		}
		wrappers = append(wrappers, w)
	}
	return wrappers, nil
}

// buildProxyWrapper dispatches on ProxyConfig.Type, resolving any required
// secret through auth.Resolve (respecting the plaintext gate), and returns
// a proxy.Wrapper suitable for inclusion in a chain.
func (p *Pool) buildProxyWrapper(
	ctx context.Context,
	pc config.ProxyConfig,
	allowPlain bool,
	visited map[string]struct{},
) (proxy.Wrapper, error) {
	switch pc.Type {
	case "http", "https":
		return p.buildHTTPWrapper(ctx, pc, allowPlain)
	case "socks5":
		return p.buildSOCKS5Wrapper(ctx, pc, allowPlain)
	case "ssh":
		return p.buildSSHWrapper(pc, visited), nil
	default:
		return nil, fmt.Errorf("unknown proxy type %q", pc.Type)
	}
}

func (p *Pool) buildHTTPWrapper(ctx context.Context, pc config.ProxyConfig, allowPlain bool) (proxy.Wrapper, error) {
	password, err := resolveProxyPassword(ctx, pc, allowPlain)
	if err != nil {
		return nil, err
	}
	cfg := proxy.HTTPConfig{
		Addr:     fmt.Sprintf("%s:%d", pc.Host, pc.Port),
		User:     pc.User,
		Password: password,
		UseTLS:   pc.Type == "https",
		Timeout:  30 * time.Second,
	}
	if cfg.UseTLS {
		// G402: InsecureSkipVerify is an opt-in dev-only escape hatch
		// surfaced by [proxies.<name>] insecure_skip_verify = true. The
		// config validator rejects this field on non-https proxies; the
		// README + SECURITY.md flag it as dev-only. We pass the user's
		// explicit choice through unchanged.
		cfg.TLSConfig = &tls.Config{
			ServerName:         pc.Host,
			InsecureSkipVerify: pc.InsecureSkipVerify, // #nosec G402 -- opt-in dev flag per [proxies.X] insecure_skip_verify
			MinVersion:         tls.VersionTLS12,
		}
	}
	return proxy.NewHTTPConnect(cfg), nil
}

func (p *Pool) buildSOCKS5Wrapper(ctx context.Context, pc config.ProxyConfig, allowPlain bool) (proxy.Wrapper, error) {
	password, err := resolveProxyPassword(ctx, pc, allowPlain)
	if err != nil {
		return nil, err
	}
	return proxy.NewSOCKS5(proxy.SOCKS5Config{
		Addr:     fmt.Sprintf("%s:%d", pc.Host, pc.Port),
		User:     pc.User,
		Password: password,
	}), nil
}

// buildSSHWrapper returns a Wrapper that opens a TCP channel through an SSH
// proxy. Two modes:
//
//  1. Server-reference (pc.Server != ""): recursively obtain a *Client for
//     that configured server via Pool.getInternal — this honours the
//     referenced server's own auth, host-key policy, and (transitively)
//     its own proxy_chain. This is the recommended mode.
//
//  2. Direct (pc.Host != ""): dial pc.Host:pc.Port through the parent
//     Dialer, then SSH-handshake with the credentials defined inline on
//     [proxies.<name>]. The host-key check is strict (acceptNew=false);
//     first-contact trust must be pre-established via `ssh-mcp trust`.
//
// Note: the ctx passed to the inner DialContext is the per-dial context
// from the chain caller (not closure-captured). ctx-cancellation propagates
// down to the parent.DialContext / sshHandshake.
func (p *Pool) buildSSHWrapper(pc config.ProxyConfig, visited map[string]struct{}) proxy.Wrapper {
	return func(parent proxy.Dialer) proxy.Dialer {
		return proxy.DialerFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
			if pc.Server != "" {
				cli, err := p.getInternal(ctx, pc.Server, visited)
				if err != nil {
					return nil, fmt.Errorf("ssh proxy via server %q: %w", pc.Server, err)
				}
				// Pooled jump client: the channel conn is returned as-is;
				// the pool owns the SSH connection's lifecycle.
				tcpConn, err := cli.inner.Dial("tcp", target)
				if err != nil {
					return nil, fmt.Errorf("ssh proxy %q channel to %s: %w", pc.Name, target, err)
				}
				return tcpConn, nil
			}

			// Direct mode: the SSH client exists only for this chained dial
			// and is not pooled. Tie its lifetime to the returned conn —
			// closing only the multiplexed channel would leave the client's
			// mux goroutines and TCP connection alive forever (leak).
			cli, err := p.dialDirectSSHProxy(ctx, pc, parent)
			if err != nil {
				return nil, err
			}
			tcpConn, err := cli.Dial("tcp", target)
			if err != nil {
				_ = cli.Close()
				return nil, fmt.Errorf("ssh proxy %q channel to %s: %w", pc.Name, target, err)
			}
			return &connWithCloser{Conn: tcpConn, closer: cli}, nil
		})
	}
}

// connWithCloser is a net.Conn whose Close also closes an owning resource
// (e.g. the throwaway SSH client a proxy channel is multiplexed over).
type connWithCloser struct {
	net.Conn
	closer interface{ Close() error }
	once   sync.Once
}

func (c *connWithCloser) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { _ = c.closer.Close() })
	return err
}

// dialDirectSSHProxy connects to pc.Host:pc.Port via parent and performs an
// SSH handshake using the auth credentials embedded in the ProxyConfig.
// Supported auths: agent, key, password (each via CredRef where applicable).
// The returned *gossh.Client is NOT pooled — it stays alive for the
// lifetime of the chained dial only. Callers should rely on the caller's
// connection lifecycle to clean it up indirectly (it will be GC'd once all
// channels are closed; in practice the SSH target client owns the multiplex
// channel and closing the target cascades).
func (p *Pool) dialDirectSSHProxy(
	ctx context.Context,
	pc config.ProxyConfig,
	parent proxy.Dialer,
) (*gossh.Client, error) {
	port := pc.Port
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", pc.Host, port)

	conn, err := parent.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh proxy %q dial %s: %w", pc.Name, addr, err)
	}

	authMethods, cleanup, err := buildDirectSSHProxyAuth(ctx, pc, p.cfg.Settings.AllowConfigPlaintextPassword)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh proxy %q auth: %w", pc.Name, err)
	}
	defer cleanup()

	clientCfg := &gossh.ClientConfig{
		User:              pc.User,
		Auth:              authMethods,
		HostKeyCallback:   safety.HostKeyCallback(false), // strict — no TOFU via tool path
		HostKeyAlgorithms: safety.ModernHostKeyAlgorithms(),
		Config:            safety.ModernAlgorithms(p.cfg.Settings.WeakAlgorithmsOptIn),
		Timeout:           15 * time.Second,
	}

	cli, err := sshHandshake(ctx, conn, addr, clientCfg)
	if err != nil {
		// sshHandshake already closes conn on failure.
		return nil, fmt.Errorf("ssh proxy %q handshake to %s: %w", pc.Name, addr, err)
	}
	return cli, nil
}

// buildDirectSSHProxyAuth resolves the auth methods for a direct-mode SSH
// proxy entry. Mirrors the credential resolution used by named servers but
// scoped to the small surface that ProxyConfig exposes (no KeyPassphrase
// field in v0.0.6; encrypted private keys for proxy entries must be stored
// via ssh-agent).
func buildDirectSSHProxyAuth(ctx context.Context, pc config.ProxyConfig, allowPlain bool) ([]gossh.AuthMethod, func(), error) {
	noop := func() {}
	switch pc.Auth {
	case "agent":
		ag, closer := auth.Agent()
		if ag == nil {
			return nil, noop, fmt.Errorf("ssh-agent unavailable (SSH_AUTH_SOCK not set)")
		}
		cleanup := func() { _ = closer.Close() }
		return []gossh.AuthMethod{gossh.PublicKeysCallback(ag.Signers)}, cleanup, nil
	case "key":
		if pc.KeyPath == "" {
			return nil, noop, fmt.Errorf("auth=key requires key_path")
		}
		// Read + parse synchronously; for encrypted keys the user must use
		// agent forwarding instead (ProxyConfig has no key_passphrase field).
		pemBytes, err := readKeyFile(pc.KeyPath)
		if err != nil {
			return nil, noop, err
		}
		signer, err := auth.LoadPrivateKey(pemBytes, nil)
		if err != nil {
			return nil, noop, fmt.Errorf("load private key %s: %w", pc.KeyPath, err)
		}
		return []gossh.AuthMethod{gossh.PublicKeys(signer)}, noop, nil
	case "password":
		secret, err := auth.Resolve(ctx, pc.Password, allowPlain)
		if err != nil {
			return nil, noop, fmt.Errorf("resolve password: %w", err)
		}
		// Copy bytes before secret.Close so the captured callback sees a stable string.
		pw := make([]byte, len(secret.Bytes()))
		copy(pw, secret.Bytes())
		cleanup := func() { secret.Close() }
		return []gossh.AuthMethod{gossh.Password(string(pw))}, cleanup, nil
	default:
		return nil, noop, fmt.Errorf("unknown auth %q (expected: agent, key, password)", pc.Auth)
	}
}

// readKeyFile is a tiny wrapper around os.ReadFile that gives a more
// helpful error message when the file cannot be opened.
func readKeyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key_path %s: %w", path, err)
	}
	return b, nil
}

// resolveProxyPassword resolves the CredRef on a ProxyConfig to a plaintext
// password string. Returns "" when no Password is configured.
func resolveProxyPassword(ctx context.Context, pc config.ProxyConfig, allowPlain bool) (string, error) {
	if pc.Password.IsZero() {
		return "", nil
	}
	secret, err := auth.Resolve(ctx, pc.Password, allowPlain)
	if err != nil {
		return "", fmt.Errorf("resolve proxy %q password: %w", pc.Name, err)
	}
	defer secret.Close()
	return string(secret.Bytes()), nil
}
