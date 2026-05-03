package ssh

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
)

// pooledEntry holds one cached Client along with connection metadata.
type pooledEntry struct {
	client   *Client
	lastUsed time.Time
	// mu serialises concurrent dials for the same server.
	mu sync.Mutex
}

// Pool manages a collection of reusable SSH clients keyed by server name.
type Pool struct {
	cfg      *config.Config
	resolver CredResolver

	mu      sync.Mutex
	entries map[string]*pooledEntry

	// tempMu guards tempServers, which holds dynamically added ad-hoc servers
	// registered via ssh_quick_setup. Entries here take precedence over cfg.Servers
	// during Get lookups.
	tempMu      sync.RWMutex
	tempServers map[string]config.ServerConfig

	// dialer is an internal hook for testing: it replaces the real SSH dial.
	dialer dialerFunc
}

// dialerFunc is the internal interface for dialing. In production it calls
// gossh.Dial / gossh.NewClientConn; in tests it can be replaced with a stub.
type dialerFunc func(ctx context.Context, network, addr string, cfg *gossh.ClientConfig) (*gossh.Client, error)

// realDialer performs an actual TCP dial then SSH handshake.
func realDialer(ctx context.Context, network, addr string, cfg *gossh.ClientConfig) (*gossh.Client, error) {
	// Respect context for the TCP connection.
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return gossh.NewClient(sshConn, chans, reqs), nil
}

// NewPool creates a new Pool using the supplied config and credential resolver.
func NewPool(cfg *config.Config, resolver CredResolver) *Pool {
	return &Pool{
		cfg:         cfg,
		resolver:    resolver,
		entries:     make(map[string]*pooledEntry),
		tempServers: make(map[string]config.ServerConfig),
		dialer:      realDialer,
	}
}

// AddTempServer registers an ad-hoc server configuration under the given name.
// The entry is immediately visible to subsequent Get calls. Callers (such as the
// ssh_quick_setup tool flow) are responsible for removing or expiring the entry
// by calling RemoveTempServer when the TTL expires.
//
// If a server with the same name already exists in cfg.Servers, the temporary
// entry shadows it for the lifetime of the registration.
func (p *Pool) AddTempServer(name string, srv config.ServerConfig) {
	p.tempMu.Lock()
	p.tempServers[name] = srv
	p.tempMu.Unlock()
}

// RemoveTempServer removes a previously registered temporary server entry.
// It is safe to call even if the entry does not exist.
func (p *Pool) RemoveTempServer(name string) {
	p.tempMu.Lock()
	delete(p.tempServers, name)
	p.tempMu.Unlock()
}

// Get returns a live Client for the named server, reusing a cached connection
// if available and alive. If multiple goroutines call Get for the same name
// concurrently only one dial is attempted.
func (p *Pool) Get(ctx context.Context, name string) (*Client, error) {
	return p.getInternal(ctx, name, nil)
}

// getInternal is the shared implementation used by both Get and recursive
// ProxyJump dialling. visited tracks names already being dialled in the
// current call chain (cycle detection).
func (p *Pool) getInternal(ctx context.Context, name string, visited map[string]struct{}) (*Client, error) {
	if visited == nil {
		visited = make(map[string]struct{})
	}
	if _, already := visited[name]; already {
		return nil, fmt.Errorf("ssh: ProxyJump cycle detected for server %q", name)
	}
	visited[name] = struct{}{}

	// Resolve server config: temp servers take precedence over static config.
	p.tempMu.RLock()
	srv, ok := p.tempServers[name]
	p.tempMu.RUnlock()
	if !ok {
		srv, ok = p.cfg.Servers[name]
	}
	if !ok {
		return nil, fmt.Errorf("ssh: server %q not found in config", name)
	}

	// Fetch or create the pool entry (without locking the inner mutex yet).
	p.mu.Lock()
	entry, exists := p.entries[name]
	if !exists {
		entry = &pooledEntry{}
		p.entries[name] = entry
	}
	p.mu.Unlock()

	// Serialise dials for this specific server.
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Check again under the per-entry lock (another goroutine may have dialled).
	if entry.client != nil && entry.client.IsAlive() {
		entry.lastUsed = time.Now()
		return entry.client, nil
	}

	// Need to dial.
	client, err := p.dial(ctx, srv, false, visited)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %q: %w", name, err)
	}

	entry.client = client
	entry.lastUsed = time.Now()
	return client, nil
}

// GetAdHoc dials a one-off connection that is NOT cached in the pool.
// Caller must call Close() on the returned Client.
func (p *Pool) GetAdHoc(ctx context.Context, params AdHocParams) (*Client, error) {
	port := params.Port
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", params.Host, port)

	authMethods, err := adHocAuthMethods(params.Auth)
	if err != nil {
		return nil, fmt.Errorf("ssh: GetAdHoc: %w", err)
	}

	clientCfg := &gossh.ClientConfig{
		User:              params.User,
		Auth:              authMethods,
		HostKeyCallback:   safety.HostKeyCallback(params.AcceptNewHost),
		HostKeyAlgorithms: safety.ModernHostKeyAlgorithms(),
		Config:            safety.ModernAlgorithms(p.cfg.Settings.WeakAlgorithmsOptIn),
		Timeout:           15 * time.Second,
	}

	inner, err := p.dialer(ctx, "tcp", addr, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh: GetAdHoc: dial %s: %w", addr, err)
	}

	label := fmt.Sprintf("adhoc:%s@%s", params.User, addr)
	return newClient(inner, label), nil
}

// CloseIdle closes and removes pool entries whose lastUsed time is older than threshold.
func (p *Pool) CloseIdle(threshold time.Duration) {
	cutoff := time.Now().Add(-threshold)

	p.mu.Lock()
	var toClose []*pooledEntry
	var toRemove []string
	for name, entry := range p.entries {
		// Lock the entry to read lastUsed safely.
		entry.mu.Lock()
		if entry.lastUsed.Before(cutoff) {
			toClose = append(toClose, entry)
			toRemove = append(toRemove, name)
		}
		entry.mu.Unlock()
	}
	for _, name := range toRemove {
		delete(p.entries, name)
	}
	p.mu.Unlock()

	for _, entry := range toClose {
		if entry.client != nil {
			_ = entry.client.Close()
		}
	}
}

// Close closes all pooled connections and clears the pool.
func (p *Pool) Close() error {
	p.mu.Lock()
	entries := p.entries
	p.entries = make(map[string]*pooledEntry)
	p.mu.Unlock()

	var lastErr error
	for _, entry := range entries {
		entry.mu.Lock()
		if entry.client != nil {
			if err := entry.client.Close(); err != nil {
				lastErr = err
			}
		}
		entry.mu.Unlock()
	}
	return lastErr
}

// dial builds an *gossh.Client for srv. acceptNew controls whether unknown
// host keys are silently accepted (only true for ad-hoc calls).
func (p *Pool) dial(ctx context.Context, srv config.ServerConfig, acceptNew bool, visited map[string]struct{}) (*Client, error) {
	authMethods, _, err := p.resolver.ResolveServerAuth(ctx, srv)
	if err != nil {
		return nil, fmt.Errorf("resolve auth for %q: %w", srv.Name, err)
	}

	port := srv.Port
	if port == 0 {
		port = 22
	}

	clientCfg := &gossh.ClientConfig{
		User:              srv.User,
		Auth:              authMethods,
		HostKeyCallback:   safety.HostKeyCallback(acceptNew),
		HostKeyAlgorithms: safety.ModernHostKeyAlgorithms(),
		Config:            safety.ModernAlgorithms(p.cfg.Settings.WeakAlgorithmsOptIn),
		Timeout:           15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", srv.Host, port)

	if srv.ProxyJump != "" {
		return p.dialViaProxy(ctx, srv, addr, clientCfg, visited)
	}

	inner, err := p.dialer(ctx, "tcp", addr, clientCfg)
	if err != nil {
		return nil, err
	}
	return newClient(inner, srv.Name), nil
}

// dialViaProxy implements ProxyJump: obtain a jump client, open a TCP channel
// through it, then complete the SSH handshake to the target. SDD §12.4.
func (p *Pool) dialViaProxy(
	ctx context.Context,
	target config.ServerConfig,
	targetAddr string,
	targetCfg *gossh.ClientConfig,
	visited map[string]struct{},
) (*Client, error) {
	jumpClient, err := p.getInternal(ctx, target.ProxyJump, visited)
	if err != nil {
		return nil, fmt.Errorf("proxy jump via %q: %w", target.ProxyJump, err)
	}

	// Open a TCP channel through the jump host to the target.
	tcpConn, err := jumpClient.inner.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy jump: dial target %s: %w", targetAddr, err)
	}

	// Complete SSH handshake over the proxied connection.
	sshConn, chans, reqs, err := gossh.NewClientConn(tcpConn, targetAddr, targetCfg)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("proxy jump: SSH handshake to %s: %w", targetAddr, err)
	}

	inner := gossh.NewClient(sshConn, chans, reqs)
	return newClient(inner, target.Name), nil
}

// adHocAuthMethods converts an AdHocParams.Auth into a []gossh.AuthMethod slice.
func adHocAuthMethods(am AuthMethod) ([]gossh.AuthMethod, error) {
	if am.Agent {
		// Try to connect to the SSH agent via SSH_AUTH_SOCK.
		sock, err := net.Dial("unix", sshAuthSock())
		if err != nil {
			return nil, fmt.Errorf("cannot connect to SSH agent: %w", err)
		}
		ag := agent.NewClient(sock)
		return []gossh.AuthMethod{gossh.PublicKeysCallback(ag.Signers)}, nil
	}
	if am.PrivateKey != nil {
		return []gossh.AuthMethod{gossh.PublicKeys(am.PrivateKey)}, nil
	}
	// H05: PasswordCallback takes precedence over Password to avoid a permanent
	// string copy. The callback is invoked by the ssh library at handshake time;
	// the caller is expected to zero the underlying secret via cleanup() after
	// the dial attempt completes.
	if am.PasswordCallback != nil {
		cb := am.PasswordCallback
		return []gossh.AuthMethod{gossh.PasswordCallback(func() (string, error) {
			return cb(), nil
		})}, nil
	}
	if len(am.Password) > 0 {
		pw := string(am.Password)
		// Zero the slice immediately; pw is a local string copy that the
		// Go runtime will eventually GC, but we cannot control its lifetime.
		for i := range am.Password {
			am.Password[i] = 0
		}
		return []gossh.AuthMethod{gossh.Password(pw)}, nil
	}
	return nil, fmt.Errorf("AdHocParams.Auth: no authentication method set")
}
