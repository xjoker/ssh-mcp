package ssh

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/safety"
)

// pooledEntry holds one cached Client along with connection metadata.
type pooledEntry struct {
	client   *Client
	lastUsed time.Time
	// evicted marks an entry that has been (or is being) removed from
	// Pool.entries. A goroutine that acquires mu and finds evicted=true must
	// not reuse the entry — it re-fetches from the map instead. This prevents
	// a Get racing with eviction from storing a fresh connection into an
	// orphaned entry, which would leak the connection.
	evicted bool
	// mu serialises concurrent dials for the same server.
	mu sync.Mutex
}

// tempEntry holds a dynamically registered ad-hoc server together with its
// expiry time so that Pool.getInternal can reject stale entries on cache hits.
type tempEntry struct {
	srv       config.ServerConfig
	expiresAt time.Time
}

// TempServerInfo is the safe, credential-free snapshot of a runtime
// temp-server registration.
type TempServerInfo struct {
	Server    config.ServerConfig
	ExpiresAt time.Time
}

// handshakeTimeout is the maximum time allowed for the SSH handshake phase
// (after the TCP connection is established). The ctx deadline is used if it
// fires sooner. 30 s is generous enough for slow links while still bounding
// the exposure window for hung endpoints.
const handshakeTimeout = 30 * time.Second

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
	tempServers map[string]tempEntry

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
	return sshHandshake(ctx, conn, addr, cfg)
}

// sshHandshake wraps gossh.NewClientConn with a deadline and a context-watcher
// goroutine so that the handshake is always bounded. It is used by both
// realDialer (direct path) and dialViaProxy (ProxyJump path).
//
// The deadline is the minimum of handshakeTimeout and the ctx deadline (if
// any). Once the handshake completes the deadline is cleared so keepalive
// probes are not affected.
func sshHandshake(ctx context.Context, conn net.Conn, addr string, cfg *gossh.ClientConfig) (*gossh.Client, error) {
	// Compute handshake deadline: respect context deadline when it fires sooner.
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// ctx watcher: if the caller cancels ctx before NewClientConn returns,
	// close conn so the blocking read inside NewClientConn is unblocked
	// immediately rather than waiting for the deadline.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	clientConn, chans, reqs, err := gossh.NewClientConn(conn, addr, cfg)
	close(done) // stop watcher regardless of outcome
	if err != nil {
		_ = conn.Close() // ensure conn is closed on handshake failure
		return nil, fmt.Errorf("handshake: %w", err)
	}

	// Clear deadline so subsequent keepalive probes are not time-bounded.
	_ = conn.SetDeadline(time.Time{})

	return gossh.NewClient(clientConn, chans, reqs), nil
}

// NewPool creates a new Pool using the supplied config and credential resolver.
func NewPool(cfg *config.Config, resolver CredResolver) *Pool {
	return &Pool{
		cfg:         cfg,
		resolver:    resolver,
		entries:     make(map[string]*pooledEntry),
		tempServers: make(map[string]tempEntry),
		dialer:      realDialer,
	}
}

// LookupTempServer returns the ServerConfig for a previously-registered
// temp-server entry. Expired entries are not returned. Used by the tools
// layer so callers like ssh_exec / ssh_group_exec / session_start can
// resolve quick_setup-registered names without consulting cfg.Servers
// directly (which only contains statically configured servers).
func (p *Pool) LookupTempServer(name string) (config.ServerConfig, bool) {
	p.tempMu.RLock()
	defer p.tempMu.RUnlock()
	te, ok := p.tempServers[name]
	if !ok {
		return config.ServerConfig{}, false
	}
	if !te.expiresAt.IsZero() && time.Now().After(te.expiresAt) {
		return config.ServerConfig{}, false
	}
	return te.srv, true
}

// ListTempServers returns all live temp-server registrations. Expired entries
// are omitted; the reaper/lookup paths will evict them separately.
func (p *Pool) ListTempServers() []TempServerInfo {
	p.tempMu.RLock()
	defer p.tempMu.RUnlock()

	out := make([]TempServerInfo, 0, len(p.tempServers))
	now := time.Now()
	for _, te := range p.tempServers {
		if !te.expiresAt.IsZero() && now.After(te.expiresAt) {
			continue
		}
		out = append(out, TempServerInfo{
			Server:    te.srv,
			ExpiresAt: te.expiresAt,
		})
	}
	return out
}

// AddTempServer registers an ad-hoc server configuration under the given name.
// expiresAt records when the entry should be considered expired; Pool.Get will
// return an error for any cache hit whose expiry has passed. Pass a zero value
// to disable expiry checking (entry lives until RemoveTempServer is called).
//
// The entry is immediately visible to subsequent Get calls. If a server with
// the same name already exists in cfg.Servers, the temporary entry shadows it
// for the lifetime of the registration.
func (p *Pool) AddTempServer(name string, srv config.ServerConfig, expiresAt time.Time) {
	p.tempMu.Lock()
	p.tempServers[name] = tempEntry{srv: srv, expiresAt: expiresAt}
	p.tempMu.Unlock()
}

// RemoveTempServer removes a previously registered temporary server entry and
// evicts any live pooled client for the same name (closing the underlying SSH
// connection). It is safe to call even if the entry does not exist.
func (p *Pool) RemoveTempServer(name string) {
	p.tempMu.Lock()
	delete(p.tempServers, name)
	p.tempMu.Unlock()

	p.evictByName(name)
}

// evictByName closes and removes the pooled entry for name (if any). It does
// NOT touch tempServers; callers that need both must manage tempServers
// separately (e.g. RemoveTempServer).
func (p *Pool) evictByName(name string) {
	p.mu.Lock()
	entry, ok := p.entries[name]
	if ok {
		delete(p.entries, name)
	}
	p.mu.Unlock()

	if ok {
		entry.mu.Lock()
		client := entry.client
		entry.client = nil
		entry.evicted = true
		entry.mu.Unlock()
		if client != nil {
			_ = client.Close()
		}
	}
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
	te, isTemp := p.tempServers[name]
	p.tempMu.RUnlock()

	var srv config.ServerConfig
	var ok bool
	if isTemp {
		// Check expiry before returning or caching.
		if !te.expiresAt.IsZero() && time.Now().After(te.expiresAt) {
			// Expired: evict the pool entry + temp entry so future calls also fail fast.
			p.RemoveTempServer(name)
			return nil, fmt.Errorf("ssh: server %q: quick_setup entry expired", name)
		}
		srv = te.srv
		ok = true
	} else {
		srv, ok = p.cfg.Servers[name]
	}
	if !ok {
		return nil, fmt.Errorf("ssh: server %q not found in config", name)
	}

	// Fetch (or create) the pool entry and lock it. Serialises dials for this
	// specific server; skips entries that were evicted while we waited.
	entry := p.lockLiveEntry(name)
	defer entry.mu.Unlock()

	// Check again under the per-entry lock (another goroutine may have dialled).
	if entry.client != nil {
		if entry.client.IsAlive() {
			entry.lastUsed = time.Now()
			return entry.client, nil
		}
		// M01: old client is dead — close it explicitly before redialling so
		// the underlying TCP connection is released promptly.
		_ = entry.client.Close()
		entry.client = nil
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

	authMethods, adHocCleanup, err := adHocAuthMethods(params.Auth)
	if err != nil {
		return nil, fmt.Errorf("ssh: GetAdHoc: %w", err)
	}
	// Release agent socket / secret material once the dial attempt completes.
	defer adHocCleanup()

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

// lockLiveEntry returns the pooled entry for name with entry.mu held,
// creating it if absent. If the fetched entry was evicted while we waited on
// its lock, it is discarded and the map is consulted again, so the caller
// always operates on an entry that is (still) reachable from p.entries.
// The caller must release entry.mu.
//
// Lock discipline: p.mu and entry.mu are never held at the same time by any
// code path in this file. lastUsed is initialised at creation time so a
// concurrent CloseIdle never mistakes a brand-new entry for an idle one.
func (p *Pool) lockLiveEntry(name string) *pooledEntry {
	for {
		p.mu.Lock()
		entry, exists := p.entries[name]
		if !exists {
			entry = &pooledEntry{lastUsed: time.Now()}
			p.entries[name] = entry
		}
		p.mu.Unlock()

		entry.mu.Lock()
		if !entry.evicted {
			return entry
		}
		entry.mu.Unlock()
	}
}

// CloseIdle closes and removes pool entries whose lastUsed time is older than threshold.
//
// It never blocks on a busy entry: entries whose mu is held (mid-dial or
// being handed out by Get) are by definition not idle and are skipped via
// TryLock. p.mu is only held for the map snapshot/delete, never across
// entry.mu, so a slow dial cannot stall Get calls for other servers.
func (p *Pool) CloseIdle(threshold time.Duration) {
	cutoff := time.Now().Add(-threshold)

	p.mu.Lock()
	snapshot := make(map[string]*pooledEntry, len(p.entries))
	for name, entry := range p.entries {
		snapshot[name] = entry
	}
	p.mu.Unlock()

	for name, entry := range snapshot {
		if !entry.mu.TryLock() {
			continue // in use right now — not idle
		}
		if entry.evicted || !entry.lastUsed.Before(cutoff) {
			entry.mu.Unlock()
			continue
		}
		client := entry.client
		entry.client = nil
		entry.evicted = true
		entry.mu.Unlock()

		p.mu.Lock()
		// Only delete if the map still points at the entry we marked; it may
		// have been replaced by a concurrent evict+Get cycle.
		if p.entries[name] == entry {
			delete(p.entries, name)
		}
		p.mu.Unlock()

		if client != nil {
			_ = client.Close()
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
		client := entry.client
		entry.client = nil
		entry.evicted = true
		entry.mu.Unlock()
		if client != nil {
			if err := client.Close(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

// dial builds an *gossh.Client for srv. acceptNew controls whether unknown
// host keys are silently accepted (only true for ad-hoc calls).
func (p *Pool) dial(ctx context.Context, srv config.ServerConfig, acceptNew bool, visited map[string]struct{}) (*Client, error) {
	authMethods, authLabel, cleanup, err := p.resolver.ResolveServerAuth(ctx, srv)
	if err != nil {
		return nil, fmt.Errorf("resolve auth for %q: %w", srv.Name, err)
	}
	// Zero secret material (e.g. agent socket, password Secret) once the dial
	// attempt completes — the ssh.Client retains its connection, not the
	// credential material, so it is safe to release the secrets here.
	defer cleanup()

	port := srv.Port
	if port == 0 {
		port = 22
	}

	// For named/temp servers the host-key policy comes from the ServerConfig
	// field populated at registration time (e.g. by ssh_quick_setup or
	// session_start inline). The acceptNew parameter is kept for callers that
	// override it directly; named server dials also consult srv.AcceptNewHost
	// so that quick_setup's accept_new_host argument is honoured end-to-end.
	acceptNew = acceptNew || srv.AcceptNewHost

	clientCfg := &gossh.ClientConfig{
		User:              srv.User,
		Auth:              authMethods,
		HostKeyCallback:   safety.HostKeyCallback(acceptNew),
		HostKeyAlgorithms: safety.ModernHostKeyAlgorithms(),
		Config:            safety.ModernAlgorithms(p.cfg.Settings.WeakAlgorithmsOptIn),
		Timeout:           15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", srv.Host, port)

	// Dial route precedence: proxy_chain > proxy_jump > direct. The config
	// layer enforces that proxy_chain and proxy_jump are mutually exclusive,
	// so this ordering is just defensive — only one branch will be entered
	// in practice.
	if len(srv.ProxyChain) > 0 {
		return p.dialViaChain(ctx, srv, addr, clientCfg, authLabel, visited)
	}
	if srv.ProxyJump != "" {
		return p.dialViaProxy(ctx, srv, addr, clientCfg, authLabel, visited)
	}

	inner, err := p.dialer(ctx, "tcp", addr, clientCfg)
	if err != nil {
		return nil, err
	}
	return newClientWithAuthMode(inner, srv.Name, authLabel), nil
}

// dialViaProxy implements ProxyJump: obtain a jump client, open a TCP channel
// through it, then complete the SSH handshake to the target. SDD §12.4.
func (p *Pool) dialViaProxy(
	ctx context.Context,
	target config.ServerConfig,
	targetAddr string,
	targetCfg *gossh.ClientConfig,
	authLabel string,
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

	// Complete SSH handshake over the proxied connection with deadline +
	// ctx-cancellation support (H01: ProxyJump path).
	inner, err := sshHandshake(ctx, tcpConn, targetAddr, targetCfg)
	if err != nil {
		return nil, fmt.Errorf("proxy jump: SSH handshake to %s: %w", targetAddr, err)
	}

	return newClientWithAuthMode(inner, target.Name, authLabel), nil
}

// adHocAuthMethods converts an AdHocParams.Auth into a []gossh.AuthMethod
// slice plus a cleanup function. The cleanup closes any agent socket opened
// by this call (H04). Callers MUST defer the returned cleanup after a
// successful call.
func adHocAuthMethods(am AuthMethod) ([]gossh.AuthMethod, func(), error) {
	noop := func() {}
	if am.Agent {
		// Try to connect to the SSH agent via SSH_AUTH_SOCK.
		sock, err := net.Dial("unix", sshAuthSock())
		if err != nil {
			return nil, noop, fmt.Errorf("cannot connect to SSH agent: %w", err)
		}
		ag := agent.NewClient(sock)
		// cleanup closes the socket to release the file descriptor (H04).
		cleanup := func() { _ = sock.Close() }
		return []gossh.AuthMethod{gossh.PublicKeysCallback(ag.Signers)}, cleanup, nil
	}
	if am.PrivateKey != nil {
		return []gossh.AuthMethod{gossh.PublicKeys(am.PrivateKey)}, noop, nil
	}
	// H05: PasswordCallback takes precedence over Password to avoid a permanent
	// string copy. The callback is invoked by the ssh library at handshake time;
	// the caller is expected to zero the underlying secret via cleanup() after
	// the dial attempt completes.
	if am.PasswordCallback != nil {
		cb := am.PasswordCallback
		return []gossh.AuthMethod{gossh.PasswordCallback(func() (string, error) {
			return cb(), nil
		})}, noop, nil
	}
	if len(am.Password) > 0 {
		pw := string(am.Password)
		// Zero the slice immediately; pw is a local string copy that the
		// Go runtime will eventually GC, but we cannot control its lifetime.
		for i := range am.Password {
			am.Password[i] = 0
		}
		return []gossh.AuthMethod{gossh.Password(pw)}, noop, nil
	}
	return nil, noop, fmt.Errorf("AdHocParams.Auth: no authentication method set")
}
