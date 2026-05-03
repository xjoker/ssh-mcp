// Package tunnel manages local and remote SSH port-forwarding tunnels.
// SDD §5.8, §13 (S-9).
//
// Module boundary: only imports standard library.
// Callers inject a Dialer that wraps internal/ssh.
package tunnel

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// --------------------------------------------------------------------------
// Dialer interface
// --------------------------------------------------------------------------

// Dialer abstracts the SSH-level dial/listen operations so that internal/tunnel
// does not directly import internal/ssh.
//
// The server parameter is the logical server name registered in the SSH pool.
type Dialer interface {
	// SSHDial dials network/addr through the SSH connection identified by server.
	SSHDial(ctx context.Context, server, network, addr string) (net.Conn, error)
	// SSHListen opens a remote listener on bind:port via server.
	SSHListen(ctx context.Context, server, bind string, port int) (net.Listener, error)
}

// --------------------------------------------------------------------------
// TunnelInfo
// --------------------------------------------------------------------------

// TunnelInfo is a read-only snapshot of a tunnel's state.
type TunnelInfo struct {
	ID         string
	Type       string // "local" | "remote"
	Server     string
	LocalAddr  string
	RemoteAddr string
	StartedAt  time.Time
	BytesIn    int64
	BytesOut   int64
	ConnCount  int
}

// --------------------------------------------------------------------------
// internal tunnel record
// --------------------------------------------------------------------------

type tunnelEntry struct {
	id         string
	kind       string // "local" | "remote"
	server     string
	localAddr  string
	remoteAddr string
	startedAt  time.Time

	bytesIn   atomic.Int64
	bytesOut  atomic.Int64
	connCount atomic.Int64

	listener net.Listener
	cancel   context.CancelFunc

	// connsMu guards the activeConns set.
	connsMu     sync.Mutex
	activeConns map[net.Conn]struct{}
}

func (e *tunnelEntry) addConn(c net.Conn) {
	e.connsMu.Lock()
	e.activeConns[c] = struct{}{}
	e.connsMu.Unlock()
}

func (e *tunnelEntry) removeConn(c net.Conn) {
	e.connsMu.Lock()
	delete(e.activeConns, c)
	e.connsMu.Unlock()
}

func (e *tunnelEntry) closeAllConns() {
	e.connsMu.Lock()
	conns := make([]net.Conn, 0, len(e.activeConns))
	for c := range e.activeConns {
		conns = append(conns, c)
	}
	e.connsMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (e *tunnelEntry) snapshot() TunnelInfo {
	return TunnelInfo{
		ID:         e.id,
		Type:       e.kind,
		Server:     e.server,
		LocalAddr:  e.localAddr,
		RemoteAddr: e.remoteAddr,
		StartedAt:  e.startedAt,
		BytesIn:    e.bytesIn.Load(),
		BytesOut:   e.bytesOut.Load(),
		ConnCount:  int(e.connCount.Load()),
	}
}

// --------------------------------------------------------------------------
// Manager
// --------------------------------------------------------------------------

// Manager creates and manages SSH tunnels.
type Manager struct {
	dialer Dialer

	mu      sync.Mutex
	tunnels map[string]*tunnelEntry
}

// NewManager returns a Manager backed by the given Dialer.
func NewManager(d Dialer) *Manager {
	return &Manager{
		dialer:  d,
		tunnels: make(map[string]*tunnelEntry),
	}
}

// --------------------------------------------------------------------------
// CreateLocal — local port-forwarding: local listener → SSH → remote dst
// --------------------------------------------------------------------------

// CreateLocal creates a local port-forward tunnel.
// Traffic arriving at localBind:localPort is forwarded through the SSH
// connection for server to dstHost:dstPort.
//
// S-9: if localBind is empty it defaults to 127.0.0.1 (never 0.0.0.0).
func (m *Manager) CreateLocal(
	server, localBind string,
	localPort int,
	dstHost string,
	dstPort int,
) (id string, err error) {
	// S-9: default local bind to loopback only.
	if localBind == "" {
		localBind = "127.0.0.1"
	}

	listenAddr := net.JoinHostPort(localBind, strconv.Itoa(localPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", fmt.Errorf("tunnel: CreateLocal: listen %s: %w", listenAddr, err)
	}

	id, err = newUUID()
	if err != nil {
		_ = ln.Close()
		return "", fmt.Errorf("tunnel: CreateLocal: generate id: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	entry := &tunnelEntry{
		id:          id,
		kind:        "local",
		server:      server,
		localAddr:   ln.Addr().String(),
		remoteAddr:  net.JoinHostPort(dstHost, strconv.Itoa(dstPort)),
		startedAt:   time.Now(),
		listener:    ln,
		cancel:      cancel,
		activeConns: make(map[net.Conn]struct{}),
	}

	m.mu.Lock()
	m.tunnels[id] = entry
	m.mu.Unlock()

	go m.localAcceptLoop(ctx, entry, dstHost, dstPort)
	return id, nil
}

func (m *Manager) localAcceptLoop(ctx context.Context, e *tunnelEntry, dstHost string, dstPort int) {
	defer e.cancel()
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			// Listener closed or context done.
			return
		}
		go m.localForward(ctx, e, conn, dstHost, dstPort)
	}
}

func (m *Manager) localForward(ctx context.Context, e *tunnelEntry, local net.Conn, dstHost string, dstPort int) {
	defer local.Close()

	remoteAddr := net.JoinHostPort(dstHost, strconv.Itoa(dstPort))
	remote, err := m.dialer.SSHDial(ctx, e.server, "tcp", remoteAddr)
	if err != nil {
		return
	}
	defer remote.Close()

	e.addConn(local)
	e.addConn(remote)
	defer e.removeConn(local)
	defer e.removeConn(remote)

	e.connCount.Add(1)

	var wg sync.WaitGroup
	wg.Add(2)

	// local → remote (bytesOut: bytes leaving the local side toward remote)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(remote, local)
		e.bytesOut.Add(n)
		_ = remote.Close()
	}()

	// remote → local (bytesIn: bytes arriving from remote to local)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(local, remote)
		e.bytesIn.Add(n)
		_ = local.Close()
	}()

	wg.Wait()
}

// --------------------------------------------------------------------------
// CreateRemote — remote port-forwarding: remote listener → SSH → local dst
// --------------------------------------------------------------------------

// CreateRemote creates a remote port-forward tunnel.
// Traffic arriving at remoteBind:remotePort on the SSH server is forwarded
// locally to localHost:localPort.
//
// S-9: if remoteBind is empty it defaults to 127.0.0.1 so the remote listener
// is restricted to loopback only (never wildcard). This is symmetric with
// CreateLocal's default.
func (m *Manager) CreateRemote(
	server, remoteBind string,
	remotePort int,
	localHost string,
	localPort int,
) (id string, err error) {
	// S-9: default remote bind to loopback only.
	if remoteBind == "" {
		remoteBind = "127.0.0.1"
	}

	ctx, cancel := context.WithCancel(context.Background())

	ln, err := m.dialer.SSHListen(ctx, server, remoteBind, remotePort)
	if err != nil {
		cancel()
		return "", fmt.Errorf("tunnel: CreateRemote: SSHListen %s:%d: %w", remoteBind, remotePort, err)
	}

	id, err = newUUID()
	if err != nil {
		cancel()
		_ = ln.Close()
		return "", fmt.Errorf("tunnel: CreateRemote: generate id: %w", err)
	}

	entry := &tunnelEntry{
		id:          id,
		kind:        "remote",
		server:      server,
		localAddr:   net.JoinHostPort(localHost, strconv.Itoa(localPort)),
		remoteAddr:  ln.Addr().String(),
		startedAt:   time.Now(),
		listener:    ln,
		cancel:      cancel,
		activeConns: make(map[net.Conn]struct{}),
	}

	m.mu.Lock()
	m.tunnels[id] = entry
	m.mu.Unlock()

	go m.remoteAcceptLoop(ctx, entry, localHost, localPort)
	return id, nil
}

func (m *Manager) remoteAcceptLoop(ctx context.Context, e *tunnelEntry, localHost string, localPort int) {
	defer e.cancel()
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			return
		}
		go m.remoteForward(ctx, e, conn, localHost, localPort)
	}
}

func (m *Manager) remoteForward(ctx context.Context, e *tunnelEntry, remote net.Conn, localHost string, localPort int) {
	defer remote.Close()

	localAddr := net.JoinHostPort(localHost, strconv.Itoa(localPort))
	local, err := net.Dial("tcp", localAddr)
	if err != nil {
		return
	}
	defer local.Close()

	e.addConn(remote)
	e.addConn(local)
	defer e.removeConn(remote)
	defer e.removeConn(local)

	e.connCount.Add(1)

	var wg sync.WaitGroup
	wg.Add(2)

	// remote → local (bytesIn: bytes arriving from remote)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(local, remote)
		e.bytesIn.Add(n)
		_ = local.Close()
	}()

	// local → remote (bytesOut: bytes going back to remote)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(remote, local)
		e.bytesOut.Add(n)
		_ = remote.Close()
	}()

	wg.Wait()
}

// --------------------------------------------------------------------------
// Close / CloseAll / List
// --------------------------------------------------------------------------

// Close shuts down the tunnel identified by id.
// Returns an error if id is not found.
func (m *Manager) Close(id string) error {
	m.mu.Lock()
	entry, ok := m.tunnels[id]
	if ok {
		delete(m.tunnels, id)
	}
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("tunnel: Close: id %q not found", id)
	}

	entry.cancel()
	_ = entry.listener.Close()
	entry.closeAllConns()
	return nil
}

// CloseAll shuts down every active tunnel.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	entries := make([]*tunnelEntry, 0, len(m.tunnels))
	for _, e := range m.tunnels {
		entries = append(entries, e)
	}
	m.tunnels = make(map[string]*tunnelEntry)
	m.mu.Unlock()

	for _, e := range entries {
		e.cancel()
		_ = e.listener.Close()
		e.closeAllConns()
	}
}

// List returns a snapshot of all active tunnels.
func (m *Manager) List() []TunnelInfo {
	m.mu.Lock()
	out := make([]TunnelInfo, 0, len(m.tunnels))
	for _, e := range m.tunnels {
		out = append(out, e.snapshot())
	}
	m.mu.Unlock()
	return out
}

// --------------------------------------------------------------------------
// UUID v4 helper (crypto/rand, no external deps)
// --------------------------------------------------------------------------

// newUUID generates a random UUID v4 string (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx).
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Set version 4.
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits (RFC 4122).
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
