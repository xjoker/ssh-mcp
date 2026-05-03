package tunnel

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// Fake Dialer
// --------------------------------------------------------------------------

// fakeDialer is a test double for Dialer.
// SSHDial returns one end of a pre-created net.Pipe() pair;
// SSHListen returns a real TCP listener bound on 127.0.0.1:0.
type fakeDialer struct {
	mu sync.Mutex

	// For SSHDial: each call pops the next (local, remote) pipe pair.
	// local is what SSHDial returns; remote is the other end for the test to use.
	dialConns []pipeConn

	// For SSHListen: each call pops the next listener.
	listeners []net.Listener

	// lastListenBind records the bind argument passed to the most recent SSHListen call.
	// Used by tests to verify S-9 compliance.
	lastListenBind string

	// dialErr / listenErr make the respective call fail.
	dialErr   error
	listenErr error
}

type pipeConn struct {
	local  net.Conn // returned to the tunnel Manager
	remote net.Conn // held by the test
}

// addPipe creates a net.Pipe() pair and queues it for the next SSHDial call.
// Returns the "remote" end that the test controls.
func (f *fakeDialer) addPipe() net.Conn {
	local, remote := net.Pipe()
	f.mu.Lock()
	f.dialConns = append(f.dialConns, pipeConn{local, remote})
	f.mu.Unlock()
	return remote
}

// addListener creates a real TCP listener and queues it for the next
// SSHListen call. Returns the listener (so tests can also dial into it).
func (f *fakeDialer) addListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeDialer.addListener: %v", err)
	}
	f.mu.Lock()
	f.listeners = append(f.listeners, ln)
	f.mu.Unlock()
	return ln
}

func (f *fakeDialer) SSHDial(_ context.Context, _, _, _ string) (net.Conn, error) {
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.dialConns) == 0 {
		// Auto-create a pipe if none queued (convenience).
		local, remote := net.Pipe()
		_ = remote // caller doesn't need it
		return local, nil
	}
	pc := f.dialConns[0]
	f.dialConns = f.dialConns[1:]
	return pc.local, nil
}

func (f *fakeDialer) SSHListen(_ context.Context, _ string, bind string, _ int) (net.Listener, error) {
	if f.listenErr != nil {
		return nil, f.listenErr
	}
	f.mu.Lock()
	f.lastListenBind = bind
	defer f.mu.Unlock()
	if len(f.listeners) == 0 {
		return nil, io.EOF // nothing queued
	}
	ln := f.listeners[0]
	f.listeners = f.listeners[1:]
	return ln, nil
}

// --------------------------------------------------------------------------
// Helper
// --------------------------------------------------------------------------

func newTestManager(d Dialer) *Manager {
	return NewManager(d)
}

// waitFor polls cond until it returns true or timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("waitFor: condition not met within timeout")
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

// TestCreateLocal_DefaultBind_S9 verifies that an empty localBind defaults to
// 127.0.0.1 (S-9 requirement: never bind on 0.0.0.0).
func TestCreateLocal_DefaultBind_S9(t *testing.T) {
	fd := &fakeDialer{}
	m := newTestManager(fd)
	defer m.CloseAll()

	id, err := m.CreateLocal("server1", "", 0, "dst", 8080)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	infos := m.List()
	found := false
	for _, info := range infos {
		if info.ID == id {
			found = true
			if !strings.HasPrefix(info.LocalAddr, "127.0.0.1:") {
				t.Errorf("LocalAddr = %q, want prefix 127.0.0.1:", info.LocalAddr)
			}
		}
	}
	if !found {
		t.Fatal("tunnel id not found in List()")
	}
}

// TestCreateLocal_ExplicitEmptyBind_S9 verifies that localBind="" also
// defaults to 127.0.0.1 (same S-9 rule, tested via TunnelInfo.LocalAddr).
func TestCreateLocal_ExplicitEmptyBind_S9(t *testing.T) {
	fd := &fakeDialer{}
	m := newTestManager(fd)
	defer m.CloseAll()

	id, err := m.CreateLocal("server1", "", 0, "remote-host", 3306)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}
	infos := m.List()
	for _, info := range infos {
		if info.ID == id {
			if !strings.HasPrefix(info.LocalAddr, "127.0.0.1:") {
				t.Errorf("S-9 violated: LocalAddr = %q, expected 127.0.0.1:*", info.LocalAddr)
			}
			return
		}
	}
	t.Fatal("tunnel not found")
}

// TestCreateLocal_ForwardData verifies end-to-end data forwarding for a local
// tunnel.  The fake dialer returns one end of a net.Pipe; the test writes to
// the SSH-side end and verifies the data appears on the local-listener side.
func TestCreateLocal_ForwardData(t *testing.T) {
	fd := &fakeDialer{}
	remotePipe := fd.addPipe() // the "remote SSH side"

	m := newTestManager(fd)
	defer m.CloseAll()

	id, err := m.CreateLocal("srv", "", 0, "dst", 9999)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	// Get the listener address.
	var listenAddr string
	for _, info := range m.List() {
		if info.ID == id {
			listenAddr = info.LocalAddr
		}
	}
	if listenAddr == "" {
		t.Fatal("could not determine listener addr")
	}

	// Connect as a local client.
	clientConn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer clientConn.Close()

	payload := []byte("hello tunnel")

	// Write from client → expect it on remotePipe.
	_, err = clientConn.Write(payload)
	if err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, len(payload))
	_, err = io.ReadFull(remotePipe, buf)
	if err != nil {
		t.Fatalf("remote read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Errorf("got %q, want %q", buf, payload)
	}

	// Write from remotePipe → expect it on clientConn.
	reply := []byte("world")
	_, err = remotePipe.Write(reply)
	if err != nil {
		t.Fatalf("remote write: %v", err)
	}
	buf2 := make([]byte, len(reply))
	_, err = io.ReadFull(clientConn, buf2)
	if err != nil {
		t.Fatalf("client read reply: %v", err)
	}
	if string(buf2) != string(reply) {
		t.Errorf("reply got %q, want %q", buf2, reply)
	}
}

// TestCreateLocal_ByteCount verifies that BytesIn and BytesOut are tallied
// correctly after forwarding known-size payloads.
func TestCreateLocal_ByteCount(t *testing.T) {
	fd := &fakeDialer{}
	remotePipe := fd.addPipe()

	m := newTestManager(fd)
	defer m.CloseAll()

	id, err := m.CreateLocal("srv", "", 0, "dst", 9999)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	var listenAddr string
	for _, info := range m.List() {
		if info.ID == id {
			listenAddr = info.LocalAddr
		}
	}

	clientConn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// client → remote: 10 bytes (counted as BytesOut)
	out10 := []byte("0123456789")
	if _, err := clientConn.Write(out10); err != nil {
		t.Fatalf("write out: %v", err)
	}
	buf := make([]byte, 10)
	if _, err := io.ReadFull(remotePipe, buf); err != nil {
		t.Fatalf("read remote: %v", err)
	}

	// remote → client: 5 bytes (counted as BytesIn)
	in5 := []byte("ABCDE")
	if _, err := remotePipe.Write(in5); err != nil {
		t.Fatalf("write in: %v", err)
	}
	buf2 := make([]byte, 5)
	if _, err := io.ReadFull(clientConn, buf2); err != nil {
		t.Fatalf("read client: %v", err)
	}

	// Close both ends to let io.Copy goroutines drain.
	clientConn.Close()
	remotePipe.Close()

	waitFor(t, 2*time.Second, func() bool {
		for _, info := range m.List() {
			if info.ID == id {
				return info.BytesOut >= 10 && info.BytesIn >= 5
			}
		}
		return false
	})

	for _, info := range m.List() {
		if info.ID == id {
			if info.BytesOut < 10 {
				t.Errorf("BytesOut = %d, want >= 10", info.BytesOut)
			}
			if info.BytesIn < 5 {
				t.Errorf("BytesIn = %d, want >= 5", info.BytesIn)
			}
			return
		}
	}
}

// TestClose_ListenerShutdown verifies that after Close(), the listener is
// closed and new dial attempts to it fail.
func TestClose_ListenerShutdown(t *testing.T) {
	fd := &fakeDialer{}
	m := newTestManager(fd)

	id, err := m.CreateLocal("srv", "", 0, "dst", 1234)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	var listenAddr string
	for _, info := range m.List() {
		if info.ID == id {
			listenAddr = info.LocalAddr
		}
	}

	if err := m.Close(id); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Listener should now be closed; new connections should fail.
	conn, err := net.DialTimeout("tcp", listenAddr, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Error("expected dial to fail after Close(), but it succeeded")
	}
}

// TestCreateRemote_ForwardData verifies that a remote tunnel correctly
// forwards data from the fake SSH listener to the local destination.
func TestCreateRemote_ForwardData(t *testing.T) {
	// Set up a local TCP server that will be the "local destination".
	localServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local server listen: %v", err)
	}
	defer localServer.Close()

	localAddr := localServer.Addr().String()
	var localHost, localPortStr string
	localHost, localPortStr, _ = net.SplitHostPort(localAddr)
	var localPort int
	for i := range localPortStr {
		_ = i
	}
	// Parse port from string.
	n := 0
	for _, c := range localPortStr {
		n = n*10 + int(c-'0')
	}
	localPort = n

	fd := &fakeDialer{}
	// Create a fake SSH-side listener (the remote listener).
	fakeLn := fd.addListener(t)
	defer fakeLn.Close()

	m := newTestManager(fd)
	defer m.CloseAll()

	id, err := m.CreateRemote("srv", "127.0.0.1", 0, localHost, localPort)
	if err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}

	// Verify RemoteAddr in TunnelInfo matches the fake listener.
	for _, info := range m.List() {
		if info.ID == id {
			if !strings.HasPrefix(info.RemoteAddr, "127.0.0.1:") {
				t.Errorf("RemoteAddr = %q, want 127.0.0.1:...", info.RemoteAddr)
			}
		}
	}

	// Simulate an incoming "remote" connection by dialing into the fake listener's addr.
	remoteClient, err := net.Dial("tcp", fakeLn.Addr().String())
	if err != nil {
		t.Fatalf("dial fake listener: %v", err)
	}
	defer remoteClient.Close()

	// Accept on the local server side.
	localServerConn, err := localServer.Accept()
	if err != nil {
		t.Fatalf("local server accept: %v", err)
	}
	defer localServerConn.Close()

	// Write from remote client → local server.
	msg := []byte("remote→local")
	if _, err := remoteClient.Write(msg); err != nil {
		t.Fatalf("remote client write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(localServerConn, buf); err != nil {
		t.Fatalf("local server read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("got %q, want %q", buf, msg)
	}

	// Write from local server → remote client.
	reply := []byte("local→remote")
	if _, err := localServerConn.Write(reply); err != nil {
		t.Fatalf("local server write: %v", err)
	}
	buf2 := make([]byte, len(reply))
	if _, err := io.ReadFull(remoteClient, buf2); err != nil {
		t.Fatalf("remote client read: %v", err)
	}
	if string(buf2) != string(reply) {
		t.Errorf("reply got %q, want %q", buf2, reply)
	}
}

// TestCreateRemote_DefaultBind_S9 verifies that an empty remoteBind defaults
// to 127.0.0.1 (S-9 requirement: remote listener must not expose on wildcard).
// It checks that SSHListen is called with bind="127.0.0.1".
func TestCreateRemote_DefaultBind_S9(t *testing.T) {
	fd := &fakeDialer{}
	fakeLn := fd.addListener(t)
	defer fakeLn.Close()

	m := newTestManager(fd)
	defer m.CloseAll()

	_, err := m.CreateRemote("srv", "" /* empty = should default */, 0, "localhost", 8080)
	if err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}

	fd.mu.Lock()
	gotBind := fd.lastListenBind
	fd.mu.Unlock()

	if gotBind != "127.0.0.1" {
		t.Errorf("SSHListen called with bind=%q, want 127.0.0.1 (S-9)", gotBind)
	}
}

// TestCreateRemote_ExplicitBind_S9 verifies that an explicitly provided
// remoteBind is forwarded as-is to SSHListen (not overwritten).
func TestCreateRemote_ExplicitBind_S9(t *testing.T) {
	fd := &fakeDialer{}
	fakeLn := fd.addListener(t)
	defer fakeLn.Close()

	m := newTestManager(fd)
	defer m.CloseAll()

	_, err := m.CreateRemote("srv", "127.0.0.1", 0, "localhost", 8080)
	if err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}

	fd.mu.Lock()
	gotBind := fd.lastListenBind
	fd.mu.Unlock()

	if gotBind != "127.0.0.1" {
		t.Errorf("SSHListen called with bind=%q, want 127.0.0.1", gotBind)
	}
}

// TestCloseAll_EmptiesManager verifies that CloseAll removes all tunnels and
// List() returns empty.
func TestCloseAll_EmptiesManager(t *testing.T) {
	fd := &fakeDialer{}
	m := newTestManager(fd)

	if _, err := m.CreateLocal("srv", "", 0, "dst1", 1111); err != nil {
		t.Fatalf("CreateLocal 1: %v", err)
	}
	if _, err := m.CreateLocal("srv", "", 0, "dst2", 2222); err != nil {
		t.Fatalf("CreateLocal 2: %v", err)
	}

	if len(m.List()) != 2 {
		t.Fatalf("expected 2 tunnels before CloseAll, got %d", len(m.List()))
	}

	m.CloseAll()

	if len(m.List()) != 0 {
		t.Errorf("expected 0 tunnels after CloseAll, got %d", len(m.List()))
	}
}

// TestTunnelInfo_Fields verifies LocalAddr / RemoteAddr semantics for local
// and remote tunnel types.
func TestTunnelInfo_Fields(t *testing.T) {
	fd := &fakeDialer{}
	m := newTestManager(fd)
	defer m.CloseAll()

	// Local tunnel: LocalAddr = listener bind, RemoteAddr = dstHost:dstPort
	localID, err := m.CreateLocal("srv", "127.0.0.1", 0, "db.internal", 5432)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}
	for _, info := range m.List() {
		if info.ID == localID {
			if info.Type != "local" {
				t.Errorf("Type = %q, want local", info.Type)
			}
			if !strings.HasPrefix(info.LocalAddr, "127.0.0.1:") {
				t.Errorf("LocalAddr = %q, want 127.0.0.1:*", info.LocalAddr)
			}
			if info.RemoteAddr != "db.internal:5432" {
				t.Errorf("RemoteAddr = %q, want db.internal:5432", info.RemoteAddr)
			}
		}
	}

	// Remote tunnel
	fakeLn := fd.addListener(t)
	defer fakeLn.Close()
	remoteID, err := m.CreateRemote("srv", "127.0.0.1", 0, "localhost", 8080)
	if err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}
	for _, info := range m.List() {
		if info.ID == remoteID {
			if info.Type != "remote" {
				t.Errorf("Type = %q, want remote", info.Type)
			}
			if info.LocalAddr != "localhost:8080" {
				t.Errorf("LocalAddr = %q, want localhost:8080", info.LocalAddr)
			}
			if !strings.HasPrefix(info.RemoteAddr, "127.0.0.1:") {
				t.Errorf("RemoteAddr = %q, want 127.0.0.1:*", info.RemoteAddr)
			}
		}
	}
}
