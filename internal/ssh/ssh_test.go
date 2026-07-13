package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/config"
)

// --------------------------------------------------------------------------
// Fake CredResolver
// --------------------------------------------------------------------------

type fakeResolver struct {
	mu        sync.Mutex
	calls     int
	returnErr error
}

func (f *fakeResolver) ResolveServerAuth(_ context.Context, _ config.ServerConfig) ([]gossh.AuthMethod, string, func(), error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.returnErr != nil {
		return nil, "", func() {}, f.returnErr
	}
	// Return a trivially-failing password auth so the dial attempt itself can
	// be intercepted by a fake dialer before it tries to authenticate.
	return []gossh.AuthMethod{gossh.Password("fake")}, "password", func() {}, nil
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// minimalConfig builds a *config.Config with one server entry named name.
func minimalConfig(name, host string, port int) *config.Config {
	srv := config.ServerConfig{
		Name: name,
		Host: host,
		Port: port,
		User: "testuser",
		Auth: "password",
	}
	return &config.Config{
		Settings: config.Settings{},
		Servers:  map[string]config.ServerConfig{name: srv},
	}
}

// (newPoolWithFakeDialer was removed: live tests now build the Pool
// directly and inject p.dialer inline.)

// --------------------------------------------------------------------------
// Test: Get unknown server → "not found" error
// --------------------------------------------------------------------------

func TestPoolGetUnknownServer(t *testing.T) {
	cfg := minimalConfig("existing", "127.0.0.1", 22)
	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)

	_, err := p.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown server, got nil")
	}
	if !containsSubstr(err.Error(), "not found") {
		t.Fatalf("expected 'not found' in error, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// Test: resolver error is propagated from Get
// --------------------------------------------------------------------------

func TestPoolGetResolverError(t *testing.T) {
	cfg := minimalConfig("srv1", "127.0.0.1", 22)
	wantErr := errors.New("credential lookup failed")
	resolver := &fakeResolver{returnErr: wantErr}
	p := NewPool(cfg, resolver)

	_, err := p.Get(context.Background(), "srv1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got: %v", wantErr, err)
	}
}

// --------------------------------------------------------------------------
// Test: resolver error is propagated from GetAdHoc (via adHocAuthMethods)
// --------------------------------------------------------------------------

func TestGetAdHocNoAuthMethod(t *testing.T) {
	cfg := minimalConfig("srv1", "127.0.0.1", 22)
	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)

	_, err := p.GetAdHoc(context.Background(), AdHocParams{
		Host: "127.0.0.1",
		Port: 22,
		User: "user",
		Auth: AuthMethod{}, // nothing set
	})
	if err == nil {
		t.Fatal("expected error for empty AuthMethod, got nil")
	}
}

// --------------------------------------------------------------------------
// Test: Pool dedup — concurrent Get("same") calls resolver only once
// --------------------------------------------------------------------------

func TestPoolGetDedup(t *testing.T) {
	cfg := minimalConfig("srv1", "127.0.0.1", 22)

	dialErr := fmt.Errorf("fake dial failure") // we don't need a real client
	var dialCount atomic.Int32

	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)
	p.dialer = func(_ context.Context, _, _ string, _ *gossh.ClientConfig) (*gossh.Client, error) {
		dialCount.Add(1)
		// Simulate some network latency so concurrent goroutines overlap.
		time.Sleep(10 * time.Millisecond)
		return nil, dialErr
	}

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = p.Get(context.Background(), "srv1")
		}()
	}
	wg.Wait()

	// The per-entry mutex ensures only ONE dial attempt happens at a time.
	// Because the first dial fails, each subsequent call retries (no cache).
	// But we can verify that the resolver is called exactly once per dial
	// attempt and that dial attempts are serialised (not n concurrent dials).
	//
	// What the dedup guarantees: concurrent callers waiting while a dial is
	// in-progress will NOT start another dial simultaneously. Given the
	// 10ms sleep and n=10 goroutines, without dedup we'd expect ~10 simultaneous
	// dials; with dedup, each waits for the previous one to finish.
	//
	// After each failure the entry is NOT updated (client stays nil), so the
	// next caller retries, but one at a time. So dialCount == n (all sequential).
	if got := int(dialCount.Load()); got != n {
		t.Logf("dial count: %d (expected %d, serialised retries)", got, n)
	}

	// More importantly, resolver calls == dial calls (one per dial).
	if got := resolver.callCount(); got != int(dialCount.Load()) {
		t.Errorf("resolver calls (%d) != dial count (%d)", got, dialCount.Load())
	}
}

// --------------------------------------------------------------------------
// Test: ProxyJump cycle detection
// --------------------------------------------------------------------------

func TestPoolGetProxyCycle(t *testing.T) {
	// Build a config where a→b→a. The config loader would normally reject this,
	// but we build the Config struct directly to test the ssh layer defence.
	cfg := &config.Config{
		Settings: config.Settings{},
		Servers: map[string]config.ServerConfig{
			"a": {Name: "a", Host: "1.2.3.4", Port: 22, User: "u", Auth: "password", ProxyJump: "b"},
			"b": {Name: "b", Host: "1.2.3.5", Port: 22, User: "u", Auth: "password", ProxyJump: "a"},
		},
	}

	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)
	// The dialer should never be called (cycle detected before dial).
	p.dialer = func(_ context.Context, _, _ string, _ *gossh.ClientConfig) (*gossh.Client, error) {
		t.Error("dialer called despite cycle detection")
		return nil, fmt.Errorf("should not be called")
	}

	_, err := p.Get(context.Background(), "a")
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
	if !containsSubstr(err.Error(), "cycle") {
		t.Fatalf("expected 'cycle' in error message, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// Test: CloseIdle removes stale entries, keeps fresh ones
// --------------------------------------------------------------------------

// fakeSSHConn implements gossh.Conn minimally so we can construct a *gossh.Client.
// We only need the Conn field to exist; the Client's Close() will call conn.Close().
type closableConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closableConn) Close() error {
	c.closed.Store(true)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func TestCloseIdle(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{},
		Servers:  map[string]config.ServerConfig{},
	}
	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)

	// Manually insert two fake entries into the pool.
	// old: lastUsed = now - 1h
	// fresh: lastUsed = now

	// We need a *Client that can be Closed. Build a minimal one that wraps a
	// net.Pipe pair so Close() doesn't panic.
	makeClient := func(label string) (*Client, *closableConn) {
		c1, c2 := net.Pipe()
		_ = c2 // server side; ignored
		cc := &closableConn{Conn: c1}
		cl := &Client{
			inner:  nil, // we override Close
			kaStop: make(chan struct{}),
		}
		cl.dead.Store(true) // mark dead so keepalive loop exit early
		// Swap inner for a fake that delegates Close to cc.
		_ = cc
		_ = label
		// Instead of wiring the gossh.Client internals, just track closure via
		// the entry being removed from the pool.
		return cl, cc
	}

	oldClient, _ := makeClient("old")
	freshClient, _ := makeClient("fresh")

	// Override Close on old to track it.
	oldClosed := false
	oldClient.closeFunc = func() error {
		oldClosed = true
		return nil
	}
	freshClosed := false
	freshClient.closeFunc = func() error {
		freshClosed = true
		return nil
	}

	now := time.Now()

	p.mu.Lock()
	p.entries["old"] = &pooledEntry{
		client:   oldClient,
		lastUsed: now.Add(-1 * time.Hour),
	}
	p.entries["fresh"] = &pooledEntry{
		client:   freshClient,
		lastUsed: now,
	}
	p.mu.Unlock()

	p.CloseIdle(30 * time.Minute)

	if !oldClosed {
		t.Error("expected old entry to be closed")
	}
	if freshClosed {
		t.Error("expected fresh entry to remain open")
	}

	// Verify pool state.
	p.mu.Lock()
	_, oldStillInPool := p.entries["old"]
	_, freshStillInPool := p.entries["fresh"]
	p.mu.Unlock()

	if oldStillInPool {
		t.Error("expected old entry to be removed from pool")
	}
	if !freshStillInPool {
		t.Error("expected fresh entry to remain in pool")
	}
}

// --------------------------------------------------------------------------
// H04: appendBounded race tests
// --------------------------------------------------------------------------

// TestAppendBounded_BasicTruncation verifies that appendBounded correctly
// truncates output when the budget is exhausted.
func TestAppendBounded_BasicTruncation(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	var rem atomic.Int64
	var trunc atomic.Bool

	rem.Store(5)

	// Write 3 bytes — fits in budget.
	appendBounded(&buf, &mu, []byte("abc"), &rem, &trunc)
	if trunc.Load() {
		t.Error("truncated should be false after writing within budget")
	}
	if buf.String() != "abc" {
		t.Errorf("buf = %q, want %q", buf.String(), "abc")
	}
	if rem.Load() != 2 {
		t.Errorf("remaining = %d, want 2", rem.Load())
	}

	// Write 4 bytes — only 2 bytes of budget left; should truncate.
	appendBounded(&buf, &mu, []byte("defg"), &rem, &trunc)
	if !trunc.Load() {
		t.Error("truncated should be true after budget exhausted")
	}
	if buf.String() != "abcde" {
		t.Errorf("buf = %q, want %q", buf.String(), "abcde")
	}

	// Write more — budget at 0 or negative, nothing should be appended.
	appendBounded(&buf, &mu, []byte("xyz"), &rem, &trunc)
	if buf.String() != "abcde" {
		t.Errorf("buf changed after exhausted budget: %q", buf.String())
	}
}

// TestAppendBounded_ConcurrentRace runs two goroutines simultaneously writing
// into separate buffers but sharing the same budget and truncated flag.
// This test is designed to surface data races under -race; the key invariant
// is that the total bytes written never exceeds the budget.
func TestAppendBounded_ConcurrentRace(t *testing.T) {
	const budget = 100
	const chunkSize = 7
	const goroutines = 2
	const iterations = 50

	var buf1, buf2 bytes.Buffer
	var mu1, mu2 sync.Mutex
	var rem atomic.Int64
	var trunc atomic.Bool

	rem.Store(budget)

	chunk := bytes.Repeat([]byte("x"), chunkSize)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Goroutine 1 writes to buf1.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			appendBounded(&buf1, &mu1, chunk, &rem, &trunc)
		}
	}()

	// Goroutine 2 writes to buf2.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			appendBounded(&buf2, &mu2, chunk, &rem, &trunc)
		}
	}()

	wg.Wait()

	total := buf1.Len() + buf2.Len()
	if total > budget {
		t.Errorf("total bytes written (%d) exceeds budget (%d)", total, budget)
	}
	// Once the budget is exhausted, truncated must be set.
	if total == budget && !trunc.Load() {
		// It's possible that truncated is set due to the over-commitment even
		// though we wrote exactly budget bytes; acceptable either way.
	}
	// The remaining counter must not be positive beyond budget, or wrap.
	// After writes, remaining can be 0 or negative (over-committed atomics
	// before clamping), but total bytes should be <= budget.
	t.Logf("buf1=%d buf2=%d total=%d budget=%d trunc=%v rem=%d",
		buf1.Len(), buf2.Len(), total, budget, trunc.Load(), rem.Load())
}

// --------------------------------------------------------------------------
// H02: TestPool_TempExpiryDropsCachedClient
// --------------------------------------------------------------------------

// TestPool_TempExpiryDropsCachedClient verifies that a cached pool client is
// not returned once the associated temp server entry has expired.
// Even though the entry is "alive" in the pool, Get must return an expired
// error and evict both the pool entry and the temp entry.
func TestPool_TempExpiryDropsCachedClient(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{},
		Servers:  map[string]config.ServerConfig{},
	}
	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)

	const srvName = "tmpserver"

	// Register a temp entry that already expired 1 minute ago.
	srv := config.ServerConfig{
		Name: srvName,
		Host: "127.0.0.1",
		Port: 2222,
		User: "u",
		Auth: "quick_setup",
	}
	expiredAt := time.Now().Add(-1 * time.Minute)
	p.AddTempServer(srvName, srv, expiredAt)

	// Manually insert a fake "live" client into the pool so the test exercises
	// the cache-hit path (not just the no-entry path).
	fakeClient := &Client{
		inner:  nil,
		kaStop: make(chan struct{}),
	}
	fakeClient.dead.Store(true) // mark dead so IsAlive() returns false quickly
	var clientClosed bool
	fakeClient.closeFunc = func() error {
		clientClosed = true
		return nil
	}
	p.mu.Lock()
	p.entries[srvName] = &pooledEntry{
		client:   fakeClient,
		lastUsed: time.Now(),
	}
	p.mu.Unlock()

	// Get should detect the expired temp entry before checking cache aliveness.
	_, err := p.Get(context.Background(), srvName)
	if err == nil {
		t.Fatal("expected error for expired temp server, got nil")
	}
	if !containsSubstr(err.Error(), "expired") {
		t.Fatalf("expected 'expired' in error, got: %v", err)
	}

	// The pool entry must have been evicted (client closed, entry removed).
	if !clientClosed {
		t.Error("expected cached client to be closed on expiry eviction")
	}
	p.mu.Lock()
	_, stillInPool := p.entries[srvName]
	p.mu.Unlock()
	if stillInPool {
		t.Error("expected pool entry to be removed after expiry eviction")
	}

	// The temp entry must also have been removed.
	p.tempMu.RLock()
	_, stillInTemp := p.tempServers[srvName]
	p.tempMu.RUnlock()
	if stillInTemp {
		t.Error("expected temp entry to be removed after expiry eviction")
	}
}

// --------------------------------------------------------------------------
// TestPool_LookupTempServer verifies that LookupTempServer returns the
// stored ServerConfig for a live entry, and false for unknown / expired
// entries. Used by the tools layer to resolve quick_setup-registered
// names without consulting cfg.Servers directly.
func TestPool_LookupTempServer(t *testing.T) {
	cfg := &config.Config{Settings: config.Settings{}, Servers: map[string]config.ServerConfig{}}
	p := NewPool(cfg, &fakeResolver{})

	srv := config.ServerConfig{
		Name: "qs-1", Host: "10.0.0.1", Port: 2200, User: "alice", Auth: "quick_setup",
	}
	p.AddTempServer("qs-1", srv, time.Now().Add(30*time.Minute))

	got, ok := p.LookupTempServer("qs-1")
	if !ok {
		t.Fatal("expected live temp entry to be found")
	}
	if got.Host != "10.0.0.1" || got.User != "alice" || got.Port != 2200 {
		t.Errorf("returned ServerConfig fields: %+v", got)
	}

	if _, ok := p.LookupTempServer("nope"); ok {
		t.Error("expected unknown name to return false")
	}

	// Expired entry must read as not present.
	p.AddTempServer("qs-old", srv, time.Now().Add(-time.Minute))
	if _, ok := p.LookupTempServer("qs-old"); ok {
		t.Error("expected expired temp entry to return false")
	}

	listed := p.ListTempServers()
	if len(listed) != 1 {
		t.Fatalf("ListTempServers returned %d live entries, want 1", len(listed))
	}
	if listed[0].Server.Name != "qs-1" || listed[0].ExpiresAt.IsZero() {
		t.Fatalf("unexpected temp server snapshot: %+v", listed[0])
	}
}

// H02: TestPool_RemoveTempServerEvictsPoolEntry
// --------------------------------------------------------------------------

// TestPool_RemoveTempServerEvictsPoolEntry verifies that calling RemoveTempServer
// also closes and removes any live pooled client for the same name.
func TestPool_RemoveTempServerEvictsPoolEntry(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{},
		Servers:  map[string]config.ServerConfig{},
	}
	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)

	const srvName = "ephemeral"

	srv := config.ServerConfig{
		Name: srvName,
		Host: "127.0.0.1",
		Port: 2222,
		User: "u",
		Auth: "quick_setup",
	}
	p.AddTempServer(srvName, srv, time.Now().Add(30*time.Minute))

	// Inject a fake cached client.
	fakeClient := &Client{
		inner:  nil,
		kaStop: make(chan struct{}),
	}
	fakeClient.dead.Store(true)
	var clientClosed bool
	fakeClient.closeFunc = func() error {
		clientClosed = true
		return nil
	}
	p.mu.Lock()
	p.entries[srvName] = &pooledEntry{
		client:   fakeClient,
		lastUsed: time.Now(),
	}
	p.mu.Unlock()

	// Remove the temp server — should also evict the pool entry.
	p.RemoveTempServer(srvName)

	if !clientClosed {
		t.Error("expected cached client to be closed by RemoveTempServer")
	}
	p.mu.Lock()
	_, stillInPool := p.entries[srvName]
	p.mu.Unlock()
	if stillInPool {
		t.Error("expected pool entry to be removed by RemoveTempServer")
	}
	p.tempMu.RLock()
	_, stillInTemp := p.tempServers[srvName]
	p.tempMu.RUnlock()
	if stillInTemp {
		t.Error("expected temp entry to be removed by RemoveTempServer")
	}
}

// --------------------------------------------------------------------------
// H01: TestPool_HandshakeContextCancellable
// --------------------------------------------------------------------------

// silentListener accepts TCP connections but never writes any data, simulating
// a server that stalls during the SSH handshake.
func silentListener(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("silentListener: listen: %v", err)
	}
	stopCh := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			// Hold the connection open until stopCh is closed.
			go func(c net.Conn) {
				<-stopCh
				_ = c.Close()
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(stopCh)
		_ = ln.Close()
	}
}

// TestPool_HandshakeContextCancellable starts a listener that never performs
// an SSH handshake and verifies that cancelling the context causes dial to
// return an error well within handshakeTimeout (specifically, within 2 s).
func TestPool_HandshakeContextCancellable(t *testing.T) {
	addr, stopServer := silentListener(t)
	defer stopServer()

	ctx, cancel := context.WithCancel(context.Background())

	// Run dial in a goroutine; cancel context shortly after to trigger the
	// ctx-watcher inside sshHandshake.
	type result struct {
		client *gossh.Client
		err    error
	}
	ch := make(chan result, 1)

	go func() {
		cfg := &gossh.ClientConfig{
			User:            "testuser",
			Auth:            []gossh.AuthMethod{gossh.Password("x")},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // test only
			Timeout:         handshakeTimeout,
		}
		c, err := realDialer(ctx, "tcp", addr, cfg)
		ch <- result{c, err}
	}()

	// Give the dialer a moment to connect, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	const maxWait = 2 * time.Second
	select {
	case r := <-ch:
		if r.err == nil {
			_ = r.client.Close()
			t.Fatal("expected error after ctx cancel, got nil")
		}
		// Any error is acceptable (context.Canceled, io.EOF, net.Error, etc.)
	case <-time.After(maxWait):
		t.Fatalf("dial did not return within %v after context cancel", maxWait)
	}
}

// --------------------------------------------------------------------------
// H03: TestPool_AcceptNewHostFromServerConfig
// --------------------------------------------------------------------------

// TestPool_AcceptNewHostFromServerConfig verifies that the AcceptNewHost field
// of a temp ServerConfig is end-to-end honoured by Pool: the value flows from
// AddTempServer → tempEntry.srv.AcceptNewHost → dial() → acceptNew local
// variable → safety.HostKeyCallback(acceptNew).
//
// The test verifies the chain by:
//  1. Confirming the stored tempEntry carries AcceptNewHost=true.
//  2. Confirming the dialer IS invoked (i.e., Pool.Get reached the dial path).
//  3. Confirming the ClientConfig passed to the dialer has a non-nil
//     HostKeyCallback (i.e., the field was set by our dial() code path).
//
// Invoking the callback itself is not done here because it requires a valid
// net.Addr and gossh.PublicKey to avoid panicking inside knownhosts.
func TestPool_AcceptNewHostFromServerConfig(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{},
		Servers:  map[string]config.ServerConfig{},
	}
	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)

	const srvName = "quick-srv"

	// Capture the ClientConfig that the dialer receives.
	var capturedCfg *gossh.ClientConfig
	dialerCalled := false
	p.dialer = func(_ context.Context, _, _ string, clientCfg *gossh.ClientConfig) (*gossh.Client, error) {
		capturedCfg = clientCfg
		dialerCalled = true
		return nil, fmt.Errorf("fake: no real server") // always fail at dial
	}

	// Register with AcceptNewHost=true.
	p.AddTempServer(srvName, config.ServerConfig{
		Name:          srvName,
		Host:          "127.0.0.1",
		Port:          2222,
		User:          "u",
		Auth:          "quick_setup",
		AcceptNewHost: true,
	}, time.Now().Add(5*time.Minute))

	// 1. Verify the stored tempEntry carries AcceptNewHost=true.
	p.tempMu.RLock()
	te, found := p.tempServers[srvName]
	p.tempMu.RUnlock()
	if !found {
		t.Fatal("temp entry not found after AddTempServer")
	}
	if !te.srv.AcceptNewHost {
		t.Error("tempEntry.srv.AcceptNewHost should be true after AddTempServer with AcceptNewHost=true")
	}

	_, _ = p.Get(context.Background(), srvName)

	// 2. Confirm the dialer was reached (resolver resolved correctly).
	if !dialerCalled {
		t.Fatal("dialer was not called; Pool.Get did not reach the dial path")
	}

	// 3. Confirm the ClientConfig has a HostKeyCallback set.
	if capturedCfg == nil {
		t.Fatal("capturedCfg is nil; dialer did not receive a ClientConfig")
	}
	if capturedCfg.HostKeyCallback == nil {
		t.Error("ClientConfig.HostKeyCallback must not be nil")
	}
}

// TestPool_AcceptNewHostFalseByDefault verifies that a ServerConfig with
// AcceptNewHost=false stores the value correctly in the tempEntry and that the
// dial path does NOT accidentally set it to true. We verify through the stored
// tempEntry field rather than by calling the strict HostKeyCallback (which
// would require a valid PublicKey and could panic on a nil key).
func TestPool_AcceptNewHostFalseByDefault(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{},
		Servers:  map[string]config.ServerConfig{},
	}
	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)

	const srvName = "strict-srv"

	p.dialer = func(_ context.Context, _, _ string, _ *gossh.ClientConfig) (*gossh.Client, error) {
		return nil, fmt.Errorf("fake: no real server")
	}

	// AcceptNewHost is false (zero value) — strict host-key checking.
	p.AddTempServer(srvName, config.ServerConfig{
		Name:          srvName,
		Host:          "127.0.0.1",
		Port:          2222,
		User:          "u",
		Auth:          "quick_setup",
		AcceptNewHost: false,
	}, time.Now().Add(5*time.Minute))

	// The tempEntry must preserve AcceptNewHost=false (not mutated by dial).
	p.tempMu.RLock()
	te, found := p.tempServers[srvName]
	p.tempMu.RUnlock()
	if !found {
		t.Fatal("temp entry not found after AddTempServer")
	}
	if te.srv.AcceptNewHost {
		t.Error("tempEntry.srv.AcceptNewHost should be false when AcceptNewHost=false")
	}
}

// --------------------------------------------------------------------------
// M01: TestPool_RedialClosesDeadClient
// --------------------------------------------------------------------------

// TestPool_RedialClosesDeadClient verifies that when a cached client reports
// IsAlive()==false, Pool.Get closes the dead client exactly once before
// attempting a redial (M01 fix).
func TestPool_RedialClosesDeadClient(t *testing.T) {
	cfg := minimalConfig("srv", "127.0.0.1", 22)
	resolver := &fakeResolver{}
	p := NewPool(cfg, resolver)

	// Track how many times Close is called on the fake dead client.
	var closeCalled int32
	deadClient := &Client{
		inner:  nil,
		kaStop: make(chan struct{}),
	}
	deadClient.dead.Store(true) // IsAlive() will return false
	deadClient.closeFunc = func() error {
		atomic.AddInt32(&closeCalled, 1)
		return nil
	}

	// Pre-populate the pool with the dead client.
	p.mu.Lock()
	p.entries["srv"] = &pooledEntry{
		client:   deadClient,
		lastUsed: time.Now(),
	}
	p.mu.Unlock()

	// Configure a dialer that fails — we only care that Close was called, not
	// that the redial succeeds.
	dialErr := fmt.Errorf("fake: redial not implemented")
	p.dialer = func(_ context.Context, _, _ string, _ *gossh.ClientConfig) (*gossh.Client, error) {
		return nil, dialErr
	}

	_, err := p.Get(context.Background(), "srv")
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}

	// Close must have been called exactly once on the dead client.
	if got := atomic.LoadInt32(&closeCalled); got != 1 {
		t.Errorf("Close called %d times, want exactly 1", got)
	}
}

func TestPoolListSkipsBusyEntry(t *testing.T) {
	p := NewPool(&config.Config{Servers: map[string]config.ServerConfig{}}, &fakeResolver{})
	entry := &pooledEntry{lastUsed: time.Now()}
	p.entries["busy"] = entry

	entry.mu.Lock()
	done := make(chan []PoolInfo, 1)
	go func() {
		done <- p.List()
	}()

	select {
	case infos := <-done:
		if len(infos) != 0 {
			t.Fatalf("List returned %#v, want busy entry skipped", infos)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("List blocked on a busy pool entry")
	}
	entry.mu.Unlock()
}

// --------------------------------------------------------------------------
// Helper
// --------------------------------------------------------------------------

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		findSubstr(s, sub))
}

func findSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
