package ssh

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/config"
)

// TestCloseIdle_DoesNotStallOtherServersDuringDial reproduces the pool-wide
// stall: server A is mid-dial (entry.mu held); CloseIdle must not block on it
// while holding p.mu, and Get("b") must complete promptly.
func TestCloseIdle_DoesNotStallOtherServersDuringDial(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{},
		Servers: map[string]config.ServerConfig{
			"a": {Name: "a", Host: "1.1.1.1", Port: 22, User: "u", Auth: "password"},
			"b": {Name: "b", Host: "2.2.2.2", Port: 22, User: "u", Auth: "password"},
		},
	}
	p := NewPool(cfg, &fakeResolver{})

	dialABlocked := make(chan struct{})
	releaseDialA := make(chan struct{})
	p.dialer = func(_ context.Context, _, addr string, _ *gossh.ClientConfig) (*gossh.Client, error) {
		if addr == "1.1.1.1:22" {
			close(dialABlocked)
			<-releaseDialA // simulate a slow dial holding entry.mu
		}
		return nil, fmt.Errorf("fake dial failure")
	}
	defer close(releaseDialA)

	go func() { _, _ = p.Get(context.Background(), "a") }()
	<-dialABlocked // A is now mid-dial, holding its entry.mu

	done := make(chan struct{})
	go func() {
		p.CloseIdle(time.Hour) // must skip the busy entry, not block on it
		_, _ = p.Get(context.Background(), "b")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CloseIdle/Get(b) stalled behind server a's in-flight dial")
	}
}

// TestCloseIdle_DoesNotEvictFreshlyCreatedEntry covers the lost-connection
// race: a brand-new entry (previously lastUsed == zero time) must not look
// idle to a concurrent CloseIdle, otherwise the connection dialled into it
// leaks outside the pool.
func TestCloseIdle_DoesNotEvictFreshlyCreatedEntry(t *testing.T) {
	p := NewPool(&config.Config{
		Settings: config.Settings{},
		Servers:  map[string]config.ServerConfig{},
	}, &fakeResolver{})

	// Simulate the window in getInternal between entry creation (under p.mu)
	// and the dial: the entry exists in the map with no client yet.
	entry := p.lockLiveEntry("fresh")
	entry.mu.Unlock()

	p.CloseIdle(30 * time.Minute)

	p.mu.Lock()
	_, still := p.entries["fresh"]
	p.mu.Unlock()
	if !still {
		t.Fatal("freshly created entry was evicted by CloseIdle; the dialled connection would leak")
	}
}

// TestGet_RetriesWhenEntryEvictedWhileWaiting covers the orphaned-entry race:
// a Get that was queued behind an eviction must not store its new client in
// the removed entry — the client must land in an entry reachable from the map.
func TestGet_RetriesWhenEntryEvictedWhileWaiting(t *testing.T) {
	p := NewPool(&config.Config{
		Settings: config.Settings{},
		Servers: map[string]config.ServerConfig{
			"srv": {Name: "srv", Host: "1.1.1.1", Port: 22, User: "u", Auth: "password"},
		},
	}, &fakeResolver{})
	p.dialer = func(_ context.Context, _, _ string, _ *gossh.ClientConfig) (*gossh.Client, error) {
		return nil, fmt.Errorf("fake dial failure")
	}

	// Stale idle entry with a closable client.
	closed := false
	stale := &Client{kaStop: make(chan struct{})}
	stale.dead.Store(true)
	stale.closeFunc = func() error { closed = true; return nil }
	p.mu.Lock()
	p.entries["srv"] = &pooledEntry{client: stale, lastUsed: time.Now().Add(-time.Hour)}
	p.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.CloseIdle(30 * time.Minute) }()
	go func() { defer wg.Done(); _, _ = p.Get(context.Background(), "srv") }()
	wg.Wait()

	if !closed {
		t.Error("stale client was not closed by CloseIdle")
	}
	// Whatever entry is in the map now must not be the evicted one.
	p.mu.Lock()
	entry, ok := p.entries["srv"]
	p.mu.Unlock()
	if ok {
		entry.mu.Lock()
		if entry.evicted {
			t.Error("map still holds an evicted entry")
		}
		entry.mu.Unlock()
	}
}
