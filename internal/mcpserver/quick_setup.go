// Package mcpserver — quickSetupRegistry implements tools.QuickSetupRegistry
// with an in-memory map and TTL-based reaper goroutine. SDD §6.13.
package mcpserver

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/auth"
)

// --------------------------------------------------------------------------
// Registry
// --------------------------------------------------------------------------

// quickSetupEntry holds one registered temp server.
type quickSetupEntry struct {
	host      string
	port      int
	user      string
	secret    *auth.Secret
	expiresAt time.Time
}

// quickSetupRegistry is an in-memory QuickSetupRegistry implementation.
// All exported methods are safe for concurrent use.
type quickSetupRegistry struct {
	mu      sync.Mutex
	m       map[string]*quickSetupEntry
	counter map[string]int // for disambiguation: base → count

	stopReaper chan struct{}
	reaperDone chan struct{}
}

// newQuickSetupRegistry creates and starts a quickSetupRegistry.
// The caller must call Close() to stop the reaper goroutine.
func newQuickSetupRegistry() *quickSetupRegistry {
	r := &quickSetupRegistry{
		m:          make(map[string]*quickSetupEntry),
		counter:    make(map[string]int),
		stopReaper: make(chan struct{}),
		reaperDone: make(chan struct{}),
	}
	go r.reaperLoop()
	return r
}

// --------------------------------------------------------------------------
// QuickSetupRegistry interface
// --------------------------------------------------------------------------

// Register stores a new entry keyed by a sanitised/disambiguated name.
// secret must be the raw credential bytes (password or PEM key).
// Returns the canonical name and the Unix expiry timestamp.
func (r *quickSetupRegistry) Register(nameHint, host string, port int, user string, secret []byte, ttlMinutes int) (string, int64, error) {
	base := sanitiseName(nameHint, host)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Disambiguate: if name already exists, append an incrementing suffix.
	name := base
	r.counter[base]++
	if r.counter[base] > 1 {
		name = fmt.Sprintf("%s-%d", base, r.counter[base])
	}

	expiresAt := time.Now().Add(time.Duration(ttlMinutes) * time.Minute)

	r.m[name] = &quickSetupEntry{
		host:      host,
		port:      port,
		user:      user,
		secret:    auth.NewSecret(secret),
		expiresAt: expiresAt,
	}

	return name, expiresAt.Unix(), nil
}

// Lookup returns the stored entry for name if it exists and has not expired.
// The returned secret is a copy of the underlying bytes; callers should zero
// it after use.
func (r *quickSetupRegistry) Lookup(name string) (host string, port int, user string, secret []byte, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, exists := r.m[name]
	if !exists {
		return "", 0, "", nil, false
	}
	if time.Now().After(e.expiresAt) {
		// Expired — remove lazily.
		r.evict(name, e)
		return "", 0, "", nil, false
	}

	// Return a copy so that the caller's slice remains valid even if entry is
	// later evicted and the Secret is closed.
	secretBytes := e.secret.Bytes()
	cp := make([]byte, len(secretBytes))
	copy(cp, secretBytes)

	return e.host, e.port, e.user, cp, true
}

// Close stops the reaper goroutine. Idempotent.
func (r *quickSetupRegistry) Close() {
	select {
	case <-r.stopReaper:
		// already closed
	default:
		close(r.stopReaper)
	}
	<-r.reaperDone
}

// --------------------------------------------------------------------------
// Reaper
// --------------------------------------------------------------------------

// reaperLoop scans for expired entries every minute and evicts them.
func (r *quickSetupRegistry) reaperLoop() {
	defer close(r.reaperDone)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopReaper:
			r.evictAll()
			return
		case <-ticker.C:
			r.reapExpired()
		}
	}
}

// reapExpired removes all entries whose expiresAt is in the past.
func (r *quickSetupRegistry) reapExpired() {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, e := range r.m {
		if now.After(e.expiresAt) {
			r.evict(name, e)
		}
	}
}

// evictAll closes and removes all entries. Called on shutdown.
func (r *quickSetupRegistry) evictAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, e := range r.m {
		r.evict(name, e)
	}
}

// evict closes the secret and removes the entry from the map.
// Caller must hold r.mu.
func (r *quickSetupRegistry) evict(name string, e *quickSetupEntry) {
	if e.secret != nil {
		e.secret.Close()
	}
	delete(r.m, name)
}

// --------------------------------------------------------------------------
// Name sanitisation
// --------------------------------------------------------------------------

// sanitisedRe matches characters that are NOT allowed in server names.
var sanitisedRe = regexp.MustCompile(`[^a-z0-9-]`)

// sanitiseName derives a base server name from nameHint or host.
// Result matches ^[a-z0-9][a-z0-9-]*$ up to 32 chars.
func sanitiseName(hint, host string) string {
	base := hint
	if base == "" {
		base = "qs-" + host
	}
	// Lowercase first.
	base = strings.ToLower(base)
	// Replace common separators/spaces with dashes.
	base = strings.ReplaceAll(base, ".", "-")
	base = strings.ReplaceAll(base, ":", "-")
	base = strings.ReplaceAll(base, "_", "-")
	base = strings.ReplaceAll(base, " ", "-")
	// Remove any remaining disallowed characters.
	base = sanitisedRe.ReplaceAllString(base, "")
	// Trim leading dashes.
	base = strings.TrimLeft(base, "-")
	// Collapse consecutive dashes.
	for strings.Contains(base, "--") {
		base = strings.ReplaceAll(base, "--", "-")
	}
	if base == "" {
		base = "qs-temp"
	}
	if len(base) > 32 {
		base = base[:32]
	}
	return base
}
