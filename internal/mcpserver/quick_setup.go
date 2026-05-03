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
	"github.com/xjoker/mcp-ssh-bridge/internal/tools"
)

// --------------------------------------------------------------------------
// Registry
// --------------------------------------------------------------------------

// quickSetupEntry holds one registered temp server.
type quickSetupEntry struct {
	host          string
	port          int
	user          string
	authKind      string // "password" or "key"
	secret        *auth.Secret
	passphrase    *auth.Secret // nil when no passphrase
	acceptNewHost bool
	expiresAt     time.Time
}

// quickSetupRegistry is an in-memory QuickSetupRegistry implementation.
// All exported methods are safe for concurrent use.
type quickSetupRegistry struct {
	mu      sync.Mutex
	m       map[string]*quickSetupEntry
	counter map[string]int // for disambiguation: base → count

	// staticNames is the set of statically-configured server names. Quick-
	// setup names MUST NOT collide with these — otherwise a malicious
	// elicitation could "shadow" prod (Codex R2-C02).
	staticNames map[string]struct{}

	// onEvict is invoked whenever an entry is removed from the registry
	// (TTL expiry, manual reap, Close). The mcpserver wires this to
	// ssh.Pool.RemoveTempServer so expired entries do not linger and
	// continue to mask static servers.
	onEvict func(name string)

	stopReaper chan struct{}
	reaperDone chan struct{}
}

// newQuickSetupRegistry creates and starts a quickSetupRegistry.
// staticNames is the closed set of configured server names which the
// registry MUST NOT collide with. onEvict (optional) is fired on every
// eviction; pass ssh.Pool.RemoveTempServer to keep the pool in sync.
// The caller must call Close() to stop the reaper goroutine.
func newQuickSetupRegistry(staticNames map[string]struct{}, onEvict func(name string)) *quickSetupRegistry {
	if staticNames == nil {
		staticNames = map[string]struct{}{}
	}
	r := &quickSetupRegistry{
		m:           make(map[string]*quickSetupEntry),
		counter:     make(map[string]int),
		staticNames: staticNames,
		onEvict:     onEvict,
		stopReaper:  make(chan struct{}),
		reaperDone:  make(chan struct{}),
	}
	go r.reaperLoop()
	return r
}

// --------------------------------------------------------------------------
// QuickSetupRegistry interface
// --------------------------------------------------------------------------

// Register stores a new entry keyed by a sanitised/disambiguated name.
// SDD §6.13. Returns the canonical name and the Unix expiry timestamp.
func (r *quickSetupRegistry) Register(spec tools.QuickSetupSpec) (string, int64, error) {
	if spec.AuthKind != "password" && spec.AuthKind != "key" {
		return "", 0, fmt.Errorf("quickSetupRegistry: invalid auth kind %q", spec.AuthKind)
	}
	if len(spec.Secret) == 0 {
		return "", 0, fmt.Errorf("quickSetupRegistry: empty secret")
	}
	// H02: registry-level TTL guard (defence-in-depth against callers that
	// bypass the handler layer, e.g. future internal callers or direct tests).
	if spec.TTLMinutes < 1 || spec.TTLMinutes > 240 {
		return "", 0, fmt.Errorf("quickSetupRegistry: ttl_minutes %d out of allowed range 1..240", spec.TTLMinutes)
	}
	base := sanitiseName(spec.NameHint, spec.Host)

	r.mu.Lock()
	defer r.mu.Unlock()

	// R2-C02: Disambiguate against BOTH existing temp entries and the
	// static server set. Walk the suffix counter until we land on a name
	// that does not collide with either, so a quick_setup registration
	// can never shadow a configured production server.
	name := base
	for {
		r.counter[base]++
		if r.counter[base] > 1 {
			name = fmt.Sprintf("%s-%d", base, r.counter[base])
		}
		if _, taken := r.staticNames[name]; taken {
			continue
		}
		if _, taken := r.m[name]; taken {
			continue
		}
		break
	}

	expiresAt := time.Now().Add(time.Duration(spec.TTLMinutes) * time.Minute)

	entry := &quickSetupEntry{
		host:          spec.Host,
		port:          spec.Port,
		user:          spec.User,
		authKind:      spec.AuthKind,
		secret:        auth.NewSecret(spec.Secret),
		acceptNewHost: spec.AcceptNewHost,
		expiresAt:     expiresAt,
	}
	if len(spec.Passphrase) > 0 {
		entry.passphrase = auth.NewSecret(spec.Passphrase)
	}
	r.m[name] = entry

	return name, expiresAt.Unix(), nil
}

// Lookup returns the stored entry for name if it exists and has not expired.
// Secret / Passphrase in the returned view are fresh copies; callers
// SHOULD zero them after use. The registry's own copy lives until
// Close()/eviction.
func (r *quickSetupRegistry) Lookup(name string) (tools.QuickSetupView, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, exists := r.m[name]
	if !exists {
		return tools.QuickSetupView{}, false
	}
	if time.Now().After(e.expiresAt) {
		// Expired — remove lazily.
		r.evict(name, e)
		return tools.QuickSetupView{}, false
	}

	view := tools.QuickSetupView{
		Host:          e.host,
		Port:          e.port,
		User:          e.user,
		AuthKind:      e.authKind,
		AcceptNewHost: e.acceptNewHost,
	}
	if e.secret != nil {
		view.Secret = copyBytes(e.secret.Bytes())
	}
	if e.passphrase != nil {
		view.Passphrase = copyBytes(e.passphrase.Bytes())
	}
	return view, true
}

func copyBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
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

// evict closes the secret, removes the entry from the map, and notifies
// the onEvict callback (which the mcpserver wires to
// ssh.Pool.RemoveTempServer so the pool entry is dropped in lock-step).
// Caller must hold r.mu.
func (r *quickSetupRegistry) evict(name string, e *quickSetupEntry) {
	if e.secret != nil {
		e.secret.Close()
	}
	if e.passphrase != nil {
		e.passphrase.Close()
	}
	delete(r.m, name)
	if r.onEvict != nil {
		// Run outside the lock to avoid potential ordering issues with the
		// pool's own mutex. We're still inside r.mu but Pool.RemoveTempServer
		// only takes its own private mutex; releasing r.mu here would expose
		// the half-closed entry to concurrent Lookup. Net: keep it under
		// r.mu and accept the one-mutex-then-the-other ordering.
		r.onEvict(name)
	}
}

// --------------------------------------------------------------------------
// Name sanitisation
// --------------------------------------------------------------------------

// sanitisedRe matches characters that are NOT allowed in server names.
var sanitisedRe = regexp.MustCompile(`[^a-z0-9-]`)

// sanitiseName derives a base server name from nameHint or host.
// Result matches ^qs-[a-z0-9-]*$ up to 32 chars.
//
// R2-C02: every quick_setup name lives in the qs- namespace. A user-
// supplied name_hint that already starts with qs- is preserved (after
// lowercase + sanitisation); anything else gets the qs- prefix added so
// it cannot accidentally or maliciously match a static server name.
func sanitiseName(hint, host string) string {
	base := hint
	if base == "" {
		base = host
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
		base = "temp"
	}
	if !strings.HasPrefix(base, "qs-") {
		base = "qs-" + base
	}
	if len(base) > 32 {
		base = base[:32]
	}
	// Ensure the truncation didn't strip the qs- prefix.
	if !strings.HasPrefix(base, "qs-") {
		base = "qs-" + base
		if len(base) > 32 {
			base = base[:32]
		}
	}
	return base
}
