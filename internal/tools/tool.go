// Package tools defines the tool layer contract used by every MCP tool
// in this project. Each tool is a function that consumes raw JSON args
// and returns a unified envelope.Response.
//
// The mcpserver package wires concrete dependencies (Deps) and registers
// tools via Registry.
package tools

import (
	"context"
	"encoding/json"

	"github.com/xjoker/mcp-ssh-bridge/internal/audit"
	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	"github.com/xjoker/mcp-ssh-bridge/internal/session"
	"github.com/xjoker/mcp-ssh-bridge/internal/ssh"
	"github.com/xjoker/mcp-ssh-bridge/internal/tunnel"
)

// HandlerFunc is the signature implemented by every tool.
//
// args carries the raw JSON of the tool input. The handler MUST return a
// fully-formed envelope.Response; framework-level concerns (panic recovery,
// audit logging) are handled by middleware in the mcpserver package.
type HandlerFunc func(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response

// Tool is the descriptor registered with the MCP layer.
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	Handle      HandlerFunc
}

// Registry collects tools produced by individual files in this package.
type Registry struct {
	tools []Tool
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(t Tool) { r.tools = append(r.tools, t) }

func (r *Registry) All() []Tool { return r.tools }

// Deps is the bundle of long-lived dependencies injected into every tool.
// Concrete instances are constructed in the mcpserver bootstrap.
type Deps struct {
	Cfg          *config.Config
	Pool         *ssh.Pool
	SessionMgr   *session.Manager
	TunnelMgr    *tunnel.Manager
	Audit        *audit.Logger
	QuickSetup   QuickSetupRegistry

	// AllowPlaintext mirrors Cfg.Settings.AllowConfigPlaintextPassword,
	// passed to auth.Resolve when handling CredRefPlaintext.
	AllowPlaintext bool

	// Elicit issues an MCP elicitation/create request. Returns the user's
	// response or an error. Used by ssh_quick_setup.
	Elicit ElicitFunc

	// Progress emits an MCP progress notification with the given message
	// payload. Returns nil if no progress token is associated with the
	// current request (i.e., client did not request streaming).
	Progress ProgressFunc

	// SessionID is the MCP session identifier injected by the server.
	SessionID string
}

// QuickSetupSpec describes a temporary server registration request.
// SDD §6.13: quick_setup persists credentials only in memory for the
// declared TTL, then zeroes them.
type QuickSetupSpec struct {
	NameHint      string
	Host          string
	Port          int
	User          string
	AuthKind      string // "password" or "key"
	Secret        []byte // password bytes or PEM key bytes (caller may zero after Register)
	Passphrase    []byte // optional, for encrypted PEM keys
	AcceptNewHost bool
	TTLMinutes    int
}

// QuickSetupView is the read-side projection returned by Lookup. Secret /
// Passphrase fields are fresh copies; the registry retains its own
// scrubbing-on-evict copy.
type QuickSetupView struct {
	Host          string
	Port          int
	User          string
	AuthKind      string
	Secret        []byte
	Passphrase    []byte
	AcceptNewHost bool
}

// QuickSetupRegistry is the interface for ad-hoc server registry used by
// ssh_quick_setup. Implementation lives in mcpserver.
type QuickSetupRegistry interface {
	Register(spec QuickSetupSpec) (registeredName string, expiresAt int64, err error)
	Lookup(name string) (view QuickSetupView, ok bool)
	// Remove deletes a previously-registered entry, scrubs its secret, and
	// fires the registry's onEvict callback (which keeps the SSH pool in
	// sync). It is idempotent — calling Remove on an unknown name is a
	// no-op. Used by the inline session_start path so credentials live
	// only for the lifetime of the session, not the registry's TTL.
	Remove(name string)
}

// ElicitFunc requests user confirmation via MCP elicitation/create.
type ElicitFunc func(ctx context.Context, schema json.RawMessage, message string) (json.RawMessage, error)

// ProgressFunc sends a progress notification. value is an arbitrary
// JSON-encodable payload (e.g., {bytes_read, total} or stdout chunk).
type ProgressFunc func(value any)
