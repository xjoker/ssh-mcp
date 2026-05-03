// Package ssh manages SSH connection pooling, command execution, and streaming.
// SDD §5.5, §12.1, §12.4, §4.4.
//
// Module boundary: only imports internal/safety and internal/config (types).
package ssh

import (
	"context"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
)

// CredResolver is an abstraction injected into Pool so that internal/ssh
// does NOT depend on internal/auth (which would violate module-boundary rules).
//
// internal/auth provides a concrete implementation that callers wire in.
type CredResolver interface {
	// ResolveServerAuth resolves credentials for a given server config.
	// Returns the ordered list of ssh.AuthMethod to try, plus a human-readable
	// label describing the auth mode (for logging). The order defines the
	// attempt sequence: agent first, key second, password last.
	ResolveServerAuth(ctx context.Context, srv config.ServerConfig) ([]gossh.AuthMethod, string, error)
}

// AuthMethod specifies credentials for ad-hoc connections.
// Exactly one field should be set.
type AuthMethod struct {
	// Agent=true means use the SSH agent available in the environment.
	Agent bool

	// PrivateKey holds a pre-loaded signer (key-based auth).
	PrivateKey gossh.Signer

	// Password is a cleartext password. Callers should zero it after use.
	// Deprecated: prefer PasswordCallback which avoids a permanent string copy.
	Password []byte

	// PasswordCallback, when non-nil, is called at dial time to obtain the
	// password string. This avoids retaining a permanent string copy in memory
	// (SDD §8.5 / S-7). If both Password and PasswordCallback are set,
	// PasswordCallback takes precedence.
	PasswordCallback func() string
}

// AdHocParams specifies parameters for an ad-hoc (not configured) SSH connection.
type AdHocParams struct {
	Host          string
	Port          int
	User          string
	Auth          AuthMethod
	AcceptNewHost bool
}

// ExecOpts controls buffered command execution.
type ExecOpts struct {
	// OutputMaxBytes limits the combined stdout+stderr buffer.
	// Zero means use a built-in default (64 KiB).
	OutputMaxBytes int

	// Timeout for the command. Zero means no timeout (context deadline applies).
	Timeout time.Duration
}

// StreamOpts controls streaming command execution.
type StreamOpts struct {
	// ChunkBytes controls the approximate chunk size for streaming.
	// Zero defaults to 4 KiB.
	ChunkBytes int

	// Timeout for the command. Zero means no timeout.
	Timeout time.Duration

	// OnStdout is called each time a chunk of stdout is ready.
	// eof=true on the final call.
	OnStdout func(chunk []byte, eof bool)

	// OnStderr is called each time a chunk of stderr is ready.
	// eof=true on the final call.
	OnStderr func(chunk []byte, eof bool)
}

// ExecResult holds the result of a buffered command execution.
type ExecResult struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Signal    string
	Truncated bool
	Duration  time.Duration
}

// defaultOutputMaxBytes is the fallback when ExecOpts.OutputMaxBytes == 0.
const defaultOutputMaxBytes = 64 * 1024

// defaultChunkBytes is the fallback when StreamOpts.ChunkBytes == 0.
const defaultChunkBytes = 4 * 1024

// keepaliveInterval is how often to probe the connection.
const keepaliveInterval = 30 * time.Second

// keepaliveMaxFails is how many consecutive failures before marking the
// connection dead.
const keepaliveMaxFails = 3

// Ensure safety import is used (RemoteCommand).
var _ safety.RemoteCommand
