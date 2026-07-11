// Package tools — shared helpers for resolving server/inline SSH connections.
// Used internally by sftp_* and tunnel tool handlers.
//
// NOTE: exec.go (W4-D0) already defines buildAdHocAuth / mapConnError with
// *execInline and Deps signatures. This file provides sftp-specific helpers
// that accept json.RawMessage directly so sftp/tunnel handlers need not
// duplicate the full inline-resolution logic.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/auth"
	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/safety"
	"github.com/xjoker/ssh-mcp/internal/ssh"
)

// clampPTYDim normalises a user-supplied PTY dimension (cols / rows) to the
// uint32 type the ssh library expects, defending against the gosec G115
// integer-overflow class: a negative or oversized int from a non-conforming
// MCP client (one that bypasses the JSON schema's minimum/maximum) would
// otherwise wrap into a huge uint32 (e.g. -1 → 4294967295) and travel into
// gossh.RequestPty as a nonsensical terminal size. The defaults match the
// schema (cols 10..500 default 220, rows 5..200 default 50).
func clampPTYDim(v int, defaultV, minV, maxV uint32) uint32 {
	if v <= 0 {
		return defaultV
	}
	if v < int(minV) {
		return minV
	}
	if v > int(maxV) {
		return maxV
	}
	return uint32(v) // #nosec G115 -- v is bounded to [minV, maxV] above, both uint32
}

// sftpInline mirrors the inline JSON object reused across sftp_* tools.
// It is intentionally separate from execInline to avoid coupling.
//
// accept_new_host is intentionally NOT a field: AI-initiated first-contact
// trust is forbidden; use `ssh-mcp trust ...` to pin host keys instead.
type sftpInline struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	Password      string `json:"password,omitempty"`
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	Passphrase    string `json:"passphrase,omitempty"`
}

// sftpConnArgs holds only the server/inline fields (common to all sftp/tunnel tools).
type sftpConnArgs struct {
	Server *string     `json:"server,omitempty"`
	Inline *sftpInline `json:"inline,omitempty"`
}

// allowedPathsForServer returns the allowed_prefixes list for a server,
// consulting (in order):
//  1. cfg.Servers — the static config snapshot loaded at MCP startup.
//  2. The SSH pool's temp-server map — entries injected by
//     `list_servers refresh` (zero-expiry shadows for hand-edited
//     config entries) and `ssh_persistent_setup` (newly registered
//     servers). These carry the AllowedPaths field copied from the
//     freshly loaded TOML, so paths added/edited on disk after process
//     start are still policy-enforced.
//
// Returns nil for genuine inline / quick_setup entries (no AllowedPaths
// to enforce). An empty slice means "all paths allowed".
func allowedPathsForServer(deps *Deps, name string) []string {
	if name == "" {
		return nil
	}
	if deps != nil && deps.Cfg != nil {
		if srv, ok := deps.Cfg.Servers[name]; ok {
			return srv.AllowedPaths
		}
	}
	// Pool fallback: zero-expiry refresh shadows + persistent_setup writes.
	if deps != nil && deps.Pool != nil {
		if srv, ok := deps.Pool.LookupTempServer(name); ok {
			return srv.AllowedPaths
		}
	}
	return nil
}

// enforceAllowedPath validates rp against the server's allowed_paths list.
// Returns (zeroResponse, true) when allowed (or when server is inline/temp
// with no policy). Returns (PERMISSION_DENIED response, false) when the
// path is outside the configured prefixes.
//
// serverName == "" is treated as "inline / no restriction" and always
// returns (zeroResponse, true).
//
// NOTE: this is the syntactic check. To prevent symlink-based TOCTOU
// bypass (Codex R2-C01) callers handling SFTP/exec operations against
// configured servers MUST call resolveAndCheckRemotePath after the
// connection is established, which canonicalises through the remote OS
// before applying the prefix policy.
func enforceAllowedPath(deps *Deps, serverName string, rp safety.RemotePath) (envelope.Response, bool) {
	prefixes := allowedPathsForServer(deps, serverName)
	if err := safety.CheckAllowed(rp, prefixes); err != nil {
		msg := fmt.Sprintf("path %q not in allowed_prefixes for server %q", rp.String(), serverName)
		return envelope.Err(envelope.CodePermissionDenied, msg, false), false
	}
	return envelope.Response{}, true
}

// resolveAndCheckRemotePath canonicalises rawPath through the remote
// SFTP server's Realpath (which follows symlinks) and then enforces the
// server's allowed_paths policy on the resolved form. Returns the
// canonical RemotePath that the caller SHOULD use for the actual SFTP
// or exec operation — using anything other than the canonical path
// reopens the TOCTOU window.
//
// For write/create operations whose target may not exist yet, pass
// allowMissing=true: the helper falls back to resolving the parent
// directory and joins the original basename, then checks both the
// resolved parent and the synthetic full path.
//
// inline / temp servers (allowed_paths empty) bypass the policy check
// but still receive the canonicalised path so handlers can use it
// uniformly.
func resolveAndCheckRemotePath(
	deps *Deps,
	serverName string,
	sftpc remoteRealpather,
	rawPath string,
	allowMissing bool,
) (safety.RemotePath, envelope.Response, bool) {
	resolved, err := sftpc.Realpath(rawPath)
	if err != nil {
		if !allowMissing {
			return safety.RemotePath{},
				envelope.Err(envelope.CodeNotFound,
					fmt.Sprintf("realpath %q: %v", rawPath, err), false),
				false
		}
		// Fallback: realpath the parent, append basename, validate.
		parent, base := splitPath(rawPath)
		if parent == "" {
			return safety.RemotePath{},
				envelope.Err(envelope.CodeInvalidArgument,
					fmt.Sprintf("realpath %q: %v (no parent to fall back on)", rawPath, err), false),
				false
		}
		parentRP, perr := sftpc.Realpath(parent)
		if perr != nil {
			return safety.RemotePath{},
				envelope.Err(envelope.CodeNotFound,
					fmt.Sprintf("realpath parent of %q: %v", rawPath, perr), false),
				false
		}
		// Validate the parent is under allowed_paths.
		if errResp, allowed := enforceAllowedPath(deps, serverName, parentRP); !allowed {
			return safety.RemotePath{}, errResp, false
		}
		joined := joinPath(parentRP.String(), base)
		joinedRP, vErr := safety.ValidateRemotePath(joined)
		if vErr != nil {
			return safety.RemotePath{},
				envelope.Err(envelope.CodeInvalidArgument,
					fmt.Sprintf("invalid resolved path %q: %v", joined, vErr), false),
				false
		}
		// Re-check the full synthetic path (typically same prefix as parent).
		if errResp, allowed := enforceAllowedPath(deps, serverName, joinedRP); !allowed {
			return safety.RemotePath{}, errResp, false
		}
		return joinedRP, envelope.Response{}, true
	}
	if errResp, allowed := enforceAllowedPath(deps, serverName, resolved); !allowed {
		return safety.RemotePath{}, errResp, false
	}
	return resolved, envelope.Response{}, true
}

// remoteRealpather is the subset of internal/sftp.Client used by
// resolveAndCheckRemotePath; declared as an interface so handlers can
// inject a fake in tests without spinning up a real SFTP backend.
type remoteRealpather interface {
	Realpath(p string) (safety.RemotePath, error)
}

// splitPath returns (parent, basename). Both empty when path is "" or "/".
func splitPath(p string) (string, string) {
	if p == "" || p == "/" {
		return "", ""
	}
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			parent := p[:i]
			if parent == "" {
				parent = "/"
			}
			return parent, p[i+1:]
		}
	}
	// No slash — relative path with no parent.
	return "", p
}

// joinPath joins parent + base with a single slash, idempotent on a
// trailing slash in parent.
func joinPath(parent, base string) string {
	if parent == "" {
		return base
	}
	if parent[len(parent)-1] == '/' {
		return parent + base
	}
	return parent + "/" + base
}

// resolveClient obtains a *ssh.Client from either a named server or inline
// credentials.
//
// For pool-backed clients, closeFn is a no-op (caller must NOT close them).
// For ad-hoc inline clients, closeFn must be deferred.
//
// Returns (client, closeFn, errResponse, ok). When ok==false the caller
// should return errResponse immediately.
func resolveClient(
	ctx context.Context,
	deps *Deps,
	rawArgs json.RawMessage,
) (client *ssh.Client, closeFn func(), resp envelope.Response, ok bool) {

	var ca sftpConnArgs
	if err := json.Unmarshal(rawArgs, &ca); err != nil {
		resp = envelope.Err(envelope.CodeInvalidArgument, "cannot parse args: "+err.Error(), false)
		return
	}

	hasServer := ca.Server != nil && *ca.Server != ""
	hasInline := ca.Inline != nil

	if !hasServer && !hasInline {
		resp = envelope.Err(envelope.CodeInvalidArgument,
			"either server or inline must be provided", false)
		return
	}
	if hasServer && hasInline {
		resp = envelope.Err(envelope.CodeInvalidArgument,
			"server and inline are mutually exclusive", false)
		return
	}

	if hasInline {
		in := ca.Inline
		if !deps.Cfg.Settings.AllowInlineCredentials {
			resp = envelope.Err(envelope.CodeInlineCredsDisabled,
				"inline credentials are disabled by configuration", false)
			return
		}
		if in.Host == "" || in.User == "" {
			resp = envelope.Err(envelope.CodeInvalidArgument,
				"inline: host and user are required", false)
			return
		}

		am, cleanup, buildErr := buildSFTPAdHocAuth(in)
		if buildErr != nil {
			resp = envelope.Err(envelope.CodeInvalidArgument,
				"inline auth: "+buildErr.Error(), false)
			return
		}

		port := in.Port
		if port == 0 {
			port = 22
		}

		// AcceptNewHost is hard-coded to false — see sftpInline doc.
		c, err := deps.Pool.GetAdHoc(ctx, ssh.AdHocParams{
			Host:          in.Host,
			Port:          port,
			User:          in.User,
			Auth:          am,
			AcceptNewHost: false,
		})
		cleanup() // zero the secret immediately after the dial attempt
		if err != nil {
			resp = mapSSHConnErr(err)
			return
		}
		client = c
		closeFn = func() { _ = c.Close() }
		ok = true
		return
	}

	// Named server path.
	name := strings.TrimSpace(*ca.Server)
	if name == "" {
		resp = envelope.Err(envelope.CodeInvalidArgument, "server name is empty", false)
		return
	}
	c, err := deps.Pool.Get(ctx, name)
	if err != nil {
		resp = mapSSHConnErr(err)
		return
	}
	client = c
	closeFn = func() {} // pool-owned; do not close
	ok = true
	return
}

// buildSFTPAdHocAuth converts sftpInline into an ssh.AuthMethod plus a cleanup
// function that zeros any secret material held by the returned method.
// Callers MUST invoke cleanup() after the connection attempt completes.
//
// H05 fix: inline passwords are wrapped in *auth.Secret and exposed via
// ssh.AuthMethod.PasswordCallback so that the ssh pool uses PasswordCallback
// (which calls Secret.Bytes() at dial time) rather than a plain []byte /
// string copy. cleanup() calls Secret.Close() to zero the buffer.
//
// Name differs from exec.go's buildAdHocAuth to avoid redeclaration.
func buildSFTPAdHocAuth(p *sftpInline) (ssh.AuthMethod, func(), error) {
	noop := func() {}

	if p.PrivateKeyPEM != "" {
		var passSecret *auth.Secret
		if p.Passphrase != "" {
			passSecret = auth.NewSecret([]byte(p.Passphrase))
		}
		signer, err := auth.LoadPrivateKey([]byte(p.PrivateKeyPEM), passSecret)
		if passSecret != nil {
			passSecret.Close()
		}
		if err != nil {
			return ssh.AuthMethod{}, noop, err
		}
		return ssh.AuthMethod{PrivateKey: signer}, noop, nil
	}
	if p.Password != "" {
		secret := auth.NewSecret([]byte(p.Password))
		cleanup := func() { secret.Close() }
		am := ssh.AuthMethod{
			PasswordCallback: func() string {
				b := secret.Bytes()
				if len(b) == 0 {
					return ""
				}
				return string(b)
			},
		}
		return am, cleanup, nil
	}
	return ssh.AuthMethod{Agent: true}, noop, nil
}

// resolveAndCheckRemotePathWalkUp resolves rawPath by walking up its
// ancestors until it finds one that the remote SFTP server can canonicalise.
// It then re-applies the allowed_paths policy against the resolved
// ancestor + the remaining (synthetic) tail.
//
// Used for recursive mkdir where multiple levels of intermediate
// directories may not exist yet.
func resolveAndCheckRemotePathWalkUp(
	deps *Deps,
	serverName string,
	sftpc remoteRealpather,
	rawPath string,
) (safety.RemotePath, envelope.Response, bool) {
	// Try the full path first; if it succeeds (target already exists),
	// canonical form decides everything.
	if rp, err := sftpc.Realpath(rawPath); err == nil {
		if errResp, allowed := enforceAllowedPath(deps, serverName, rp); !allowed {
			return safety.RemotePath{}, errResp, false
		}
		return rp, envelope.Response{}, true
	}

	// Walk up from the closest existing ancestor.
	parts := []string{}
	cur := rawPath
	for cur != "/" && cur != "" {
		parent, base := splitPath(cur)
		if base != "" {
			parts = append([]string{base}, parts...)
		}
		if parent == "" || parent == "/" {
			cur = "/"
			break
		}
		// Try parent — if it resolves, we found the existing ancestor.
		if rp, err := sftpc.Realpath(parent); err == nil {
			// Validate ancestor inside policy.
			if errResp, allowed := enforceAllowedPath(deps, serverName, rp); !allowed {
				return safety.RemotePath{}, errResp, false
			}
			// Re-attach unresolved tail; check each cumulative path.
			joined := rp.String()
			for _, p := range parts {
				joined = joinPath(joined, p)
				jrp, vErr := safety.ValidateRemotePath(joined)
				if vErr != nil {
					return safety.RemotePath{}, envelope.Err(envelope.CodeInvalidArgument,
						fmt.Sprintf("invalid resolved path %q: %v", joined, vErr), false), false
				}
				if errResp, allowed := enforceAllowedPath(deps, serverName, jrp); !allowed {
					return safety.RemotePath{}, errResp, false
				}
			}
			// Final synthetic full path.
			full, _ := safety.ValidateRemotePath(joined)
			return full, envelope.Response{}, true
		}
		cur = parent
	}
	return safety.RemotePath{}, envelope.Err(envelope.CodeNotFound,
		fmt.Sprintf("realpath %q: no existing ancestor", rawPath), false), false
}

// mapSSHConnErr converts an SSH dial/pool error into an envelope.Response.
// Name differs from exec.go's mapConnError to avoid redeclaration.
func mapSSHConnErr(err error) envelope.Response {
	if err == nil {
		return envelope.OK(nil)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "HOST_KEY_MISMATCH"):
		return envelope.Err(envelope.CodeHostKeyMismatch, msg, false)
	case strings.Contains(msg, "HOST_KEY_UNKNOWN"):
		// First contact with a new host always lands here (there is no TOFU
		// flag on the MCP tool path by design — v0.0.5 removed it). Give the
		// operator the exact next step instead of a bare error.
		return envelope.ErrWithHint(envelope.CodeHostKeyUnknown, msg,
			"First connection to an unknown host. Ask the user to run `ssh-mcp trust <host>[:port]` on this machine to inspect and pin the host key fingerprint, then retry.",
			false)
	case strings.Contains(msg, "unable to authenticate"),
		strings.Contains(msg, "Authentication failed"),
		strings.Contains(msg, "auth failed"),
		strings.Contains(msg, "permission denied"):
		return envelope.Err(envelope.CodeAuthFailed, msg, true)
	default:
		return envelope.Err(envelope.CodeConnFailed, msg, true)
	}
}

// mapSFTPErr converts an error from internal/sftp into an envelope.Response.
func mapSFTPErr(err error) envelope.Response {
	if err == nil {
		return envelope.OK(nil)
	}
	msg := err.Error()
	switch {
	case isSFTPTimeout(msg):
		return envelope.Err(envelope.CodeTimeout, msg, true)
	case strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "not found"):
		return envelope.Err(envelope.CodeNotFound, msg, false)
	case strings.Contains(msg, "permission denied"):
		return envelope.Err(envelope.CodePermissionDenied, msg, false)
	default:
		return envelope.Err(envelope.CodeSftpError, msg, false)
	}
}

func isSFTPTimeout(msg string) bool {
	return strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "context canceled")
}
