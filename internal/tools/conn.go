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

	"github.com/xjoker/mcp-ssh-bridge/internal/auth"
	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
	"github.com/xjoker/mcp-ssh-bridge/internal/ssh"
)

// sftpInline mirrors the inline JSON object reused across sftp_* tools.
// It is intentionally separate from execInline to avoid coupling.
type sftpInline struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	Password      string `json:"password,omitempty"`
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	Passphrase    string `json:"passphrase,omitempty"`
	AcceptNewHost bool   `json:"accept_new_host"`
}

// sftpConnArgs holds only the server/inline fields (common to all sftp/tunnel tools).
type sftpConnArgs struct {
	Server *string     `json:"server,omitempty"`
	Inline *sftpInline `json:"inline,omitempty"`
}

// allowedPathsForServer returns the allowed_prefixes list for a configured
// server name, or nil for inline / quick_setup / temp servers (those entries
// are not in cfg.Servers so we cannot retrieve their AllowedPaths).
// An empty slice means "all paths allowed" (no restriction).
func allowedPathsForServer(cfg *config.Config, name string) []string {
	if cfg == nil || name == "" {
		return nil
	}
	srv, ok := cfg.Servers[name]
	if !ok {
		// Inline or temp server — no allowed_paths to enforce.
		return nil
	}
	return srv.AllowedPaths
}

// enforceAllowedPath validates rp against the server's allowed_paths list.
// Returns (zeroResponse, true) when allowed (or when server is inline/temp).
// Returns (PERMISSION_DENIED response, false) when the path is outside the
// configured prefixes.
//
// serverName == "" is treated as "inline / no restriction" and always
// returns (zeroResponse, true).
func enforceAllowedPath(cfg *config.Config, serverName string, rp safety.RemotePath) (envelope.Response, bool) {
	prefixes := allowedPathsForServer(cfg, serverName)
	if err := safety.CheckAllowed(rp, prefixes); err != nil {
		msg := fmt.Sprintf("path %q not in allowed_prefixes for server %q", rp.String(), serverName)
		return envelope.Err(envelope.CodePermissionDenied, msg, false), false
	}
	return envelope.Response{}, true
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

		c, err := deps.Pool.GetAdHoc(ctx, ssh.AdHocParams{
			Host:          in.Host,
			Port:          port,
			User:          in.User,
			Auth:          am,
			AcceptNewHost: in.AcceptNewHost,
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
		return envelope.Err(envelope.CodeHostKeyUnknown, msg, false)
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
