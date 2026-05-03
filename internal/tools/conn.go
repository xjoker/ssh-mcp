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
	"strings"

	"github.com/xjoker/mcp-ssh-bridge/internal/auth"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
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

		am, buildErr := buildSFTPAdHocAuth(in)
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

// buildSFTPAdHocAuth converts sftpInline into an ssh.AuthMethod.
// Name differs from exec.go's buildAdHocAuth to avoid redeclaration.
func buildSFTPAdHocAuth(p *sftpInline) (ssh.AuthMethod, error) {
	if p.PrivateKeyPEM != "" {
		var passSecret *auth.Secret
		if p.Passphrase != "" {
			passSecret = auth.NewSecret([]byte(p.Passphrase))
			defer passSecret.Close()
		}
		signer, err := auth.LoadPrivateKey([]byte(p.PrivateKeyPEM), passSecret)
		if err != nil {
			return ssh.AuthMethod{}, err
		}
		return ssh.AuthMethod{PrivateKey: signer}, nil
	}
	if p.Password != "" {
		return ssh.AuthMethod{Password: []byte(p.Password)}, nil
	}
	return ssh.AuthMethod{Agent: true}, nil
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
