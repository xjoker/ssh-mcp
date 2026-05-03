// Package mcpserver — transport.go wires internal/ssh.Pool to the session and
// tunnel manager interfaces. SDD §4.4.
package mcpserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/mcp-ssh-bridge/internal/auth"
	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	sshpkg "github.com/xjoker/mcp-ssh-bridge/internal/ssh"
)

// --------------------------------------------------------------------------
// sshTransport — implements session.Transport
// --------------------------------------------------------------------------

// sshTransport opens interactive shell channels via the SSH pool.
type sshTransport struct {
	pool *sshpkg.Pool
}

// OpenShell opens a PTY-backed shell on the named server.
// It allocates a PTY, starts a shell, and returns the three I/O streams plus
// a close function. The caller owns all returned values.
func (t *sshTransport) OpenShell(
	ctx context.Context,
	server string,
) (stdin io.WriteCloser, stdout io.Reader, stderr io.Reader, close func() error, err error) {
	cl, err := t.pool.Get(ctx, server)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("sshTransport.OpenShell: get client for %q: %w", server, err)
	}

	sess, err := cl.Underlying().NewSession()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("sshTransport.OpenShell: new session: %w", err)
	}

	// Request a pseudo-terminal.
	modes := gossh.TerminalModes{
		gossh.ECHO:          0,
		gossh.TTY_OP_ISPEED: 38400,
		gossh.TTY_OP_OSPEED: 38400,
	}
	if ptErr := sess.RequestPty("xterm", 40, 80, modes); ptErr != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("sshTransport.OpenShell: RequestPty: %w", ptErr)
	}

	stdinPipe, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("sshTransport.OpenShell: StdinPipe: %w", err)
	}
	stdoutPipe, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("sshTransport.OpenShell: StdoutPipe: %w", err)
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("sshTransport.OpenShell: StderrPipe: %w", err)
	}

	if startErr := sess.Shell(); startErr != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("sshTransport.OpenShell: Shell: %w", startErr)
	}

	closer := func() error { return sess.Close() }
	return stdinPipe, stdoutPipe, stderrPipe, closer, nil
}

// --------------------------------------------------------------------------
// sshDialer — implements tunnel.Dialer
// --------------------------------------------------------------------------

// sshDialer dials and listens via the SSH pool.
type sshDialer struct {
	pool *sshpkg.Pool
}

// SSHDial dials network/addr through the SSH connection identified by server.
func (d *sshDialer) SSHDial(ctx context.Context, server, network, addr string) (net.Conn, error) {
	cl, err := d.pool.Get(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("sshDialer.SSHDial: get client for %q: %w", server, err)
	}
	conn, err := cl.Underlying().Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("sshDialer.SSHDial: dial %s/%s: %w", network, addr, err)
	}
	return conn, nil
}

// SSHListen opens a remote listener on bind:port via the named server.
// S-9 (defence-in-depth): if bind is empty it defaults to 127.0.0.1 so the
// remote listener is never accidentally opened on a wildcard address even if
// an upper layer forgot to apply the default.
func (d *sshDialer) SSHListen(ctx context.Context, server, bind string, port int) (net.Listener, error) {
	if bind == "" {
		bind = "127.0.0.1"
	}
	cl, err := d.pool.Get(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("sshDialer.SSHListen: get client for %q: %w", server, err)
	}
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	ln, err := cl.Underlying().Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshDialer.SSHListen: listen %s: %w", addr, err)
	}
	return ln, nil
}

// --------------------------------------------------------------------------
// credResolver — implements ssh.CredResolver
// --------------------------------------------------------------------------

// credResolver resolves per-server authentication from config using
// internal/auth helpers. quickSetup is consulted when srv.Auth ==
// "quick_setup" (servers registered via ssh_quick_setup at runtime).
type credResolver struct {
	allowPlaintext bool
	quickSetup     *quickSetupRegistry
}

// ResolveServerAuth resolves credentials for srv.
// Returns the ordered list of gossh.AuthMethod and a human-readable label.
func (r *credResolver) ResolveServerAuth(
	ctx context.Context,
	srv config.ServerConfig,
) ([]gossh.AuthMethod, string, error) {
	switch srv.Auth {
	case "agent":
		ag := auth.Agent()
		if ag == nil {
			return nil, "", fmt.Errorf("ssh-agent unavailable (SSH_AUTH_SOCK not set or socket unreachable)")
		}
		signers, err := ag.Signers()
		if err != nil {
			return nil, "", fmt.Errorf("ssh-agent: list signers: %w", err)
		}
		return []gossh.AuthMethod{gossh.PublicKeys(signers...)}, "agent", nil

	case "key":
		if srv.KeyPath == "" {
			return nil, "", fmt.Errorf("server %q: auth=key requires key_path", srv.Name)
		}
		pemBytes, err := os.ReadFile(srv.KeyPath)
		if err != nil {
			return nil, "", fmt.Errorf("server %q: read key_path: %w", srv.Name, err)
		}
		var passSecret *auth.Secret
		label := "key"
		if !srv.KeyPassphrase.IsZero() {
			passSecret, err = auth.Resolve(ctx, srv.KeyPassphrase, r.allowPlaintext)
			if err != nil {
				return nil, "", fmt.Errorf("server %q: resolve key_passphrase: %w", srv.Name, err)
			}
			defer passSecret.Close()
			label = "key+passphrase"
		}
		signer, err := auth.LoadPrivateKey(pemBytes, passSecret)
		if err != nil {
			return nil, "", fmt.Errorf("server %q: load private key: %w", srv.Name, err)
		}
		return []gossh.AuthMethod{gossh.PublicKeys(signer)}, label, nil

	case "password":
		secret, err := auth.Resolve(ctx, srv.Password, r.allowPlaintext)
		if err != nil {
			return nil, "", fmt.Errorf("server %q: resolve password: %w", srv.Name, err)
		}
		defer secret.Close()
		pw := make([]byte, len(secret.Bytes()))
		copy(pw, secret.Bytes())
		label := authLabel(srv.Password)
		return []gossh.AuthMethod{gossh.Password(string(pw))}, label, nil

	case "quick_setup":
		if r.quickSetup == nil {
			return nil, "", fmt.Errorf("server %q: quick_setup registry not wired", srv.Name)
		}
		view, ok := r.quickSetup.Lookup(srv.Name)
		if !ok {
			return nil, "", fmt.Errorf("server %q: quick_setup entry expired or not found", srv.Name)
		}
		// Defensive: zero the local copy as soon as we're done.
		defer func() {
			for i := range view.Secret {
				view.Secret[i] = 0
			}
			for i := range view.Passphrase {
				view.Passphrase[i] = 0
			}
		}()
		switch view.AuthKind {
		case "password":
			pw := make([]byte, len(view.Secret))
			copy(pw, view.Secret)
			return []gossh.AuthMethod{gossh.Password(string(pw))}, "quick_setup", nil
		case "key":
			var passSecret *auth.Secret
			if len(view.Passphrase) > 0 {
				passSecret = auth.NewSecret(view.Passphrase)
				defer passSecret.Close()
			}
			signer, err := auth.LoadPrivateKey(view.Secret, passSecret)
			if err != nil {
				return nil, "", fmt.Errorf("server %q: load quick_setup key: %w", srv.Name, err)
			}
			return []gossh.AuthMethod{gossh.PublicKeys(signer)}, "quick_setup", nil
		default:
			return nil, "", fmt.Errorf("server %q: quick_setup view has unknown auth kind %q", srv.Name, view.AuthKind)
		}

	default:
		return nil, "", fmt.Errorf("server %q: unsupported auth method %q", srv.Name, srv.Auth)
	}
}

// authLabel returns the audit label for a password CredRef based on its kind.
func authLabel(ref config.CredRef) string {
	switch ref.Kind {
	case config.CredRefKeychain:
		return "password_keychain"
	case config.CredRefEnv:
		return "password_env"
	case config.CredRefPlaintext:
		return "plaintext_config"
	default:
		return "password"
	}
}
