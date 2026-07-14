package tui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/xjoker/ssh-mcp/internal/auth"
	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/knownhosts"
	"github.com/xjoker/ssh-mcp/internal/safety"
	sshpkg "github.com/xjoker/ssh-mcp/internal/ssh"
)

const connectionTestTimeout = 30 * time.Second
const terminalResizeInterval = 250 * time.Millisecond

var errHostKeyUnknown = errors.New("host key is not trusted")

type terminalSizeFunc func() (width, height int, err error)

type windowChanger interface {
	WindowChange(height, width int) error
}

type connectionResultMsg struct {
	name       string
	generation uint64
	err        error
}

type hostKeyResultMsg struct {
	name       string
	addr       string
	key        gossh.PublicKey
	generation uint64
	err        error
}

type tuiCredResolver struct {
	cfg *config.Config
}

func (resolver *tuiCredResolver) ResolveServerAuth(ctx context.Context, server config.ServerConfig) ([]gossh.AuthMethod, string, func(), error) {
	noop := func() {}
	switch server.Auth {
	case "agent":
		agentClient, closer := auth.Agent()
		if agentClient == nil {
			return nil, "agent", noop, errors.New("SSH agent is unavailable")
		}
		return []gossh.AuthMethod{gossh.PublicKeysCallback(agentClient.Signers)}, "agent", func() { _ = closer.Close() }, nil
	case "key":
		keyBytes, err := os.ReadFile(server.KeyPath)
		if err != nil {
			return nil, "key", noop, fmt.Errorf("read key file: %w", err)
		}
		var passphrase *auth.Secret
		if !server.KeyPassphrase.IsZero() {
			passphrase, err = auth.Resolve(ctx, server.KeyPassphrase, resolver.cfg.Settings.AllowConfigPlaintextPassword)
			if err != nil {
				return nil, "key", noop, fmt.Errorf("resolve key passphrase: %w", err)
			}
		}
		signer, err := auth.LoadPrivateKey(keyBytes, passphrase)
		if passphrase != nil {
			passphrase.Close()
		}
		for index := range keyBytes {
			keyBytes[index] = 0
		}
		if err != nil {
			return nil, "key", noop, fmt.Errorf("load private key: %w", err)
		}
		return []gossh.AuthMethod{gossh.PublicKeys(signer)}, "key", noop, nil
	case "password":
		secret, err := auth.Resolve(ctx, server.Password, resolver.cfg.Settings.AllowConfigPlaintextPassword)
		if err != nil {
			return nil, "password", noop, fmt.Errorf("resolve password: %w", err)
		}
		return []gossh.AuthMethod{gossh.PasswordCallback(func() (string, error) {
			return string(secret.Bytes()), nil
		})}, "password", secret.Close, nil
	default:
		return nil, server.Auth, noop, fmt.Errorf("unsupported authentication method %q", server.Auth)
	}
}

func defaultConnectionTest(ctx context.Context, name string, cfg *config.Config) error {
	pool := sshpkg.NewPool(cfg, &tuiCredResolver{cfg: cfg})
	defer pool.Close()
	_, err := pool.Get(ctx, name)
	return err
}

func connectInteractive(configPath, name string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectionTestTimeout)
	defer cancel()
	pool := sshpkg.NewPool(cfg, &tuiCredResolver{cfg: cfg})
	defer pool.Close()
	client, err := pool.Get(ctx, name)
	if err != nil {
		return err
	}
	session, err := client.Underlying().NewSession()
	if err != nil {
		return fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	stdinFD := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFD) {
		return errors.New("interactive connection requires a terminal")
	}
	width, height, err := term.GetSize(stdinFD)
	if err != nil {
		width, height = 80, 24
	}
	termName := os.Getenv("TERM")
	if termName == "" {
		termName = "xterm-256color"
	}
	modes := gossh.TerminalModes{gossh.ECHO: 1, gossh.TTY_OP_ISPEED: 14400, gossh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty(termName, height, width, modes); err != nil {
		return fmt.Errorf("request remote terminal: %w", err)
	}
	session.Stdin, session.Stdout, session.Stderr = os.Stdin, os.Stdout, os.Stderr
	oldState, err := term.MakeRaw(stdinFD)
	if err != nil {
		return fmt.Errorf("enter raw terminal mode: %w", err)
	}
	defer term.Restore(stdinFD, oldState)
	if err := session.Shell(); err != nil {
		return fmt.Errorf("start remote shell: %w", err)
	}
	resizeContext, stopResize := context.WithCancel(context.Background())
	resizeTicker := time.NewTicker(terminalResizeInterval)
	resizeDone := make(chan struct{})
	go func() {
		defer close(resizeDone)
		watchTerminalResize(resizeContext, resizeTicker.C, func() (int, int, error) {
			return term.GetSize(stdinFD)
		}, session, width, height)
	}()
	defer func() {
		stopResize()
		resizeTicker.Stop()
		<-resizeDone
	}()
	if err := session.Wait(); err != nil {
		var exitError *gossh.ExitError
		if errors.As(err, &exitError) {
			return fmt.Errorf("remote shell exited with status %d", exitError.ExitStatus())
		}
		return err
	}
	return nil
}

func watchTerminalResize(ctx context.Context, ticks <-chan time.Time, getSize terminalSizeFunc, remote windowChanger, width, height int) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			newWidth, newHeight, err := getSize()
			if err != nil || newWidth <= 0 || newHeight <= 0 || (newWidth == width && newHeight == height) {
				continue
			}
			if err := remote.WindowChange(newHeight, newWidth); err != nil {
				continue
			}
			width, height = newWidth, newHeight
		}
	}
}

func defaultFetchHostKey(addr string) (gossh.PublicKey, error) { return knownhosts.FetchHostKey(addr) }
func defaultCommitHostKey(host string, key gossh.PublicKey) error {
	return safety.HostKeyCallback(true)(host, staticAddr(host), key)
}

func (m *Model) startHostKeyPreview(item row) tea.Cmd {
	addr := net.JoinHostPort(item.value.Host, fmt.Sprintf("%d", effectivePort(item.value.Port)))
	m.hostKeyGeneration++
	generation := m.hostKeyGeneration
	m.message, m.err = "Fetching host key for "+addr+"...", ""
	fetch := m.fetchHostKey
	return func() tea.Msg {
		key, err := fetch(addr)
		return hostKeyResultMsg{name: item.key, addr: addr, key: key, generation: generation, err: err}
	}
}

func (m *Model) acceptHostKeyResult(message hostKeyResultMsg) bool {
	if message.generation != m.hostKeyGeneration {
		return false
	}
	item, selected := m.currentRow()
	machine, exists := m.config.Servers[message.name]
	expectedAddr := ""
	if exists {
		expectedAddr = net.JoinHostPort(machine.Host, fmt.Sprintf("%d", effectivePort(machine.Port)))
	}
	if !selected || item.key != message.name || expectedAddr != message.addr || m.confirmation != nil || m.form != nil || m.password != nil || m.menuOpen || m.helpOpen {
		m.hostKeyGeneration++
		m.message = "Host key preview cancelled; retry when the target is selected and no other action is open."
		return false
	}
	return true
}

func (m *Model) handleHostKeyResult(message hostKeyResultMsg) {
	if message.err != nil {
		m.err, m.message = "Host key fetch failed: "+message.err.Error(), ""
		return
	}
	if err := verifyFetchedHostKey(message.addr, message.key); err == nil {
		m.err, m.message = "", "Host key already trusted."
		return
	} else if !errors.Is(err, errHostKeyUnknown) {
		m.err, m.message = err.Error(), ""
		return
	}
	m.pendingHostKey = message.key
	m.confirmation = &confirmation{
		kind: confirmationTrust,
		addr: message.addr,
		key:  message.key,
		prompt: fmt.Sprintf("Trust host key for %s?\nFingerprint: %s\nVerify this fingerprint through a separate trusted channel before confirming.",
			message.addr, gossh.FingerprintSHA256(message.key)),
	}
	m.err, m.message = "", ""
}

func verifyFetchedHostKey(addr string, key gossh.PublicKey) error {
	err := safety.HostKeyCallback(false)(addr, staticAddr(addr), key)
	if err == nil {
		return nil
	}
	message := err.Error()
	if strings.Contains(message, "HOST_KEY_MISMATCH") {
		//lint:ignore ST1005 This error is rendered directly as a TUI status message.
		return fmt.Errorf("Host key mismatch for %s. Connection is blocked; verify and repair known_hosts manually", addr)
	}
	if strings.Contains(message, "HOST_KEY_UNKNOWN") {
		return errHostKeyUnknown
	}
	//lint:ignore ST1005 This error is rendered directly as a TUI status message.
	return fmt.Errorf("Host key verification failed: %w", err)
}

type staticAddr string

func (addr staticAddr) Network() string { return "tcp" }
func (addr staticAddr) String() string  { return string(addr) }

func defaultKnownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}
