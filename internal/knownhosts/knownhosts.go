package knownhosts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/safety"
)

var errHostKeyCaptured = errors.New("host key captured")

// FetchHostKey retrieves a server key without attempting authentication or
// changing known_hosts. Callers must show the fingerprint before Append.
func FetchHostKey(addr string) (gossh.PublicKey, error) {
	return FetchHostKeyContext(context.Background(), addr)
}

// FetchHostKeyContext retrieves a server key and interrupts dialing or the
// SSH handshake when ctx is cancelled.
func FetchHostKeyContext(ctx context.Context, addr string) (gossh.PublicKey, error) {
	return fetchHostKeyContext(ctx, addr, 15*time.Second)
}

func fetchHostKeyContext(ctx context.Context, addr string, timeout time.Duration) (gossh.PublicKey, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return fetchHostKeyContextWithDial(ctx, addr, timeout, dialer.DialContext)
}

func fetchHostKeyContextWithDial(ctx context.Context, addr string, timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error)) (gossh.PublicKey, error) {
	if addr == "" {
		return nil, errors.New("host address is required")
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	connection, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer connection.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancel()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set host key handshake deadline for %s: %w", addr, err)
	}

	var captured gossh.PublicKey
	clientConfig := &gossh.ClientConfig{
		User: "mcp-trust-preview",
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			captured = key
			return errHostKeyCaptured
		},
		HostKeyAlgorithms: safety.ModernHostKeyAlgorithms(),
		Config:            safety.ModernAlgorithms(nil),
		Timeout:           timeout,
	}
	_, _, _, err = gossh.NewClientConn(connection, addr, clientConfig)
	if captured != nil {
		return captured, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fetch host key from %s: %w", addr, err)
	}
	return nil, fmt.Errorf("fetch host key from %s: no host key received", addr)
}

func IsAuthenticationError(message string) bool {
	for _, substring := range []string{
		"unable to authenticate",
		"no supported methods remain",
		"handshake failed: ssh: unable to authenticate",
		"ssh: handshake failed",
		"permission denied",
	} {
		if strings.Contains(strings.ToLower(message), substring) {
			return true
		}
	}
	return false
}
