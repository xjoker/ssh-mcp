package knownhosts

import (
	"fmt"
	"net"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/safety"
)

func TrustHostKey(addr string) error {
	appended := false
	innerCallback := safety.HostKeyCallback(true)
	callback := gossh.HostKeyCallback(func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		err := innerCallback(hostname, remote, key)
		if err == nil {
			appended = true
		}
		return err
	})

	clientConfig := &gossh.ClientConfig{
		User: "mcp-trust-probe",
		Auth: []gossh.AuthMethod{
			gossh.Password(""),
		},
		HostKeyCallback:   callback,
		HostKeyAlgorithms: safety.ModernHostKeyAlgorithms(),
		Config:            safety.ModernAlgorithms(nil),
		Timeout:           15 * time.Second,
	}
	client, err := gossh.Dial("tcp", addr, clientConfig)
	if err != nil {
		if appended {
			return nil
		}
		if strings.Contains(err.Error(), "HOST_KEY_MISMATCH") {
			return fmt.Errorf("host key mismatch for %s — key has changed, manual verification required", addr)
		}
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	return client.Close()
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
