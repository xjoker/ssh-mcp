package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
)

func init() { registerSubcommand("trust", trustCmd) }

func trustCmd(args []string) int {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	var (
		hostFlag string
		portFlag int
		pathFlag string
	)
	fs.StringVar(&hostFlag, "host", "", "SSH host (use instead of a config server name)")
	fs.IntVar(&portFlag, "port", 22, "SSH port (used with --host)")
	fs.StringVar(&pathFlag, "path", "", "config file path")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: mcp-ssh-bridge trust <server-name>")
		fmt.Fprintln(os.Stderr, "       mcp-ssh-bridge trust --host <host> [--port <port>]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Fetches the host key and appends it to ~/.ssh/known_hosts.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	// Determine host and port either from flags or from named server config.
	var host string
	port := portFlag

	if hostFlag != "" {
		// Direct mode: --host was provided.
		host = hostFlag
		if port == 0 {
			port = 22
		}
	} else {
		// Named server mode.
		remaining := fs.Args()
		if len(remaining) == 0 {
			fmt.Fprintln(os.Stderr, "trust: provide a server name or --host")
			fs.Usage()
			return 1
		}
		name := strings.ToLower(remaining[0])

		cfgPath := pathFlag
		if cfgPath == "" {
			cfgPath = resolveConfigPath()
		}

		cfg, err := config.Load(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trust: %v\n", err)
			return 1
		}

		srv, ok := cfg.Servers[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "trust: server %q not found in config\n", name)
			return 1
		}
		host = srv.Host
		port = srv.Port
		if port == 0 {
			port = 22
		}
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	fmt.Printf("Fetching host key from %s ...\n", addr)

	if err := trustHostKey(addr); err != nil {
		fmt.Fprintf(os.Stderr, "trust: %v\n", err)
		return 1
	}

	fmt.Printf("Host key for %s has been added to ~/.ssh/known_hosts\n", addr)
	return 0
}

// trustHostKey connects to addr with acceptNew=true, completes the SSH
// handshake (which writes the host key to known_hosts), then immediately
// closes the connection.
//
// We use a dummy user/auth that may fail authentication — that is expected
// and acceptable, since we only care about the host key exchange phase.
func trustHostKey(addr string) error {
	cb := safety.HostKeyCallback(true)

	cfg := &gossh.ClientConfig{
		User: "mcp-trust-probe",
		Auth: []gossh.AuthMethod{
			// Use a none-auth that will always fail — we only need the handshake
			// to succeed far enough to capture the host key.
			gossh.Password(""),
		},
		HostKeyCallback:   cb,
		HostKeyAlgorithms: safety.ModernHostKeyAlgorithms(),
		Config:            safety.ModernAlgorithms(nil),
		Timeout:           15 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		// If the error is specifically an authentication failure, the host key
		// was already accepted and written to known_hosts — treat as success.
		errStr := err.Error()
		if isAuthError(errStr) {
			return nil
		}
		// If the error contains "HOST_KEY_MISMATCH", that is a real problem.
		if strings.Contains(errStr, "HOST_KEY_MISMATCH") {
			return fmt.Errorf("host key mismatch for %s — key has changed, manual verification required", addr)
		}
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	// Unexpected success (unlikely with dummy password) — still close cleanly.
	client.Close()
	return nil
}

// isAuthError reports whether an SSH dial error is specifically an
// authentication failure (meaning the host key exchange already succeeded).
func isAuthError(msg string) bool {
	authErrorSubstrings := []string{
		"unable to authenticate",
		"no supported methods remain",
		"handshake failed: ssh: unable to authenticate",
		"ssh: handshake failed",
		"permission denied",
	}
	lower := strings.ToLower(msg)
	for _, s := range authErrorSubstrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
