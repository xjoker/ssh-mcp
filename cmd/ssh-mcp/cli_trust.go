package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/knownhosts"
	gossh "golang.org/x/crypto/ssh"
)

func init() { registerSubcommand("trust", trustCmd) }

var (
	trustFetchHostKey             = knownhosts.FetchHostKey
	trustCheckHostKey             = knownhosts.Check
	trustAppendHostKey            = knownhosts.Append
	trustKnownHostsPath           = defaultTrustKnownHostsPath
	trustInput          io.Reader = os.Stdin
	trustOutput         io.Writer = os.Stdout
)

func trustCmd(args []string) int {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	var (
		hostFlag string
		portFlag int
		pathFlag string
		yesFlag  bool
	)
	fs.StringVar(&hostFlag, "host", "", "SSH host (use instead of a config server name)")
	fs.IntVar(&portFlag, "port", 22, "SSH port (used with --host)")
	fs.StringVar(&pathFlag, "path", "", "config file path")
	fs.BoolVar(&yesFlag, "yes", false, "trust the displayed host key without prompting")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ssh-mcp trust <server-name>")
		fmt.Fprintln(os.Stderr, "       ssh-mcp trust --host <host> [--port <port>]")
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

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Fprintf(trustOutput, "Fetching host key from %s ...\n", addr)

	key, err := trustFetchHostKey(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust: %v\n", err)
		return 1
	}
	fmt.Fprintf(trustOutput, "Host key type: %s\nFingerprint: %s\n", key.Type(), gossh.FingerprintSHA256(key))

	knownHostsPath, err := trustKnownHostsPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust: %v\n", err)
		return 1
	}
	status, err := trustCheckHostKey(knownHostsPath, addr, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust: %v\n", err)
		return 1
	}
	switch status {
	case knownhosts.StatusTrusted:
		fmt.Fprintf(trustOutput, "Host key for %s is already trusted in %s\n", addr, knownHostsPath)
		return 0
	case knownhosts.StatusMismatch:
		fmt.Fprintf(os.Stderr, "trust: host key mismatch for %s; known_hosts already contains a different key. Verify the fingerprint through a trusted channel and repair known_hosts manually\n", addr)
		return 1
	}

	if !yesFlag {
		fmt.Fprint(trustOutput, "Trust this host key? Type yes to continue: ")
		answer, err := bufio.NewReader(trustInput).ReadString('\n')
		answer = strings.TrimSuffix(strings.TrimSuffix(answer, "\n"), "\r")
		if err != nil || answer != "yes" {
			fmt.Fprintln(os.Stderr, "trust: host key was not confirmed")
			return 1
		}
	}

	if err := trustAppendHostKey(knownHostsPath, addr, key); err != nil {
		fmt.Fprintf(os.Stderr, "trust: %v\n", err)
		return 1
	}

	fmt.Fprintf(trustOutput, "Host key for %s has been added to %s\n", addr, knownHostsPath)
	return 0
}

func defaultTrustKnownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}
