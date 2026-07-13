package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/knownhosts"
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

	addr := fmt.Sprintf("%s:%d", host, port)
	fmt.Printf("Fetching host key from %s ...\n", addr)

	if err := knownhosts.TrustHostKey(addr); err != nil {
		fmt.Fprintf(os.Stderr, "trust: %v\n", err)
		return 1
	}

	fmt.Printf("Host key for %s has been added to ~/.ssh/known_hosts\n", addr)
	return 0
}
