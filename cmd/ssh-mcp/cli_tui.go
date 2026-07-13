package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xjoker/ssh-mcp/internal/tui"
)

func init() { registerSubcommand("tui", tuiCmd) }

func tuiCmd(args []string) int {
	options, code, run := parseTUIOptions(args)
	if code != 0 || !run {
		return code
	}
	if err := tui.Run(options); err != nil {
		fmt.Fprintf(os.Stderr, "tui: %v\n", err)
		return 1
	}
	return 0
}

func parseTUIOptions(args []string) (tui.Options, int, bool) {
	flags := flag.NewFlagSet("tui", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("path", "", "config file path")
	auditDir := flags.String("audit-dir", "", "audit directory")
	knownHostsPath := flags.String("known-hosts", "", "known_hosts file path")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ssh-mcp tui [--path config.toml] [--audit-dir dir] [--known-hosts file]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return tui.Options{}, 0, false
		}
		return tui.Options{}, 1, false
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return tui.Options{}, 1, false
	}

	if *configPath == "" {
		*configPath = resolveConfigPath()
	}
	if *auditDir == "" {
		*auditDir = defaultAuditDirCLI()
	}
	if *knownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "tui: resolve home directory: %v\n", err)
			return tui.Options{}, 1, false
		}
		*knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}
	return tui.Options{ConfigPath: *configPath, AuditDir: *auditDir, KnownHostsPath: *knownHostsPath}, 0, true
}
