package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
)

func init() { registerSubcommand("config", configCmd) }

// defaultConfigContent is written by `config init` when no config file exists.
const defaultConfigContent = `# mcp-ssh-bridge configuration
# See documentation for full option reference.

[settings]
# allow_config_plaintext_password = false
# allow_inline_credentials = true
# allow_quick_setup = true
# default_timeout_ms = 120000
# max_timeout_ms = 1800000
# output_max_bytes = 65536
# session_idle_seconds = 3600
# conn_idle_seconds = 600
# audit_retention_days = 90

# [servers.example]
# host = "example.com"
# port = 22
# user = "myuser"
# auth = "key"
# key_path = "~/.ssh/id_ed25519"
`

func configCmd(args []string) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: mcp-ssh-bridge config <subcommand> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Subcommands:")
		fmt.Fprintln(os.Stderr, "  init      Write default config.toml (fails if file already exists)")
		fmt.Fprintln(os.Stderr, "  validate  Load and validate the config file, print errors or 'Config OK'")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  --path <file>  Config file path (default: platform default)")
	}

	if len(args) == 0 {
		fs.Usage()
		return 1
	}

	pathFlag := ""
	// Strip leading flags before subcommand detection (simple approach).
	subArgs := args
	sub := subArgs[0]
	if len(subArgs) > 1 {
		subArgs = subArgs[1:]
	} else {
		subArgs = nil
	}

	subFS := flag.NewFlagSet("config "+sub, flag.ContinueOnError)
	subFS.StringVar(&pathFlag, "path", "", "config file path")
	if err := subFS.Parse(subArgs); err != nil {
		fmt.Fprintf(os.Stderr, "config %s: %v\n", sub, err)
		return 1
	}

	cfgPath := pathFlag
	if cfgPath == "" {
		cfgPath = resolveConfigPath()
	}

	switch sub {
	case "init":
		return configInitCmd(cfgPath)
	case "validate":
		return configValidateCmd(cfgPath)
	default:
		fmt.Fprintf(os.Stderr, "config: unknown subcommand %q\n", sub)
		fs.Usage()
		return 1
	}
}

// resolveConfigPath returns MCP_SSH_BRIDGE_CONFIG env var or the platform default.
func resolveConfigPath() string {
	if p := os.Getenv("MCP_SSH_BRIDGE_CONFIG"); p != "" {
		return p
	}
	return config.DefaultPath()
}

// configInitCmd writes the default config to cfgPath, failing if it already exists.
func configInitCmd(cfgPath string) int {
	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Fprintf(os.Stderr, "config init: file already exists: %s\n", cfgPath)
		fmt.Fprintf(os.Stderr, "  Use 'config validate' to check it, or delete it to re-initialize.\n")
		return 1
	}

	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "config init: cannot create directory %s: %v\n", dir, err)
		return 1
	}

	if err := os.WriteFile(cfgPath, []byte(defaultConfigContent), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "config init: write failed: %v\n", err)
		return 1
	}

	fmt.Printf("Config initialized: %s\n", cfgPath)
	return 0
}

// configValidateCmd loads and validates cfgPath, printing errors or "Config OK".
func configValidateCmd(cfgPath string) int {
	_, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config validate: %v\n", err)
		return 1
	}
	fmt.Println("Config OK")
	return 0
}
