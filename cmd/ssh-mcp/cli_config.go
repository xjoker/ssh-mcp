package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/config"
)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func init() { registerSubcommand("config", configCmd) }

// defaultConfigContent is written by `config init` when no config file exists.
const defaultConfigContent = `# ssh-mcp configuration
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
		fmt.Fprintln(os.Stderr, "Usage: ssh-mcp config <subcommand> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Subcommands:")
		fmt.Fprintln(os.Stderr, "  init        Write default config.toml (fails if file already exists)")
		fmt.Fprintln(os.Stderr, "  validate    Load and validate the config file")
		fmt.Fprintln(os.Stderr, "  add-server  Append a new [servers.<name>] block")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  --path <file>  Config file path (default: platform default)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "add-server flags (all writable via the same --path):")
		fmt.Fprintln(os.Stderr, "  --name <name>      server entry name (required, [a-z0-9][a-z0-9_-]{0,63})")
		fmt.Fprintln(os.Stderr, "  --host <host>      remote host or IP (required)")
		fmt.Fprintln(os.Stderr, "  --user <user>      SSH user (required)")
		fmt.Fprintln(os.Stderr, "  --port <n>         SSH port (default 22)")
		fmt.Fprintln(os.Stderr, "  --auth <mode>      one of agent|key|password (default agent)")
		fmt.Fprintln(os.Stderr, "  --key-path <path>  key path for auth=key")
		fmt.Fprintln(os.Stderr, "  --password-keychain  store keychain ref for auth=password (default true)")
		fmt.Fprintln(os.Stderr, "  --tags <a,b,c>     comma-separated tags")
		fmt.Fprintln(os.Stderr, "  --description <s>  free-form description")
		fmt.Fprintln(os.Stderr, "  --proxy-jump <name>  jump-host server name")
		fmt.Fprintln(os.Stderr, "  --default-dir <p>  default working directory")
		fmt.Fprintln(os.Stderr, "  --mode <mode>      command policy: unrestricted|readonly|restricted")
		fmt.Fprintln(os.Stderr, "  --allow <regexp>   allow command pattern (repeatable)")
		fmt.Fprintln(os.Stderr, "  --deny <regexp>    deny command pattern (repeatable)")
	}

	if len(args) == 0 {
		fs.Usage()
		return 1
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "init":
		cfgPath, rest, ok := parsePathFlag(sub, subArgs)
		if !ok {
			return 1
		}
		_ = rest
		return configInitCmd(cfgPath)
	case "validate":
		cfgPath, _, ok := parsePathFlag(sub, subArgs)
		if !ok {
			return 1
		}
		return configValidateCmd(cfgPath)
	case "add-server":
		// add-server has many of its own flags; let it parse the entire
		// arg list so --path is just one of them.
		return configAddServerCmd(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "config: unknown subcommand %q\n", sub)
		fs.Usage()
		return 1
	}
}

// parsePathFlag extracts an optional --path flag from args for subcommands
// that take only that one flag. Returns (resolved path, remaining args, ok).
// Falls back to resolveConfigPath when --path is absent.
func parsePathFlag(sub string, args []string) (string, []string, bool) {
	pathFlag := ""
	subFS := flag.NewFlagSet("config "+sub, flag.ContinueOnError)
	subFS.StringVar(&pathFlag, "path", "", "config file path")
	if err := subFS.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "config %s: %v\n", sub, err)
		return "", nil, false
	}
	if pathFlag == "" {
		pathFlag = resolveConfigPath()
	}
	return pathFlag, subFS.Args(), true
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

func configAddServerCmd(args []string) int {
	fs := flag.NewFlagSet("config add-server", flag.ContinueOnError)
	var (
		pathFlag         = fs.String("path", "", "config file path")
		name             = fs.String("name", "", "server entry name")
		host             = fs.String("host", "", "remote host")
		user             = fs.String("user", "", "SSH user")
		port             = fs.Int("port", 22, "SSH port")
		auth             = fs.String("auth", "agent", "auth mode: agent|key|password")
		keyPath          = fs.String("key-path", "", "private key path (auth=key)")
		passwordKeychain = fs.Bool("password-keychain", true, "use keychain reference for auth=password")
		tagsCSV          = fs.String("tags", "", "comma-separated tags")
		description      = fs.String("description", "", "free-form description")
		proxyJump        = fs.String("proxy-jump", "", "jump-host server name")
		defaultDir       = fs.String("default-dir", "", "default working directory")
		mode             = fs.String("mode", "", "command policy mode")
		allowPatterns    stringList
		denyPatterns     stringList
	)
	fs.Var(&allowPatterns, "allow", "allow command pattern (repeatable)")
	fs.Var(&denyPatterns, "deny", "deny command pattern (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	cfgPath := *pathFlag
	if cfgPath == "" {
		cfgPath = resolveConfigPath()
	}

	if *name == "" || *host == "" || *user == "" {
		fmt.Fprintln(os.Stderr, "config add-server: --name, --host, --user are required")
		return 1
	}
	if err := config.ValidateServerName(*name); err != nil {
		fmt.Fprintf(os.Stderr, "config add-server: invalid name %q (must match ^[a-z0-9][a-z0-9_-]{0,63}$)\n", *name)
		return 1
	}
	switch *auth {
	case "agent", "key", "password":
		// ok
	default:
		fmt.Fprintf(os.Stderr, "config add-server: --auth must be one of agent|key|password (got %q)\n", *auth)
		return 1
	}
	if *auth == "key" && *keyPath == "" {
		fmt.Fprintln(os.Stderr, "config add-server: --key-path is required when --auth=key")
		return 1
	}
	if *port < 1 || *port > 65535 {
		fmt.Fprintf(os.Stderr, "config add-server: --port out of range [1,65535]: %d\n", *port)
		return 1
	}

	cfg, err := loadConfigForWrite(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config add-server: %v\n", err)
		return 1
	}
	server := config.ServerConfig{
		Host:        *host,
		Port:        *port,
		User:        *user,
		Auth:        *auth,
		KeyPath:     *keyPath,
		Description: *description,
		ProxyJump:   *proxyJump,
		DefaultDir:  *defaultDir,
		Tags:        parseCommaSeparated(*tagsCSV),
	}
	keychainHint := ""
	if *auth == "password" && *passwordKeychain {
		ref := fmt.Sprintf("keychain:%s:ssh-password:%s", keychainService(), *name)
		password, parseErr := config.ParseCredRef(ref)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "config add-server: build keychain reference: %v\n", parseErr)
			return 1
		}
		server.Password = password
		keychainHint = fmt.Sprintf("ssh-mcp auth set ssh-password:%s", *name)
	}
	if err := config.AddServer(cfg, *name, server); err != nil {
		fmt.Fprintf(os.Stderr, "config add-server: validation failed (config NOT modified):\n  %v\n", err)
		return 1
	}
	if err := config.SetServerPolicy(cfg, *name, *mode, allowPatterns, denyPatterns); err != nil {
		fmt.Fprintf(os.Stderr, "config add-server: validation failed (config NOT modified):\n  %v\n", err)
		return 1
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "config add-server: validation failed (config NOT modified):\n  %v\n", err)
		return 1
	}

	fmt.Printf("Added server %q (%s@%s:%d, auth=%s) → %s\n", *name, *user, *host, *port, *auth, cfgPath)
	if keychainHint != "" {
		fmt.Println()
		fmt.Println("Next: store the password in your OS keychain with:")
		fmt.Println("  " + keychainHint)
	}
	return 0
}

func loadConfigForWrite(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return config.NewConfig(), nil
	}
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseCommaSeparated(raw string) []string {
	var values []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}
