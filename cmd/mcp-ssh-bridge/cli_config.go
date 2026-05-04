package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
)

// serverNamePattern matches the SDD server-name rule: ^[a-z0-9][a-z0-9_-]*$,
// length 1-64. Used by add-server to fail fast before writing.
var serverNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

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

// configAddServerCmd appends a new [servers.<name>] block to cfgPath.
// Refuses to overwrite an existing entry; the user must remove it manually
// to avoid silent destruction. The resulting file is re-validated; on a
// validation failure we restore the original content.
//
// For auth=password the default is to emit a keychain: reference instead
// of a plaintext value, and to print the keychain set-keychain command
// the user must run next. The CLI never reads, prompts for, or writes a
// raw password to the config file.
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
	)
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
	if !serverNamePattern.MatchString(*name) {
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

	// Refuse to clobber an existing entry: scan the current file for the
	// section header. Cheap and language-agnostic — we don't need a full
	// TOML parse to detect duplicates.
	original, err := os.ReadFile(cfgPath)
	switch {
	case err == nil:
		marker := "[servers." + *name + "]"
		if strings.Contains(string(original), marker) {
			fmt.Fprintf(os.Stderr, "config add-server: server %q already exists in %s\n", *name, cfgPath)
			fmt.Fprintln(os.Stderr, "  Edit the file manually or remove the existing block first.")
			return 1
		}
	case os.IsNotExist(err):
		// First write — ensure parent dir + run config init shape.
		dir := filepath.Dir(cfgPath)
		if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
			fmt.Fprintf(os.Stderr, "config add-server: cannot create directory %s: %v\n", dir, mkErr)
			return 1
		}
		original = []byte{}
	default:
		fmt.Fprintf(os.Stderr, "config add-server: read %s: %v\n", cfgPath, err)
		return 1
	}

	var sb strings.Builder
	sb.Write(original)
	if len(original) > 0 && !strings.HasSuffix(string(original), "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString("\n[servers.")
	sb.WriteString(*name)
	sb.WriteString("]\n")
	sb.WriteString(fmt.Sprintf("host = %q\n", *host))
	sb.WriteString(fmt.Sprintf("port = %d\n", *port))
	sb.WriteString(fmt.Sprintf("user = %q\n", *user))
	sb.WriteString(fmt.Sprintf("auth = %q\n", *auth))
	if *keyPath != "" {
		sb.WriteString(fmt.Sprintf("key_path = %q\n", *keyPath))
	}
	keychainHint := ""
	if *auth == "password" && *passwordKeychain {
		ref := fmt.Sprintf("keychain:%s:ssh-password:%s", keychainService(), *name)
		sb.WriteString(fmt.Sprintf("password = %q\n", ref))
		keychainHint = fmt.Sprintf("mcp-ssh-bridge auth set-keychain %s ssh-password:%s", keychainService(), *name)
	}
	if *description != "" {
		sb.WriteString(fmt.Sprintf("description = %q\n", *description))
	}
	if *proxyJump != "" {
		sb.WriteString(fmt.Sprintf("proxy_jump = %q\n", *proxyJump))
	}
	if *defaultDir != "" {
		sb.WriteString(fmt.Sprintf("default_dir = %q\n", *defaultDir))
	}
	if *tagsCSV != "" {
		var tags []string
		for _, t := range strings.Split(*tagsCSV, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, fmt.Sprintf("%q", t))
			}
		}
		if len(tags) > 0 {
			sb.WriteString("tags = [")
			sb.WriteString(strings.Join(tags, ", "))
			sb.WriteString("]\n")
		}
	}

	// Atomic write so a validation failure mid-flight does not corrupt the
	// config file. Permissions match the rest of the codebase (0600 for
	// secrets-adjacent files).
	tmp := cfgPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "config add-server: write %s: %v\n", tmp, err)
		return 1
	}
	if _, err := config.Load(tmp); err != nil {
		_ = os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "config add-server: validation failed (config NOT modified):\n  %v\n", err)
		return 1
	}
	if err := os.Rename(tmp, cfgPath); err != nil {
		_ = os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "config add-server: rename: %v\n", err)
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
