package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/mcp-ssh-bridge/internal/auth"
	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
	sshpkg "github.com/xjoker/mcp-ssh-bridge/internal/ssh"
)

func init() { registerSubcommand("server", serverCmd) }

func serverCmd(args []string) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: mcp-ssh-bridge server <subcommand> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Subcommands:")
		fmt.Fprintln(os.Stderr, "  add <name>    Add a new server (interactive or via flags)")
		fmt.Fprintln(os.Stderr, "  list          List all configured servers")
		fmt.Fprintln(os.Stderr, "  remove <name> Remove a server from config")
		fmt.Fprintln(os.Stderr, "  test <name>   Test connectivity to a server")
		fmt.Fprintln(os.Stderr, "  show <name>   Show server configuration details")
	}

	if len(args) == 0 {
		fs.Usage()
		return 1
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "add":
		return serverAddCmd(subArgs)
	case "list":
		return serverListCmd(subArgs)
	case "remove":
		return serverRemoveCmd(subArgs)
	case "test":
		return serverTestCmd(subArgs)
	case "show":
		return serverShowCmd(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "server: unknown subcommand %q\n", sub)
		fs.Usage()
		return 1
	}
}

// --------------------------------------------------------------------------
// server add
// --------------------------------------------------------------------------

func serverAddCmd(args []string) int {
	fs := flag.NewFlagSet("server add", flag.ContinueOnError)
	var (
		nameFlag    string
		host        string
		portStr     string
		user        string
		authMethod  string
		keyPath     string
		description string
		pathFlag    string
	)
	fs.StringVar(&nameFlag, "name", "", "server name (alternative to positional argument)")
	fs.StringVar(&host, "host", "", "SSH host")
	fs.StringVar(&portStr, "port", "", "SSH port (default 22)")
	fs.StringVar(&user, "user", "", "SSH user")
	fs.StringVar(&authMethod, "auth", "", "auth method: agent/key/password")
	fs.StringVar(&keyPath, "key-path", "", "path to private key (required for auth=key)")
	fs.StringVar(&description, "description", "", "server description")
	fs.StringVar(&pathFlag, "path", "", "config file path")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: mcp-ssh-bridge server add <name> [flags]")
		fs.PrintDefaults()
	}

	// Separate flags from positional args: collect all --flag args and
	// the first non-flag arg as the server name, allowing flags to appear
	// before or after the name.
	var positionals []string
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			// Peek ahead for the flag value (handles both -flag value and -flag=value).
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			positionals = append(positionals, a)
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	// Determine name: prefer --name flag, then positional, then interactive.
	name := nameFlag
	if name == "" && len(positionals) > 0 {
		name = positionals[0]
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "server add: missing server name")
		fs.Usage()
		return 1
	}
	name = strings.ToLower(name)

	cfgPath := pathFlag
	if cfgPath == "" {
		cfgPath = resolveConfigPath()
	}

	reader := bufio.NewReader(os.Stdin)

	// Prompt helper: prints prompt and reads a line from stdin.
	prompt := func(label, def string) string {
		if def != "" {
			fmt.Printf("  %s [%s]: ", label, def)
		} else {
			fmt.Printf("  %s: ", label)
		}
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		return line
	}

	if host == "" {
		host = prompt("Host", "")
	}
	if host == "" {
		fmt.Fprintln(os.Stderr, "server add: host is required")
		return 1
	}

	if portStr == "" {
		portStr = prompt("Port", "22")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "server add: invalid port %q\n", portStr)
		return 1
	}

	if user == "" {
		user = prompt("User", "")
	}
	if user == "" {
		fmt.Fprintln(os.Stderr, "server add: user is required")
		return 1
	}

	if authMethod == "" {
		authMethod = prompt("Auth method (agent/key/password)", "agent")
	}
	if authMethod == "" {
		authMethod = "agent"
	}

	switch authMethod {
	case "agent", "key", "password":
		// ok
	default:
		fmt.Fprintf(os.Stderr, "server add: auth must be one of agent/key/password, got %q\n", authMethod)
		return 1
	}

	if authMethod == "key" && keyPath == "" {
		keyPath = prompt("Key path", "~/.ssh/id_ed25519")
	}

	// Build a minimal TOML snippet to append.
	srv := config.ServerConfig{
		Host:    host,
		Port:    port,
		User:    user,
		Auth:    authMethod,
		KeyPath: keyPath,
	}
	if description != "" {
		srv.Description = description
	}

	if err := serverAppendToConfig(cfgPath, name, srv); err != nil {
		fmt.Fprintf(os.Stderr, "server add: %v\n", err)
		return 1
	}

	fmt.Printf("Server %q added to %s\n", name, cfgPath)
	return 0
}

// rawServerForEncode is a map-friendly representation for TOML encoding.
type rawServerForEncode struct {
	Host        string `toml:"host"`
	Port        int    `toml:"port,omitempty"`
	User        string `toml:"user"`
	Auth        string `toml:"auth"`
	KeyPath     string `toml:"key_path,omitempty"`
	Description string `toml:"description,omitempty"`
}

// serverAppendToConfig appends a [servers.<name>] section to cfgPath.
// If the file doesn't exist, it creates a minimal valid config first.
func serverAppendToConfig(cfgPath string, name string, srv config.ServerConfig) error {
	// Build TOML snippet manually to avoid the full encode/decode cycle.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n[servers.%s]\n", name))
	sb.WriteString(fmt.Sprintf("host = %q\n", srv.Host))
	if srv.Port != 0 && srv.Port != 22 {
		sb.WriteString(fmt.Sprintf("port = %d\n", srv.Port))
	}
	sb.WriteString(fmt.Sprintf("user = %q\n", srv.User))
	sb.WriteString(fmt.Sprintf("auth = %q\n", srv.Auth))
	if srv.KeyPath != "" {
		sb.WriteString(fmt.Sprintf("key_path = %q\n", srv.KeyPath))
	}
	if srv.Description != "" {
		sb.WriteString(fmt.Sprintf("description = %q\n", srv.Description))
	}

	// If the file doesn't exist, create with minimal header first.
	if _, statErr := os.Stat(cfgPath); os.IsNotExist(statErr) {
		dir := cfgPath[:strings.LastIndex(cfgPath, string(os.PathSeparator))]
		if dir != "" {
			if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
				return fmt.Errorf("cannot create config directory: %w", mkErr)
			}
		}
		header := "# mcp-ssh-bridge configuration\n\n[settings]\n"
		if writeErr := os.WriteFile(cfgPath, []byte(header), 0600); writeErr != nil {
			return fmt.Errorf("cannot create config file: %w", writeErr)
		}
	}

	// Check if server name already exists.
	existing, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("cannot read config: %w", err)
	}
	needle := fmt.Sprintf("[servers.%s]", name)
	if bytes.Contains(existing, []byte(needle)) {
		return fmt.Errorf("server %q already exists in config", name)
	}

	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot open config for append: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(sb.String()); err != nil {
		return fmt.Errorf("cannot write server entry: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// server list
// --------------------------------------------------------------------------

func serverListCmd(args []string) int {
	fs := flag.NewFlagSet("server list", flag.ContinueOnError)
	pathFlag := ""
	fs.StringVar(&pathFlag, "path", "", "config file path")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfgPath := pathFlag
	if cfgPath == "" {
		cfgPath = resolveConfigPath()
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server list: %v\n", err)
		return 1
	}

	if len(cfg.Servers) == 0 {
		fmt.Println("No servers configured.")
		return 0
	}

	fmt.Printf("%-20s %-30s %-20s %-10s %-15s %s\n",
		"NAME", "HOST", "USER", "AUTH", "TAGS", "PROXY_JUMP")
	fmt.Println(strings.Repeat("-", 100))

	for name, srv := range cfg.Servers {
		tags := strings.Join(srv.Tags, ",")
		port := srv.Port
		if port == 0 {
			port = 22
		}
		hostPort := fmt.Sprintf("%s:%d", srv.Host, port)
		fmt.Printf("%-20s %-30s %-20s %-10s %-15s %s\n",
			name, hostPort, srv.User, srv.Auth, tags, srv.ProxyJump)
	}
	return 0
}

// --------------------------------------------------------------------------
// server remove
// --------------------------------------------------------------------------

// onDiskConfig mirrors the top-level TOML structure for encode/decode.
type onDiskConfig struct {
	Settings config.Settings            `toml:"settings"`
	Servers  map[string]serverForEncode `toml:"servers,omitempty"`
}

// serverForEncode is used exclusively for round-trip TOML encode/decode.
// Using map[string]interface{} to avoid CredRef zero-value serialization issues.
type serverForEncode struct {
	Host          string          `toml:"host"`
	Port          int             `toml:"port,omitempty"`
	User          string          `toml:"user"`
	Auth          string          `toml:"auth"`
	KeyPath       string          `toml:"key_path,omitempty"`
	KeyPassphrase config.CredRef  `toml:"key_passphrase,omitempty"`
	Password      config.CredRef  `toml:"password,omitempty"`
	DefaultDir    string          `toml:"default_dir,omitempty"`
	Description   string          `toml:"description,omitempty"`
	ProxyJump     string          `toml:"proxy_jump,omitempty"`
	AllowedPaths  []string        `toml:"allowed_paths,omitempty"`
	Tags          []string        `toml:"tags,omitempty"`
}

func serverRemoveCmd(args []string) int {
	fs := flag.NewFlagSet("server remove", flag.ContinueOnError)
	pathFlag := ""
	fs.StringVar(&pathFlag, "path", "", "config file path")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "server remove: missing server name")
		return 1
	}
	name := strings.ToLower(remaining[0])

	cfgPath := pathFlag
	if cfgPath == "" {
		cfgPath = resolveConfigPath()
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server remove: %v\n", err)
		return 1
	}

	if _, ok := cfg.Servers[name]; !ok {
		fmt.Fprintf(os.Stderr, "server remove: server %q not found\n", name)
		return 1
	}

	delete(cfg.Servers, name)

	if err := saveConfig(cfgPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "server remove: %v\n", err)
		return 1
	}

	fmt.Printf("Server %q removed from %s\n", name, cfgPath)
	return 0
}

// saveConfig encodes cfg back to cfgPath using BurntSushi/toml.
// NOTE: This will lose comments — acceptable for MVP per SDD.
func saveConfig(cfgPath string, cfg *config.Config) error {
	enc := make(map[string]serverForEncode, len(cfg.Servers))
	for k, v := range cfg.Servers {
		enc[k] = serverForEncode{
			Host:          v.Host,
			Port:          v.Port,
			User:          v.User,
			Auth:          v.Auth,
			KeyPath:       v.KeyPath,
			KeyPassphrase: v.KeyPassphrase,
			Password:      v.Password,
			DefaultDir:    v.DefaultDir,
			Description:   v.Description,
			ProxyJump:     v.ProxyJump,
			AllowedPaths:  v.AllowedPaths,
			Tags:          v.Tags,
		}
	}

	disk := onDiskConfig{
		Settings: cfg.Settings,
		Servers:  enc,
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(disk); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	if err := os.WriteFile(cfgPath, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// server test
// --------------------------------------------------------------------------

func serverTestCmd(args []string) int {
	fs := flag.NewFlagSet("server test", flag.ContinueOnError)
	pathFlag := ""
	fs.StringVar(&pathFlag, "path", "", "config file path")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "server test: missing server name")
		return 1
	}
	name := strings.ToLower(remaining[0])

	cfgPath := pathFlag
	if cfgPath == "" {
		cfgPath = resolveConfigPath()
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server test: %v\n", err)
		return 1
	}

	srv, ok := cfg.Servers[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "server test: server %q not found\n", name)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("Testing server %q...\n", name)

	// Build auth methods directly (mirroring mcpserver.credResolver logic).
	authMethods, err := resolveAuthForTest(ctx, cfg, srv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Authentication... FAIL\n  %v\n", err)
		return 1
	}
	fmt.Println("Authentication... OK")

	// Use internal/ssh.Pool for the actual test dial.
	resolver := &cliCredResolver{cfg: cfg}
	pool := sshpkg.NewPool(cfg, resolver)
	defer pool.Close()

	_ = authMethods // authMethods was resolved above for early error detection

	client, err := pool.Get(ctx, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connecting... FAIL\n  %v\n", err)
		return 1
	}
	fmt.Println("Connecting... OK")

	// Run `echo ok` as a smoke test.
	cmd, err := safety.NewRemoteCommand("echo ok", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Exec echo ok... FAIL\n  %v\n", err)
		return 1
	}

	result, err := client.ExecBuffered(ctx, cmd, sshpkg.ExecOpts{Timeout: 10 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Exec echo ok... FAIL\n  %v\n", err)
		return 1
	}
	output := strings.TrimSpace(string(result.Stdout))
	if output != "ok" {
		fmt.Fprintf(os.Stderr, "Exec echo ok... FAIL (got %q, want %q)\n", output, "ok")
		return 1
	}

	fmt.Println("Exec echo ok... OK")
	fmt.Println("Done.")
	return 0
}

// cliCredResolver implements ssh.CredResolver for CLI test usage.
type cliCredResolver struct {
	cfg *config.Config
}

func (r *cliCredResolver) ResolveServerAuth(
	ctx context.Context,
	srv config.ServerConfig,
) ([]gossh.AuthMethod, string, error) {
	methods, err := resolveAuthForTest(ctx, r.cfg, srv)
	return methods, srv.Auth, err
}

// resolveAuthForTest resolves authentication methods for a server config.
// This mirrors mcpserver.credResolver.ResolveServerAuth without importing mcpserver.
func resolveAuthForTest(ctx context.Context, cfg *config.Config, srv config.ServerConfig) ([]gossh.AuthMethod, error) {
	allowPlaintext := cfg.Settings.AllowConfigPlaintextPassword

	switch srv.Auth {
	case "agent":
		ag := auth.Agent()
		if ag == nil {
			return nil, fmt.Errorf("ssh-agent unavailable (SSH_AUTH_SOCK not set or socket unreachable)")
		}
		signers, err := ag.Signers()
		if err != nil {
			return nil, fmt.Errorf("ssh-agent: list signers: %w", err)
		}
		return []gossh.AuthMethod{gossh.PublicKeys(signers...)}, nil

	case "key":
		if srv.KeyPath == "" {
			return nil, fmt.Errorf("server %q: auth=key requires key_path", srv.Name)
		}
		pemBytes, err := os.ReadFile(srv.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("server %q: read key_path: %w", srv.Name, err)
		}
		var passSecret *auth.Secret
		if !srv.KeyPassphrase.IsZero() {
			passSecret, err = auth.Resolve(ctx, srv.KeyPassphrase, allowPlaintext)
			if err != nil {
				return nil, fmt.Errorf("server %q: resolve key_passphrase: %w", srv.Name, err)
			}
			defer passSecret.Close()
		}
		signer, err := auth.LoadPrivateKey(pemBytes, passSecret)
		if err != nil {
			return nil, fmt.Errorf("server %q: load private key: %w", srv.Name, err)
		}
		return []gossh.AuthMethod{gossh.PublicKeys(signer)}, nil

	case "password":
		secret, err := auth.Resolve(ctx, srv.Password, allowPlaintext)
		if err != nil {
			return nil, fmt.Errorf("server %q: resolve password: %w", srv.Name, err)
		}
		defer secret.Close()
		pw := make([]byte, len(secret.Bytes()))
		copy(pw, secret.Bytes())
		return []gossh.AuthMethod{gossh.Password(string(pw))}, nil

	default:
		return nil, fmt.Errorf("server %q: unsupported auth method %q", srv.Name, srv.Auth)
	}
}

// --------------------------------------------------------------------------
// server show
// --------------------------------------------------------------------------

func serverShowCmd(args []string) int {
	fs := flag.NewFlagSet("server show", flag.ContinueOnError)
	pathFlag := ""
	fs.StringVar(&pathFlag, "path", "", "config file path")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "server show: missing server name")
		return 1
	}
	name := strings.ToLower(remaining[0])

	cfgPath := pathFlag
	if cfgPath == "" {
		cfgPath = resolveConfigPath()
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server show: %v\n", err)
		return 1
	}

	srv, ok := cfg.Servers[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "server show: server %q not found\n", name)
		return 1
	}

	port := srv.Port
	if port == 0 {
		port = 22
	}

	fmt.Printf("Name:        %s\n", srv.Name)
	fmt.Printf("Host:        %s\n", srv.Host)
	fmt.Printf("Port:        %d\n", port)
	fmt.Printf("User:        %s\n", srv.User)
	fmt.Printf("Auth:        %s\n", srv.Auth)
	if srv.KeyPath != "" {
		fmt.Printf("KeyPath:     %s\n", srv.KeyPath)
	}
	// Print CredRef fields without revealing plaintext secret values.
	if !srv.KeyPassphrase.IsZero() {
		fmt.Printf("KeyPassphrase: %s\n", credRefSummary(srv.KeyPassphrase))
	}
	if !srv.Password.IsZero() {
		fmt.Printf("Password:    %s\n", credRefSummary(srv.Password))
	}
	if srv.DefaultDir != "" {
		fmt.Printf("DefaultDir:  %s\n", srv.DefaultDir)
	}
	if srv.Description != "" {
		fmt.Printf("Description: %s\n", srv.Description)
	}
	if srv.ProxyJump != "" {
		fmt.Printf("ProxyJump:   %s\n", srv.ProxyJump)
	}
	if len(srv.AllowedPaths) > 0 {
		fmt.Printf("AllowedPaths: %s\n", strings.Join(srv.AllowedPaths, ", "))
	}
	if len(srv.Tags) > 0 {
		fmt.Printf("Tags:        %s\n", strings.Join(srv.Tags, ", "))
	}
	return 0
}

// credRefSummary returns a safe string representation of a CredRef that does
// NOT include any plaintext secret value.
func credRefSummary(ref config.CredRef) string {
	switch ref.Kind {
	case config.CredRefKeychain:
		return fmt.Sprintf("keychain (service=%s, account=%s)", ref.Service, ref.Account)
	case config.CredRefEnv:
		return fmt.Sprintf("env (var=%s)", ref.EnvVar)
	case config.CredRefPlaintext:
		return "plaintext (value hidden)"
	default:
		return "(none)"
	}
}
