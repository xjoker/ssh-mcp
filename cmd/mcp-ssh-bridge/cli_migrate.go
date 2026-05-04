package main

// cli_migrate.go implements:
//   - migrate-from-legacy <env-file>  (Appendix B)
//   - migrate-passwords
//
// S-15: passwords are NEVER printed to stdout in plaintext.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/xjoker/mcp-ssh-bridge/internal/auth"
	"github.com/xjoker/mcp-ssh-bridge/internal/config"
)

func init() {
	registerSubcommand("migrate-from-legacy", migrateLegacyCmd)
	registerSubcommand("migrate-passwords", migratePasswordsCmd)
}

// --------------------------------------------------------------------------
// migrate-from-legacy
// --------------------------------------------------------------------------

// migrateLegacyCmd reads a legacy SSH-tool .env file (one with SSH_HOST=,
// SSH_USER=, SSH_PORT=, SSH_AUTH=, SSH_PASSWORD=, SSH_KEY_PATH= keys, with
// optional numeric suffixes for multi-server files) and imports each server
// entry into the mcp-ssh-bridge config.toml, storing passwords in the OS
// keychain.
func migrateLegacyCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: mcp-ssh-bridge migrate-from-legacy <env-file>")
		return 1
	}
	envFile := args[0]

	entries, err := parseLegacyEnv(envFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-from-legacy: parse %q: %v\n", envFile, err)
		return 1
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "migrate-from-legacy: no server entries found in file")
		return 1
	}

	cfgPath := os.Getenv("MCP_SSH_BRIDGE_CONFIG")
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}

	// Ensure config dir exists.
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "migrate-from-legacy: create config dir: %v\n", err)
		return 1
	}

	// Open or create config file for appending.
	f, err := os.OpenFile(cfgPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-from-legacy: open config %q: %v\n", cfgPath, err)
		return 1
	}
	defer f.Close()

	exitCode := 0
	for _, e := range entries {
		if err := importLegacyEntry(f, e); err != nil {
			fmt.Fprintf(os.Stderr, "migrate-from-legacy: import %q: %v\n", e.name, err)
			exitCode = 1
			continue
		}
		// S-15: never print password. Print only the keychain location.
		service := keychainService()
		account := keychainAccount(e.name)
		fmt.Printf("imported %s → keychain:%s:%s\n", e.name, service, account)
	}
	return exitCode
}

// legacyEntry holds parsed fields from one legacy .env server block.
type legacyEntry struct {
	name     string
	host     string
	user     string
	port     int
	password string // raw secret — never print
	keyPath  string
	auth     string // "agent" | "key" | "password"
}

// parseLegacyEnv reads KEY=VALUE pairs from a simple .env file.
// It supports one server per file (a single SSH_HOST/SSH_USER block) or
// numbered prefixes SSH_HOST_1, SSH_HOST_2, etc. for multi-server files.
func parseLegacyEnv(path string) ([]legacyEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kv := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// Strip surrounding quotes.
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		kv[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Detect multi-server via numeric suffix; fall back to single-server keys.
	suffixes := map[string]struct{}{"": {}}
	for k := range kv {
		for _, prefix := range []string{"SSH_HOST", "SSH_USER", "SSH_PORT"} {
			if strings.HasPrefix(k, prefix) {
				suffix := strings.TrimPrefix(k, prefix)
				suffix = strings.TrimPrefix(suffix, "_")
				suffixes[suffix] = struct{}{}
			}
		}
	}

	var entries []legacyEntry
	for suffix := range suffixes {
		sep := ""
		if suffix != "" {
			sep = "_"
		}
		prefix := "SSH" + sep + suffix // e.g. "" → "SSH", "1" → "SSH_1"
		// Use clean prefix logic: keys like SSH_HOST, SSH_HOST_1.
		get := func(name string) string {
			// Try "SSH_<NAME>_<SUFFIX>" then "SSH_<NAME>" for single-server.
			if suffix != "" {
				if v, ok := kv["SSH_"+name+"_"+suffix]; ok {
					return v
				}
			}
			return kv["SSH_"+name]
		}
		_ = prefix // suppress unused warning

		host := get("HOST")
		if host == "" {
			continue
		}
		user := get("USER")
		if user == "" {
			user = "root"
		}

		portStr := get("PORT")
		port := 22
		if portStr != "" {
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
				port = p
			}
		}

		password := get("PASSWORD")
		keyPath := get("KEY_PATH")
		if keyPath == "" {
			keyPath = get("IDENTITY_FILE")
		}

		authMode := get("AUTH")
		if authMode == "" {
			switch {
			case keyPath != "":
				authMode = "key"
			case password != "":
				authMode = "password"
			default:
				authMode = "agent"
			}
		}

		name := get("NAME")
		if name == "" {
			if suffix != "" {
				name = "server-" + suffix
			} else {
				// derive from host
				name = strings.ReplaceAll(strings.ToLower(host), ".", "-")
				name = strings.Map(func(r rune) rune {
					if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
						return r
					}
					return '-'
				}, name)
			}
		}
		// Sanitise name to ^[a-z0-9][a-z0-9_-]*$
		name = strings.ToLower(name)
		if len(name) == 0 {
			name = "imported"
		}

		// Validate the derived name before appending. Names that still fail
		// (e.g. SSH_NAME=evil/name produces "evil/name" which is illegal)
		// are skipped with a stderr warning rather than producing a malformed
		// [servers.X] section.
		if err := validateServerName(name); err != nil {
			fmt.Fprintf(os.Stderr, "migrate-from-legacy: skipping entry with invalid server name %q: %v\n", name, err)
			continue
		}

		entries = append(entries, legacyEntry{
			name:     name,
			host:     host,
			user:     user,
			port:     port,
			password: password,
			keyPath:  keyPath,
			auth:     authMode,
		})
	}
	return entries, nil
}

// importLegacyEntry stores the password in keychain and appends a TOML block.
func importLegacyEntry(w *os.File, e legacyEntry) error {
	service := keychainService()
	account := keychainAccount(e.name)

	// Store password in keychain (only if auth=password and password non-empty).
	passwordRef := ""
	if e.auth == "password" && e.password != "" {
		if err := auth.SetKeychain(service, account, []byte(e.password)); err != nil {
			return fmt.Errorf("SetKeychain: %w", err)
		}
		// S-15: reference only, never print the raw password.
		passwordRef = fmt.Sprintf("keychain:%s:%s", service, account)
	}

	port := e.port
	if port == 0 || port == 22 {
		port = 22
	}

	// Build TOML fragment manually to avoid library pulling in extra deps for
	// append-only writes.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n[servers.%s]\n", e.name))
	sb.WriteString(fmt.Sprintf("host = %q\n", e.host))
	sb.WriteString(fmt.Sprintf("port = %d\n", port))
	sb.WriteString(fmt.Sprintf("user = %q\n", e.user))
	sb.WriteString(fmt.Sprintf("auth = %q\n", e.auth))
	if e.keyPath != "" {
		sb.WriteString(fmt.Sprintf("key_path = %q\n", e.keyPath))
	}
	if passwordRef != "" {
		sb.WriteString(fmt.Sprintf("password = %q\n", passwordRef))
	}

	_, err := w.WriteString(sb.String())
	return err
}

// keychainService returns the keychain service name for mcp-ssh-bridge.
func keychainService() string { return "mcp-ssh-bridge" }

// keychainAccount returns the keychain account string for a server name.
func keychainAccount(serverName string) string {
	return "ssh-password:" + serverName
}

// --------------------------------------------------------------------------
// migrate-passwords
// --------------------------------------------------------------------------

// migratePasswordsCmd loads the config, finds plaintext passwords, stores them
// in keychain, and rewrites the config with keychain: references.
// S-15: passwords never appear on stdout.
func migratePasswordsCmd(_ []string) int {
	cfgPath := os.Getenv("MCP_SSH_BRIDGE_CONFIG")
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}

	// Read raw TOML bytes.
	rawBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-passwords: read %q: %v\n", cfgPath, err)
		return 1
	}

	// Decode into the same rawTopLevel structure used by config.Load.
	type rawServerCfg struct {
		Host          string `toml:"host"`
		Port          int    `toml:"port"`
		User          string `toml:"user"`
		Auth          string `toml:"auth"`
		KeyPath       string `toml:"key_path"`
		KeyPassphrase string `toml:"key_passphrase"`
		Password      string `toml:"password"`
		DefaultDir    string `toml:"default_dir"`
		Description   string `toml:"description"`
		ProxyJump     string `toml:"proxy_jump"`
		AllowedPaths  []string `toml:"allowed_paths"`
		Tags          []string `toml:"tags"`
	}
	type rawSettingsCfg struct {
		AllowConfigPlaintextPassword *bool    `toml:"allow_config_plaintext_password"`
		AllowInlineCredentials       *bool    `toml:"allow_inline_credentials"`
		AllowQuickSetup              *bool    `toml:"allow_quick_setup"`
		DefaultTimeoutMs             *int     `toml:"default_timeout_ms"`
		MaxTimeoutMs                 *int     `toml:"max_timeout_ms"`
		OutputMaxBytes               *int     `toml:"output_max_bytes"`
		SftpProgressThresholdBytes   *int     `toml:"sftp_progress_threshold_bytes"`
		SessionIdleSeconds           *int     `toml:"session_idle_seconds"`
		ConnIdleSeconds              *int     `toml:"conn_idle_seconds"`
		AuditRetentionDays           *int     `toml:"audit_retention_days"`
		WeakAlgorithmsOptIn          []string `toml:"weak_algorithms_opt_in"`
	}
	type rawTop struct {
		Settings rawSettingsCfg          `toml:"settings"`
		Servers  map[string]rawServerCfg `toml:"servers"`
	}

	var raw rawTop
	if _, err := toml.Decode(string(rawBytes), &raw); err != nil {
		fmt.Fprintf(os.Stderr, "migrate-passwords: parse %q: %v\n", cfgPath, err)
		return 1
	}

	service := keychainService()
	exitCode := 0
	migrated := 0

	for name, srv := range raw.Servers {
		// Parse the raw value through the same logic config.Load uses, so a
		// "plaintext:hunter2" entry yields just "hunter2" — not the literal
		// string "plaintext:hunter2", which would then fail to authenticate
		// after migration.
		ref, perr := config.ParseCredRef(srv.Password)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "migrate-passwords: parse password for %q: %v\n", name, perr)
			exitCode = 1
			continue
		}
		if ref.Kind != config.CredRefPlaintext || ref.Value == "" {
			continue
		}
		account := keychainAccount(name)
		if err := auth.SetKeychain(service, account, []byte(ref.Value)); err != nil {
			fmt.Fprintf(os.Stderr, "migrate-passwords: SetKeychain for %q: %v\n", name, err)
			exitCode = 1
			continue
		}
		// S-15: update in-memory; never print the raw password.
		srv.Password = fmt.Sprintf("keychain:%s:%s", service, account)
		raw.Servers[name] = srv
		migrated++
		fmt.Printf("migrated %s → keychain:%s:%s\n", name, service, account)
	}

	// Also check key_passphrase fields.
	for name, srv := range raw.Servers {
		ref, perr := config.ParseCredRef(srv.KeyPassphrase)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "migrate-passwords: parse passphrase for %q: %v\n", name, perr)
			exitCode = 1
			continue
		}
		if ref.Kind != config.CredRefPlaintext || ref.Value == "" {
			continue
		}
		account := "ssh-passphrase:" + name
		if err := auth.SetKeychain(service, account, []byte(ref.Value)); err != nil {
			fmt.Fprintf(os.Stderr, "migrate-passwords: SetKeychain passphrase for %q: %v\n", name, err)
			exitCode = 1
			continue
		}
		srv.KeyPassphrase = fmt.Sprintf("keychain:%s:%s", service, account)
		raw.Servers[name] = srv
		migrated++
		fmt.Printf("migrated passphrase %s → keychain:%s:%s\n", name, service, account)
	}

	if migrated == 0 && exitCode == 0 {
		fmt.Println("migrate-passwords: no plaintext passwords found")
		return 0
	}
	if exitCode != 0 {
		return exitCode
	}

	// Rewrite config file.
	if err := writeRawConfig(cfgPath, raw.Settings, raw.Servers); err != nil {
		fmt.Fprintf(os.Stderr, "migrate-passwords: write config: %v\n", err)
		return 1
	}
	fmt.Printf("migrate-passwords: migrated %d credential(s), config updated\n", migrated)
	return 0
}

// writeRawConfig serialises the migrated config back to disk.
// Uses the same rawTop type so field names are preserved.
func writeRawConfig(path string, settings interface{}, servers interface{}) error {
	// Build a unified map so the encoder emits [settings] and [servers.*].
	type outTop struct {
		Settings interface{}            `toml:"settings"`
		Servers  interface{} `toml:"servers"`
	}
	out := outTop{Settings: settings, Servers: servers}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	enc := toml.NewEncoder(f)
	if err := enc.Encode(out); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// defaultAuditDirCLI mirrors mcpserver.defaultAuditDir for CLI use.
// We duplicate it here to avoid importing mcpserver (would create a cycle via
// the tools/session packages). SDD §14.2 allowlist does not include mcpserver
// as a CLI dep.
func defaultAuditDirCLI() string {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		return appData + `\mcp-ssh-bridge\audit`
	default:
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "/tmp/mcp-ssh-bridge/audit"
			}
			stateHome = home + "/.local/state"
		}
		return stateHome + "/mcp-ssh-bridge"
	}
}
