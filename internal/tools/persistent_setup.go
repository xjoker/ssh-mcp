// Package tools — ssh_persistent_setup tool.
//
// Unlike ssh_quick_setup (in-memory, TTL-bounded), persistent_setup writes the
// supplied server configuration to the user's config.toml so it survives
// restarts. Plaintext password storage is gated by
// settings.allow_config_plaintext_password — when that flag is false the tool
// refuses to persist a plaintext credential and tells the caller how to enable
// it.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
)

func init() {
	Registered = append(Registered, toolSSHPersistentSetup())
}

// --------------------------------------------------------------------------
// Input / output types
// --------------------------------------------------------------------------

type persistentSetupInput struct {
	Name          string   `json:"name"`
	Host          string   `json:"host"`
	Port          int      `json:"port,omitempty"`
	User          string   `json:"user"`
	Auth          string   `json:"auth"`
	KeyPath       string   `json:"key_path,omitempty"`
	KeyPassphrase string   `json:"key_passphrase,omitempty"`
	Password      string   `json:"password,omitempty"`
	AcceptNewHost bool     `json:"accept_new_host,omitempty"`
	Description   string   `json:"description,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	DefaultDir    string   `json:"default_dir,omitempty"`
	ProxyJump     string   `json:"proxy_jump,omitempty"`
}

type persistentSetupOutput struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	User       string `json:"user"`
	Auth       string `json:"auth"`
	ConfigPath string `json:"config_path"`
	// Persisted is true when the entry was written to config.toml; false would
	// indicate a session-only registration (currently always true on success).
	Persisted bool `json:"persisted"`
	// SessionLive indicates the entry is also active in the current MCP session
	// without requiring a restart.
	SessionLive bool `json:"session_live"`
}

// --------------------------------------------------------------------------
// Schema
// --------------------------------------------------------------------------

var persistentSetupSchema = json.RawMessage(`{
  "type": "object",
  "required": ["name", "host", "user", "auth"],
  "properties": {
    "name":            { "type": "string", "description": "Server entry name. Pattern: ^[a-z0-9][a-z0-9_-]{0,63}$" },
    "host":            { "type": "string", "description": "Hostname or IP address" },
    "port":            { "type": "integer", "minimum": 1, "maximum": 65535, "default": 22 },
    "user":            { "type": "string", "description": "SSH username" },
    "auth":            { "type": "string", "enum": ["agent", "key", "password"], "description": "Authentication mode" },
    "key_path":        { "type": "string", "description": "Path to private key file (auth=key)" },
    "key_passphrase":  { "type": "string", "description": "Plaintext passphrase for encrypted key (auth=key, optional). Stored as plaintext in config — gated by settings.allow_config_plaintext_password." },
    "password":        { "type": "string", "description": "Plaintext password (auth=password). Stored as plaintext in config — gated by settings.allow_config_plaintext_password." },
    "accept_new_host": { "type": "boolean", "default": false, "description": "Auto-append unknown host key to known_hosts on first dial in this session" },
    "description":     { "type": "string" },
    "tags":            { "type": "array", "items": { "type": "string" } },
    "default_dir":     { "type": "string", "description": "Default working directory" },
    "proxy_jump":      { "type": "string", "description": "Name of a previously-defined server to use as ProxyJump" }
  }
}`)

// --------------------------------------------------------------------------
// Tool descriptor
// --------------------------------------------------------------------------

func toolSSHPersistentSetup() Tool {
	return Tool{
		Name:        "ssh_persistent_setup",
		Description: "Permanently register an SSH server by appending [servers.<name>] to the user's config.toml. Unlike ssh_quick_setup, the entry survives restarts and has no TTL. Plaintext password storage requires settings.allow_config_plaintext_password=true.",
		InputSchema: persistentSetupSchema,
		Handle:      handleSSHPersistentSetup,
	}
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

// persistentNameRe mirrors the SDD server-name rule (also used by cli_config.go).
var persistentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// persistentTagRe mirrors the validate() rule for tags.
var persistentTagRe = regexp.MustCompile(`^[a-z0-9_-]+$`)

func handleSSHPersistentSetup(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input persistentSetupInput
	if err := json.Unmarshal(args, &input); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
	}

	// Required fields.
	if input.Name == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'name' is required", false)
	}
	if !persistentNameRe.MatchString(input.Name) {
		return envelope.Err(envelope.CodeInvalidArgument,
			"'name' must match ^[a-z0-9][a-z0-9_-]{0,63}$", false)
	}
	if input.Host == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'host' is required", false)
	}
	if input.User == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'user' is required", false)
	}

	// Defaults + ranges.
	port := input.Port
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return envelope.Err(envelope.CodeInvalidArgument,
			fmt.Sprintf("port out of range [1,65535]: %d", port), false)
	}

	// Auth-mode validation.
	switch input.Auth {
	case "agent":
		if input.KeyPath != "" || input.KeyPassphrase != "" || input.Password != "" {
			return envelope.Err(envelope.CodeInvalidArgument,
				"auth=agent must not set key_path, key_passphrase, or password", false)
		}
	case "key":
		if input.KeyPath == "" {
			return envelope.Err(envelope.CodeInvalidArgument,
				"auth=key requires key_path", false)
		}
		if input.Password != "" {
			return envelope.Err(envelope.CodeInvalidArgument,
				"auth=key must not set password", false)
		}
	case "password":
		if input.Password == "" {
			return envelope.Err(envelope.CodeInvalidArgument,
				"auth=password requires password", false)
		}
		if input.KeyPath != "" || input.KeyPassphrase != "" {
			return envelope.Err(envelope.CodeInvalidArgument,
				"auth=password must not set key_path or key_passphrase", false)
		}
	default:
		return envelope.Err(envelope.CodeInvalidArgument,
			"auth must be one of: agent, key, password", false)
	}

	// Tag validation (mirror validate() so we fail fast before touching disk).
	for _, t := range input.Tags {
		if !persistentTagRe.MatchString(t) {
			return envelope.Err(envelope.CodeInvalidArgument,
				fmt.Sprintf("tag %q must match ^[a-z0-9_-]+$", t), false)
		}
	}

	// Plaintext password gate. This is the only place where plaintext
	// secrets land on disk via this tool, so the check is fail-closed: if
	// the operator has not explicitly opted in, refuse and tell the caller
	// exactly how to enable it.
	if (input.Auth == "password" && input.Password != "") ||
		(input.Auth == "key" && input.KeyPassphrase != "") {
		if !deps.Cfg.Settings.AllowConfigPlaintextPassword {
			return envelope.ErrWithHint(
				envelope.CodeInvalidArgument,
				"plaintext password/passphrase persistence is disabled",
				"Set 'allow_config_plaintext_password = true' under [settings] in your config.toml, or use 'ssh-mcp config add-server --auth password --password-keychain' to store the password in your OS keychain instead.",
				false,
			)
		}
	}

	// Resolve config path.
	cfgPath := ""
	if deps.Cfg != nil {
		cfgPath = deps.Cfg.Path
	}
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}

	// Refuse if the entry already exists in the on-disk file. We deliberately
	// do not support overwrite — replacing a TOML block reliably without a
	// full round-trip risks losing user comments / formatting. Operators who
	// want to update an entry can edit config.toml directly.
	original, readErr := os.ReadFile(cfgPath)
	switch {
	case readErr == nil:
		marker := "[servers." + input.Name + "]"
		if strings.Contains(string(original), marker) {
			return envelope.ErrWithHint(
				envelope.CodeInvalidArgument,
				fmt.Sprintf("server %q already exists in %s", input.Name, cfgPath),
				"Edit config.toml manually to update an existing entry, or pick a different name.",
				false,
			)
		}
	case os.IsNotExist(readErr):
		dir := filepath.Dir(cfgPath)
		if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
			return envelope.Err(envelope.CodeInternalError,
				fmt.Sprintf("cannot create directory %s: %v", dir, mkErr), false)
		}
		original = nil
	default:
		return envelope.Err(envelope.CodeInternalError,
			fmt.Sprintf("read %s: %v", cfgPath, readErr), false)
	}

	// Refuse to shadow an in-memory static server name (already validated
	// against the on-disk file above; this catches the rare case where Cfg
	// holds a name that isn't in the file we just read, e.g. test setups).
	if deps.Cfg != nil && deps.Cfg.Servers != nil {
		if _, exists := deps.Cfg.Servers[input.Name]; exists && len(original) > 0 {
			marker := "[servers." + input.Name + "]"
			if !strings.Contains(string(original), marker) {
				return envelope.Err(envelope.CodeInvalidArgument,
					fmt.Sprintf("server %q already registered in current session", input.Name),
					false)
			}
		}
	}

	// Build the new [servers.<name>] block.
	block := buildPersistentBlock(input, port)

	var sb strings.Builder
	sb.Write(original)
	if len(original) > 0 && !strings.HasSuffix(string(original), "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString(block)

	// Atomic write to a temp file, validate, then rename. This way a
	// validation failure (e.g. proxy_jump cycle, unknown referenced server)
	// leaves the original file untouched.
	tmp := cfgPath + ".persistent-setup.tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return envelope.Err(envelope.CodeInternalError,
			fmt.Sprintf("write temp file %s: %v", tmp, err), false)
	}

	loaded, loadErr := config.Load(tmp)
	if loadErr != nil {
		_ = os.Remove(tmp)
		return envelope.ErrWithHint(
			envelope.CodeInvalidArgument,
			fmt.Sprintf("config validation failed (file NOT modified): %v", loadErr),
			"Fix the inputs and retry; the existing config.toml has not been changed.",
			false,
		)
	}
	if err := os.Rename(tmp, cfgPath); err != nil {
		_ = os.Remove(tmp)
		return envelope.Err(envelope.CodeInternalError,
			fmt.Sprintf("rename %s → %s: %v", tmp, cfgPath, err), false)
	}

	// Make the entry live in the current session without a restart by
	// registering it through the SSH pool's temp-server map (zero expiry =
	// no TTL eviction). The credResolver path for auth=agent/key/password
	// already handles these auth modes when resolving credentials, so we
	// reuse it without modification.
	sessionLive := false
	if deps.Pool != nil {
		if newSrv, ok := loaded.Servers[input.Name]; ok {
			newSrv.AcceptNewHost = input.AcceptNewHost
			deps.Pool.AddTempServer(input.Name, newSrv, time.Time{})
			sessionLive = true
		}
	}

	return envelope.OK(persistentSetupOutput{
		Name:        input.Name,
		Host:        input.Host,
		User:        input.User,
		Auth:        input.Auth,
		ConfigPath:  cfgPath,
		Persisted:   true,
		SessionLive: sessionLive,
	})
}

// buildPersistentBlock renders a [servers.<name>] TOML block from the
// validated input. All string values are emitted with %q so quotes,
// backslashes, and other shell-metacharacters are escaped correctly.
func buildPersistentBlock(in persistentSetupInput, port int) string {
	var b strings.Builder
	b.WriteString("\n[servers.")
	b.WriteString(in.Name)
	b.WriteString("]\n")
	fmt.Fprintf(&b, "host = %q\n", in.Host)
	fmt.Fprintf(&b, "port = %d\n", port)
	fmt.Fprintf(&b, "user = %q\n", in.User)
	fmt.Fprintf(&b, "auth = %q\n", in.Auth)
	if in.KeyPath != "" {
		fmt.Fprintf(&b, "key_path = %q\n", in.KeyPath)
	}
	if in.KeyPassphrase != "" {
		fmt.Fprintf(&b, "key_passphrase = %q\n", in.KeyPassphrase)
	}
	if in.Password != "" {
		fmt.Fprintf(&b, "password = %q\n", in.Password)
	}
	if in.Description != "" {
		fmt.Fprintf(&b, "description = %q\n", in.Description)
	}
	if in.DefaultDir != "" {
		fmt.Fprintf(&b, "default_dir = %q\n", in.DefaultDir)
	}
	if in.ProxyJump != "" {
		fmt.Fprintf(&b, "proxy_jump = %q\n", in.ProxyJump)
	}
	if len(in.Tags) > 0 {
		quoted := make([]string, 0, len(in.Tags))
		for _, t := range in.Tags {
			quoted = append(quoted, fmt.Sprintf("%q", t))
		}
		fmt.Fprintf(&b, "tags = [%s]\n", strings.Join(quoted, ", "))
	}
	return b.String()
}
