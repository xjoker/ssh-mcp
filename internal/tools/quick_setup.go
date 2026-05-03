// Package tools — ssh_quick_setup tool (SDD §6.13).
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
)

func init() {
	Registered = append(Registered, toolSSHQuickSetup())
}

// --------------------------------------------------------------------------
// Input / output types
// --------------------------------------------------------------------------

type quickSetupInput struct {
	Host          string `json:"host"`
	Port          int    `json:"port,omitempty"`
	User          string `json:"user"`
	Password      string `json:"password,omitempty"`
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	Passphrase    string `json:"passphrase,omitempty"`
	AcceptNewHost bool   `json:"accept_new_host,omitempty"`
	NameHint      string `json:"name_hint,omitempty"`
	TTLMinutes    int    `json:"ttl_minutes,omitempty"`
}

type quickSetupOutput struct {
	RegisteredName string `json:"registered_name"`
	ExpiresAt      string `json:"expires_at"` // RFC3339 UTC
	Host           string `json:"host"`
	User           string `json:"user"`
}

// --------------------------------------------------------------------------
// Schema
// --------------------------------------------------------------------------

var quickSetupSchema = json.RawMessage(`{
  "type": "object",
  "required": ["host", "user"],
  "properties": {
    "host":            { "type": "string", "description": "Hostname or IP address of the SSH server" },
    "port":            { "type": "integer", "minimum": 1, "maximum": 65535, "default": 22 },
    "user":            { "type": "string", "description": "SSH username" },
    "password":        { "type": "string", "description": "Plaintext password (stored in-memory only; never persisted)" },
    "private_key_pem": { "type": "string", "description": "PEM-encoded private key" },
    "passphrase":      { "type": "string", "description": "Passphrase for encrypted private key" },
    "accept_new_host": { "type": "boolean", "default": false, "description": "Accept and record unknown host keys" },
    "name_hint":       { "type": "string", "description": "Suggested name for the temporary server (bridge may sanitize)" },
    "ttl_minutes":     { "type": "integer", "default": 30, "minimum": 1, "maximum": 240, "description": "TTL in minutes before the temporary entry expires" }
  }
}`)

// --------------------------------------------------------------------------
// Tool descriptor
// --------------------------------------------------------------------------

func toolSSHQuickSetup() Tool {
	return Tool{
		Name:        "ssh_quick_setup",
		Description: "Register an ad-hoc SSH server for the duration of this session. Prompts the user to confirm before registering.",
		InputSchema: quickSetupSchema,
		Handle:      handleSSHQuickSetup,
	}
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

func handleSSHQuickSetup(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	// 1. Validate AllowQuickSetup.
	if !deps.Cfg.Settings.AllowQuickSetup {
		return envelope.Err(envelope.CodeInlineCredsDisabled,
			"ssh_quick_setup is disabled by server configuration (allow_quick_setup = false)", false)
	}

	// 2. Parse input.
	var input quickSetupInput
	if err := json.Unmarshal(args, &input); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
	}
	if input.Host == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'host' is required", false)
	}
	if input.User == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "'user' is required", false)
	}
	if input.Password == "" && input.PrivateKeyPEM == "" {
		return envelope.Err(envelope.CodeInvalidArgument,
			"either 'password' or 'private_key_pem' is required", false)
	}

	// Apply defaults.
	port := input.Port
	if port == 0 {
		port = 22
	}
	// H02: enforce TTL range 1..240 regardless of JSON schema.
	// <=0 is treated as "use default"; >240 is explicitly rejected so that a
	// client that bypasses schema validation cannot keep a secret in memory
	// beyond the permitted maximum.
	ttl := input.TTLMinutes
	if ttl <= 0 {
		ttl = 30
	} else if ttl > 240 {
		return envelope.Err(envelope.CodeInvalidArgument,
			"ttl_minutes must be between 1 and 240", false)
	}

	// 3. Issue MCP elicitation to confirm with user.
	elicitResp, err := elicitConfirmation(ctx, deps, input.Host, input.User, ttl)
	if err != nil {
		// Elicitation itself failed (e.g., not supported or timed out).
		return envelope.Err(envelope.CodeUserDeclined,
			"elicitation failed or timed out: "+err.Error(), false)
	}
	if !elicitResp {
		return envelope.Err(envelope.CodeUserDeclined,
			"user declined to register temporary server", false)
	}

	// 4. Determine secret bytes + auth kind. password takes priority.
	spec := QuickSetupSpec{
		NameHint:      input.NameHint,
		Host:          input.Host,
		Port:          port,
		User:          input.User,
		AcceptNewHost: input.AcceptNewHost,
		TTLMinutes:    ttl,
	}
	if input.Password != "" {
		spec.AuthKind = "password"
		spec.Secret = []byte(input.Password)
	} else {
		spec.AuthKind = "key"
		spec.Secret = []byte(input.PrivateKeyPEM)
		if input.Passphrase != "" {
			spec.Passphrase = []byte(input.Passphrase)
		}
	}

	// 5. Register in QuickSetup registry (in-memory secret store).
	registeredName, expiresAt, err := deps.QuickSetup.Register(spec)
	if err != nil {
		return envelope.Err(envelope.CodeInternalError,
			"failed to register temporary server: "+err.Error(), false)
	}

	// 6. Plumb the temporary server into the SSH pool so subsequent tool
	//    calls (ssh_exec, sftp_*, …) can address it by registeredName.
	//    SDD §6.13: the registered name resolves through the same Pool.Get
	//    path as configured servers. The credResolver detects auth ==
	//    "quick_setup" and looks up the in-memory secret.
	if deps.Pool != nil {
		deps.Pool.AddTempServer(registeredName, config.ServerConfig{
			Name: registeredName,
			Host: input.Host,
			Port: port,
			User: input.User,
			Auth: "quick_setup",
		})
	}

	// Format expiry as RFC3339 UTC.
	expiresAtStr := time.Unix(expiresAt, 0).UTC().Format(time.RFC3339)

	return envelope.OK(quickSetupOutput{
		RegisteredName: registeredName,
		ExpiresAt:      expiresAtStr,
		Host:           input.Host,
		User:           input.User,
	})
}

// elicitConfirmation issues an MCP elicitation/create request asking the user
// to confirm registration of a temporary server. Returns true if confirmed,
// false if declined or timed out.
func elicitConfirmation(ctx context.Context, deps *Deps, host, user string, ttlMinutes int) (bool, error) {
	if deps.Elicit == nil {
		// No elicitation func wired — behave as if declined.
		return false, fmt.Errorf("elicitation not supported by this session")
	}

	// Build elicitation schema with a 60-second context deadline.
	elicitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	schema := json.RawMessage(fmt.Sprintf(`{
  "type": "object",
  "properties": {
    "confirm": {
      "type": "boolean",
      "description": "Register temp server '%s' as user '%s' for %d minutes?"
    }
  },
  "required": ["confirm"]
}`, host, user, ttlMinutes))

	msg := fmt.Sprintf("Allow mcp-ssh-bridge to register a temporary connection to %s@%s for %d minutes?",
		user, host, ttlMinutes)

	responseRaw, err := deps.Elicit(elicitCtx, schema, msg)
	if err != nil {
		return false, err
	}

	// Parse the response. Expect {"confirm": true/false}.
	var resp struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.Unmarshal(responseRaw, &resp); err != nil {
		return false, fmt.Errorf("invalid elicitation response: %w", err)
	}

	return resp.Confirm, nil
}
