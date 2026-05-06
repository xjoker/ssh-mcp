// tunnel implements the tunnel MCP tool (SDD §6.10).
// Supports actions: create (local/remote), list, close.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/envelope"
)

func init() {
	Registered = append(Registered, Tool{
		Name:        "tunnel",
		Description: "Manage SSH port-forwarding tunnels. Actions: create (local or remote), list, close.",
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "action":       { "type": "string", "enum": ["create", "list", "close"] },
    "kind":         { "type": "string", "enum": ["local", "remote"], "description": "(create only)" },
    "server":       { "type": "string", "description": "(create only) Configured server name" },
    "local_bind":   { "type": "string", "default": "127.0.0.1", "description": "(create local) Local listener bind address. Defaults to loopback." },
    "local_port":   { "type": "integer", "description": "(create) Local port" },
    "remote_bind":  { "type": "string", "default": "127.0.0.1", "description": "(create remote) Remote bind address" },
    "remote_port":  { "type": "integer", "description": "(create remote) Remote port" },
    "dst_host":     { "type": "string", "description": "(create local) Destination host on the remote side" },
    "dst_port":     { "type": "integer", "description": "(create local) Destination port on the remote side" },
    "tunnel_id":    { "type": "string", "description": "(close only) Tunnel ID to close" }
  },
  "required": ["action"]
}`),
		Handle: handleTunnel,
	})
}

type tunnelArgs struct {
	Action     string `json:"action"`
	Kind       string `json:"kind"`
	Server     string `json:"server"`
	LocalBind  string `json:"local_bind"`
	LocalPort  int    `json:"local_port"`
	RemoteBind string `json:"remote_bind"`
	RemotePort int    `json:"remote_port"`
	DstHost    string `json:"dst_host"`
	DstPort    int    `json:"dst_port"`
	TunnelID   string `json:"tunnel_id"`
}

func handleTunnel(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var a tunnelArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "cannot parse args: "+err.Error(), false)
	}

	if a.Action == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "action is required", false)
	}

	switch a.Action {
	case "create":
		return tunnelCreate(ctx, a, deps)
	case "list":
		return tunnelList(deps)
	case "close":
		return tunnelClose(a, deps)
	default:
		return envelope.Err(envelope.CodeInvalidArgument,
			fmt.Sprintf("unknown action %q; must be one of create, list, close", a.Action),
			false)
	}
}

// --------------------------------------------------------------------------
// action: create
// --------------------------------------------------------------------------

func tunnelCreate(ctx context.Context, a tunnelArgs, deps *Deps) envelope.Response {
	if a.Kind == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "kind is required for create (local or remote)", false)
	}
	if a.Server == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "server is required for create", false)
	}
	serverName := strings.TrimSpace(a.Server)
	if serverName == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "server name is empty", false)
	}
	// Honour an already-cancelled context before any other validation so
	// callers that pre-cancel get a deterministic TIMEOUT rather than a
	// "not found" path.
	if err := ctx.Err(); err != nil {
		return envelope.Err(envelope.CodeTimeout, "tunnel create canceled: "+err.Error(), true)
	}
	if _, ok := lookupServer(deps, serverName); !ok {
		return envelope.Err(envelope.CodeInvalidArgument,
			fmt.Sprintf("server %q not found in configuration", serverName), false)
	}

	// Pre-flight: dial the SSH connection now so authentication / host-key
	// failures surface synchronously instead of being deferred until the
	// first inbound connection on the listener (which would silently drop).
	// Pool.Get is idempotent and returns the cached client on subsequent
	// calls, so this is cheap on the steady-state path.
	if deps.Pool != nil {
		if _, err := deps.Pool.Get(ctx, serverName); err != nil {
			return mapSSHConnErr(err)
		}
	}

	switch a.Kind {
	case "local":
		return tunnelCreateLocal(ctx, a, serverName, deps)
	case "remote":
		return tunnelCreateRemote(ctx, a, serverName, deps)
	default:
		return envelope.Err(envelope.CodeInvalidArgument,
			fmt.Sprintf("kind must be local or remote, got %q", a.Kind), false)
	}
}

func tunnelCreateLocal(ctx context.Context, a tunnelArgs, server string, deps *Deps) envelope.Response {
	if a.DstHost == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "dst_host is required for local tunnel", false)
	}
	if a.DstPort <= 0 {
		return envelope.Err(envelope.CodeInvalidArgument, "dst_port is required for local tunnel", false)
	}
	if a.LocalPort <= 0 {
		return envelope.Err(envelope.CodeInvalidArgument, "local_port is required for local tunnel", false)
	}

	// local_bind: pass empty string — internal/tunnel defaults to 127.0.0.1 (S-9).
	// Do NOT default to "0.0.0.0" here.
	localBind := a.LocalBind // empty → tunnel.Manager will use 127.0.0.1

	id, err := deps.TunnelMgr.CreateLocalContext(ctx, server, localBind, a.LocalPort, a.DstHost, a.DstPort)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return envelope.Err(envelope.CodeTimeout, "create local tunnel canceled: "+ctxErr.Error(), true)
		}
		return envelope.Err(envelope.CodeConnFailed, "create local tunnel: "+err.Error(), false)
	}
	if err := ctx.Err(); err != nil {
		_ = deps.TunnelMgr.Close(id)
		return envelope.Err(envelope.CodeTimeout, "create local tunnel canceled: "+err.Error(), true)
	}

	endpoint := fmt.Sprintf("%s:%d", resolvedBind(localBind, "127.0.0.1"), a.LocalPort)
	return envelope.OK(map[string]any{
		"tunnel_id": id,
		"kind":      "local",
		"endpoint":  endpoint,
	})
}

func tunnelCreateRemote(ctx context.Context, a tunnelArgs, server string, deps *Deps) envelope.Response {
	if a.RemotePort <= 0 {
		return envelope.Err(envelope.CodeInvalidArgument, "remote_port is required for remote tunnel", false)
	}
	if a.LocalPort <= 0 {
		return envelope.Err(envelope.CodeInvalidArgument, "local_port is required for remote tunnel", false)
	}
	localHost := a.DstHost
	if localHost == "" {
		localHost = "127.0.0.1"
	}

	// S-9: default remote_bind to 127.0.0.1 explicitly (never wildcard).
	// internal/tunnel also enforces this, but we apply it here too for
	// defence-in-depth and symmetric behaviour with the local branch.
	remoteBind := a.RemoteBind
	if remoteBind == "" {
		remoteBind = "127.0.0.1"
	}

	id, err := deps.TunnelMgr.CreateRemoteContext(ctx, server, remoteBind, a.RemotePort, localHost, a.LocalPort)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return envelope.Err(envelope.CodeTimeout, "create remote tunnel canceled: "+ctxErr.Error(), true)
		}
		return envelope.Err(envelope.CodeConnFailed, "create remote tunnel: "+err.Error(), false)
	}
	if err := ctx.Err(); err != nil {
		_ = deps.TunnelMgr.Close(id)
		return envelope.Err(envelope.CodeTimeout, "create remote tunnel canceled: "+err.Error(), true)
	}

	endpoint := fmt.Sprintf("%s:%d", resolvedBind(remoteBind, "127.0.0.1"), a.RemotePort)
	return envelope.OK(map[string]any{
		"tunnel_id": id,
		"kind":      "remote",
		"endpoint":  endpoint,
	})
}

// --------------------------------------------------------------------------
// action: list
// --------------------------------------------------------------------------

func tunnelList(deps *Deps) envelope.Response {
	infos := deps.TunnelMgr.List()
	return envelope.OK(map[string]any{
		"tunnels": infos,
	})
}

// --------------------------------------------------------------------------
// action: close
// --------------------------------------------------------------------------

func tunnelClose(a tunnelArgs, deps *Deps) envelope.Response {
	if a.TunnelID == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "tunnel_id is required for close", false)
	}
	if err := deps.TunnelMgr.Close(a.TunnelID); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not found") {
			return envelope.Err(envelope.CodeNotFound,
				fmt.Sprintf("tunnel %q not found", a.TunnelID), false)
		}
		return envelope.Err(envelope.CodeInternalError, "close tunnel: "+msg, false)
	}
	return envelope.OK(map[string]any{"closed": true})
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// resolvedBind returns bind if non-empty, else the fallback.
// Used purely for constructing the human-readable endpoint string.
func resolvedBind(bind, fallback string) string {
	if bind == "" {
		return fallback
	}
	return bind
}
