// Package tools — list_servers tool (SDD §6.11).
package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
)

func init() {
	Registered = append(Registered, toolListServers())
}

// --------------------------------------------------------------------------
// Input / output types
// --------------------------------------------------------------------------

type listServersInput struct {
	Tag string `json:"tag,omitempty"`
	// Refresh, when true (default), re-reads config.toml from disk so the
	// returned list reflects manual edits made since process start. Set to
	// false to skip the disk reload and report the in-memory snapshot only.
	Refresh *bool `json:"refresh,omitempty"`
}

// serverInfo is the safe, credential-free server record sent to callers.
type serverInfo struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	User        string   `json:"user"`
	Auth        string   `json:"auth"`
	DefaultDir  string   `json:"default_dir,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	ProxyJump   string   `json:"proxy_jump,omitempty"`
	Source      string   `json:"source,omitempty"`
	Ephemeral   bool     `json:"ephemeral,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

type listServersOutput struct {
	Servers []serverInfo `json:"servers"`
}

// --------------------------------------------------------------------------
// Schema
// --------------------------------------------------------------------------

var listServersSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "tag": {
      "type": "string",
      "description": "Filter by tag. If omitted all servers are returned."
    },
    "refresh": {
      "type": "boolean",
      "description": "When true (default) reload config.toml from disk so manual edits since process start are picked up; newly-discovered servers are also injected into the in-memory pool so subsequent ssh_exec / session_start calls can use them without a restart. Set to false to skip the reload."
    }
  }
}`)

// --------------------------------------------------------------------------
// Tool descriptor
// --------------------------------------------------------------------------

func toolListServers() Tool {
	return Tool{
		Name:        "list_servers",
		Description: "Return all configured SSH servers (without secrets). Optionally filter by tag. By default re-reads config.toml from disk so manual edits since process start are visible without restarting the MCP server.",
		InputSchema: listServersSchema,
		Handle:      handleListServers,
		Annotations: &Annotations{
			Title:           "List configured servers",
			ReadOnlyHint:    true,
			DestructiveHint: false,
			IdempotentHint:  false,
			OpenWorldHint:   false,
		},
	}
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

func handleListServers(_ context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input listServersInput
	if len(args) > 0 {
		if err := json.Unmarshal(args, &input); err != nil {
			return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
		}
	}

	// Default refresh=true so the AI sees the truth on disk after manual
	// config edits. Skipping the reload is opt-in (refresh:false) for the
	// rare case the caller wants the original in-memory snapshot.
	refresh := true
	if input.Refresh != nil {
		refresh = *input.Refresh
	}

	// Effective server map: starts as deps.Cfg.Servers, optionally rebuilt
	// from disk. We never mutate deps.Cfg.Servers in place — the freshly
	// loaded entries are also injected into the SSH pool's temp-server map
	// (zero expiry) so subsequent ssh_exec / session_start can resolve them
	// without an MCP restart. Pool temp-server entries shadow static ones,
	// so edits and additions both flow through.
	effective := deps.Cfg.Servers
	if refresh && deps.Cfg != nil && deps.Cfg.Path != "" {
		if reloaded, err := config.Load(deps.Cfg.Path); err == nil && reloaded != nil {
			effective = reloaded.Servers
			if deps.Pool != nil {
				// Hot-reload [proxies.*] too: newly added proxy tables become
				// resolvable by proxy_chain dials without an MCP restart.
				deps.Pool.ReloadProxies(reloaded.Proxies)
				// Inject every fresh on-disk entry as a zero-expiry
				// temp-server. Pool's temp-server map shadows cfg.Servers,
				// so this makes additions and edits immediately resolvable.
				for name, srv := range reloaded.Servers {
					deps.Pool.AddTempServer(name, srv, time.Time{})
				}
				// Reap previously-injected refresh shadows that the on-disk
				// file no longer defines (entries deleted or renamed via
				// manual edit). Without this, deleted servers would remain
				// callable in the running MCP process — confusing and a
				// stale-credential foot-gun. We only remove ZERO-EXPIRY
				// temp entries (those carry the "from config refresh"
				// semantics); ssh_quick_setup entries have a non-zero
				// ExpiresAt and are left alone.
				for _, tmp := range deps.Pool.ListTempServers() {
					if !tmp.ExpiresAt.IsZero() {
						continue // genuine ad-hoc quick_setup entry
					}
					if _, stillThere := reloaded.Servers[tmp.Server.Name]; stillThere {
						continue
					}
					deps.Pool.RemoveTempServer(tmp.Server.Name)
				}
			}
		}
		// If reload fails (file gone, invalid syntax) we silently fall back
		// to the in-memory snapshot. list_servers must remain readable even
		// when the user has corrupted their config — they need this signal
		// to debug.
	}

	// Track which names came from on-disk config so we don't double-list
	// them when iterating the pool's temp-server map below (after a refresh
	// they're injected there too, by design — but for display they should
	// appear once with Source="config").
	configNames := make(map[string]struct{}, len(effective))
	for name := range effective {
		configNames[name] = struct{}{}
	}

	servers := make([]serverInfo, 0, len(effective))
	for _, srv := range effective {
		// Tag filter: if requested, skip servers whose Tags slice doesn't contain it.
		if input.Tag != "" {
			found := false
			for _, t := range srv.Tags {
				if t == input.Tag {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		port := srv.Port
		if port == 0 {
			port = 22
		}

		servers = append(servers, serverInfo{
			Name:        srv.Name,
			Host:        srv.Host,
			Port:        port,
			User:        srv.User,
			Auth:        srv.Auth,
			DefaultDir:  srv.DefaultDir,
			Description: srv.Description,
			Tags:        srv.Tags,
			ProxyJump:   srv.ProxyJump,
			Source:      "config",
		})
	}

	if input.Tag == "" && deps.Pool != nil {
		for _, tmp := range deps.Pool.ListTempServers() {
			srv := tmp.Server
			// Skip entries that mirror an on-disk config server (avoid
			// duplicate rows when refresh injected them as temp shadows).
			if _, fromConfig := configNames[srv.Name]; fromConfig && tmp.ExpiresAt.IsZero() {
				continue
			}
			port := srv.Port
			if port == 0 {
				port = 22
			}

			source := "quick_setup"
			if len(srv.Name) >= len("qs-inline-session") && srv.Name[:len("qs-inline-session")] == "qs-inline-session" {
				source = "inline"
			}
			expiresAt := ""
			if !tmp.ExpiresAt.IsZero() {
				expiresAt = tmp.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00")
			}

			servers = append(servers, serverInfo{
				Name:      srv.Name,
				Host:      srv.Host,
				Port:      port,
				User:      srv.User,
				Auth:      srv.Auth,
				Source:    source,
				Ephemeral: true,
				ExpiresAt: expiresAt,
			})
		}
	}

	// Stable output order: sort by name so callers get deterministic results.
	sortServerInfos(servers)

	return envelope.OK(listServersOutput{Servers: servers})
}

// sortServerInfos sorts server infos in-place by name.
func sortServerInfos(s []serverInfo) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Name < s[j-1].Name; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
