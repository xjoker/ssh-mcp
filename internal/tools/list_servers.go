// Package tools — list_servers tool (SDD §6.11).
package tools

import (
	"context"
	"encoding/json"

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
    }
  }
}`)

// --------------------------------------------------------------------------
// Tool descriptor
// --------------------------------------------------------------------------

func toolListServers() Tool {
	return Tool{
		Name:        "list_servers",
		Description: "Return all configured SSH servers (without secrets). Optionally filter by tag.",
		InputSchema: listServersSchema,
		Handle:      handleListServers,
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

	servers := make([]serverInfo, 0, len(deps.Cfg.Servers))
	for _, srv := range deps.Cfg.Servers {
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
