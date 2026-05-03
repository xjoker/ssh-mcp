package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
)

func TestHandleListServers_Basic(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]config.ServerConfig{
			"prod-web": {
				Name:        "prod-web",
				Host:        "prod-web.example.com",
				Port:        22,
				User:        "deploy",
				Auth:        "agent",
				DefaultDir:  "/var/www",
				Description: "Production web server",
				Tags:        []string{"prod", "web"},
				ProxyJump:   "bastion",
				// Secrets that must NOT appear in output:
				Password: config.CredRef{Kind: config.CredRefPlaintext, Value: "supersecret"},
			},
		},
	}

	deps := &Deps{Cfg: cfg}
	resp := handleListServers(context.Background(), deps, json.RawMessage(`{}`))

	if !resp.OK {
		t.Fatalf("expected OK response, got error: %+v", resp.Error)
	}

	data, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out listServersOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(out.Servers))
	}

	s := out.Servers[0]
	if s.Name != "prod-web" {
		t.Errorf("name: want prod-web, got %s", s.Name)
	}
	if s.Host != "prod-web.example.com" {
		t.Errorf("host: want prod-web.example.com, got %s", s.Host)
	}
	if s.Port != 22 {
		t.Errorf("port: want 22, got %d", s.Port)
	}
	if s.User != "deploy" {
		t.Errorf("user: want deploy, got %s", s.User)
	}
	if s.Auth != "agent" {
		t.Errorf("auth: want agent, got %s", s.Auth)
	}
	if s.DefaultDir != "/var/www" {
		t.Errorf("default_dir: want /var/www, got %s", s.DefaultDir)
	}
	if s.Description != "Production web server" {
		t.Errorf("description mismatch")
	}
	if s.ProxyJump != "bastion" {
		t.Errorf("proxy_jump: want bastion, got %s", s.ProxyJump)
	}

	// Ensure password is NOT leaked in the JSON output.
	raw, _ := json.Marshal(s)
	if contains(string(raw), "supersecret") {
		t.Errorf("password 'supersecret' should not appear in list_servers output")
	}
}

func TestHandleListServers_NoPasswordInOutput(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]config.ServerConfig{
			"s1": {
				Name:     "s1",
				Host:     "host1",
				User:     "user1",
				Auth:     "password",
				Password: config.CredRef{Kind: config.CredRefPlaintext, Value: "TOPSECRET"},
			},
		},
	}
	deps := &Deps{Cfg: cfg}
	resp := handleListServers(context.Background(), deps, json.RawMessage(`{}`))
	raw, _ := json.Marshal(resp)
	if contains(string(raw), "TOPSECRET") {
		t.Errorf("password must not appear in list_servers output")
	}
}

func TestHandleListServers_TagFilter(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]config.ServerConfig{
			"web": {Name: "web", Host: "h1", User: "u", Auth: "agent", Tags: []string{"prod", "web"}},
			"db":  {Name: "db", Host: "h2", User: "u", Auth: "agent", Tags: []string{"prod", "db"}},
			"dev": {Name: "dev", Host: "h3", User: "u", Auth: "agent", Tags: []string{"dev"}},
		},
	}
	deps := &Deps{Cfg: cfg}

	resp := handleListServers(context.Background(), deps, json.RawMessage(`{"tag":"prod"}`))
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}

	data, _ := json.Marshal(resp.Data)
	var out listServersOutput
	json.Unmarshal(data, &out)

	if len(out.Servers) != 2 {
		t.Errorf("expected 2 prod servers, got %d", len(out.Servers))
	}
}

func TestHandleListServers_EmptyConfig(t *testing.T) {
	cfg := &config.Config{Servers: map[string]config.ServerConfig{}}
	deps := &Deps{Cfg: cfg}

	resp := handleListServers(context.Background(), deps, json.RawMessage(`{}`))
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp.Error)
	}
	data, _ := json.Marshal(resp.Data)
	var out listServersOutput
	json.Unmarshal(data, &out)

	if len(out.Servers) != 0 {
		t.Errorf("expected empty list, got %d servers", len(out.Servers))
	}
}

func TestHandleListServers_InvalidJSON(t *testing.T) {
	deps := &Deps{Cfg: &config.Config{Servers: map[string]config.ServerConfig{}}}
	resp := handleListServers(context.Background(), deps, json.RawMessage(`{bad json}`))
	if resp.OK {
		t.Error("expected error response for bad JSON")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Errorf("expected INVALID_ARGUMENT, got %+v", resp.Error)
	}
}

// contains is a simple string-contains helper for tests.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
