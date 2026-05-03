//go:build integration

// Package integration runs against the docker-compose stack in
// test/integration/docker-compose.yml. Bring it up first:
//
//	docker compose -f test/integration/docker-compose.yml up -d
//
// Then run:
//
//	go test -tags=integration ./test/integration/... -count=1 -v
package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func startBridge(t *testing.T, ctx context.Context) (*mcp.ClientSession, func()) {
	t.Helper()
	root := repoRoot(t)
	bin := filepath.Join(root, "bin", "mcp-ssh-bridge")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("binary not built at %s: %v", bin, err)
	}
	cfg := filepath.Join(root, "test", "integration", "config.toml")

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "MCP_SSH_BRIDGE_CONFIG="+cfg)
	tr := &mcp.CommandTransport{Command: cmd}

	client := mcp.NewClient(&mcp.Implementation{Name: "smoke", Version: "0.0"}, nil)
	sess, err := client.Connect(ctx, tr, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cleanup := func() { _ = sess.Close() }
	return sess, cleanup
}

// decodeData returns the data payload from a successful CallToolResult.
// On failure, decodes the envelope and t.Fatalf's with its contents.
//
// The mcpserver dispatcher emits raw data on success (no envelope wrapper),
// and the full {ok:false, error:{...}} envelope on failure, with IsError set.
func decodeData(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("empty content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected text content, got %T", res.Content[0])
	}
	if res.IsError {
		t.Fatalf("tool returned error: %s", tc.Text)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &data); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, tc.Text)
	}
	return data
}

func TestSSHExec_Password(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, cleanup := startBridge(t, ctx)
	defer cleanup()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "ssh_exec",
		Arguments: map[string]any{
			"server":  "test-pwd",
			"command": "echo HELLO_FROM_PWD && id -un",
		},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	data := decodeData(t, res)
	stdout, _ := data["stdout"].(string)
	if !strings.Contains(stdout, "HELLO_FROM_PWD") {
		t.Errorf("stdout missing marker: %q", stdout)
	}
	if !strings.Contains(stdout, "tester") {
		t.Errorf("stdout missing username: %q", stdout)
	}
}

func TestSSHExec_Key_WithCwd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, cleanup := startBridge(t, ctx)
	defer cleanup()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "ssh_exec",
		Arguments: map[string]any{
			"server":  "test-key",
			"command": "pwd",
			"cwd":     "/tmp",
		},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	data := decodeData(t, res)
	stdout, _ := data["stdout"].(string)
	if strings.TrimSpace(stdout) != "/tmp" {
		t.Errorf("expected /tmp, got %q", stdout)
	}
}

func TestSFTPList_Root(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, cleanup := startBridge(t, ctx)
	defer cleanup()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "sftp_list",
		Arguments: map[string]any{
			"server": "test-key",
			"path":   "/",
		},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	data := decodeData(t, res)
	entries, _ := data["entries"].([]any)
	if len(entries) < 5 {
		t.Errorf("expected at least 5 root entries, got %d", len(entries))
	}
}

func TestSession_RoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sess, cleanup := startBridge(t, ctx)
	defer cleanup()

	// start
	startRes, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "session_start",
		Arguments: map[string]any{"server": "test-pwd"},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	data := decodeData(t, startRes)
	sid, _ := data["session_id"].(string)
	if sid == "" {
		t.Fatalf("no session_id in %#v", data)
	}

	// send: validate exit code propagation and stdout content
	sendRes, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "session_send",
		Arguments: map[string]any{
			"session_id": sid,
			"command":    "echo SESSION_MARKER && false",
			"timeout_ms": 15000,
		},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	sd := decodeData(t, sendRes)
	stdout, _ := sd["stdout"].(string)
	if !strings.Contains(stdout, "SESSION_MARKER") {
		t.Errorf("stdout missing marker: %q", stdout)
	}
	exit, _ := sd["exit_code"].(float64)
	if int(exit) != 1 {
		t.Errorf("expected exit 1 from `false`, got %v", exit)
	}

	// close (idempotent)
	closeRes, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "session_close",
		Arguments: map[string]any{"session_id": sid},
	})
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	decodeData(t, closeRes)
}

func TestGroupExec(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, cleanup := startBridge(t, ctx)
	defer cleanup()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "ssh_group_exec",
		Arguments: map[string]any{
			"servers": []string{"test-pwd", "test-key"},
			"command": "uname -s",
		},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	data := decodeData(t, res)
	results, _ := data["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d (data=%#v)", len(results), data)
	}
	for _, r := range results {
		m := r.(map[string]any)
		if ok, _ := m["ok"].(bool); !ok {
			t.Errorf("subresult not ok: %#v", m)
		}
	}
}

func TestAuditQuery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, cleanup := startBridge(t, ctx)
	defer cleanup()

	// First, run an exec to ensure there's at least one audit entry.
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "ssh_exec",
		Arguments: map[string]any{"server": "test-pwd", "command": "true"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "audit_query",
		Arguments: map[string]any{"limit": 10},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	data := decodeData(t, res)
	entries, _ := data["entries"].([]any)
	if len(entries) == 0 {
		t.Errorf("expected at least one audit entry, got 0")
	}
}

func TestListServers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, cleanup := startBridge(t, ctx)
	defer cleanup()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_servers",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	data := decodeData(t, res)
	servers, _ := data["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	// ensure no password leakage
	raw, _ := json.Marshal(servers)
	if strings.Contains(string(raw), "test-password-marker") {
		t.Errorf("password leaked into list_servers output: %s", raw)
	}
}
