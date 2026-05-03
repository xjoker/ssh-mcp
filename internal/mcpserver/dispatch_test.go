package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
)

// SDD §5.1: every tool returns the unified envelope shape. The dispatcher
// MUST emit the full {ok, data?, error?} object as a single TextContent
// payload — not just the data on success.
func TestEnvelopeWrapsOnSuccess(t *testing.T) {
	resp := envelope.OK(map[string]any{"hello": "world", "n": 42})
	got := envelopeToCallToolResult(resp)

	if got.IsError {
		t.Fatalf("IsError=true on OK envelope")
	}
	tc, ok := got.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent")
	}
	var env struct {
		OK    bool           `json:"ok"`
		Data  map[string]any `json:"data"`
		Error any            `json:"error"`
	}
	if err := json.Unmarshal([]byte(tc.Text), &env); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, tc.Text)
	}
	if !env.OK {
		t.Errorf("ok field should be true; raw=%s", tc.Text)
	}
	if env.Error != nil {
		t.Errorf("error should be omitted on success; raw=%s", tc.Text)
	}
	if env.Data["hello"] != "world" {
		t.Errorf("data not wrapped; got %v", env.Data)
	}
}

func TestEnvelopeWrapsOnError(t *testing.T) {
	resp := envelope.Err(envelope.CodeAuthFailed, "bad creds", false)
	got := envelopeToCallToolResult(resp)

	if !got.IsError {
		t.Fatalf("IsError=false on error envelope")
	}
	tc := got.Content[0].(*mcp.TextContent)
	if !strings.Contains(tc.Text, `"ok":false`) {
		t.Errorf("missing ok:false: %s", tc.Text)
	}
	if !strings.Contains(tc.Text, `"code":"AUTH_FAILED"`) {
		t.Errorf("missing error code: %s", tc.Text)
	}
}
