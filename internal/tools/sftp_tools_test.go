// Tests for sftp_list, sftp_read, sftp_stat, sftp_op, tunnel tools.
// All tests exercise pre-validation (bad arguments, encoding mismatches, etc.)
// without making real SSH connections.
package tools

import (
	"context"
	"testing"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	"github.com/xjoker/mcp-ssh-bridge/internal/tunnel"
)

// --------------------------------------------------------------------------
// Helpers shared across tools test files
// --------------------------------------------------------------------------

// minDeps builds a minimal *Deps with config settings for testing.
// Pool and SessionMgr left nil — tests that need them set up separately.
func minDeps(allowInline bool) *Deps {
	return &Deps{
		Cfg: &config.Config{
			Settings: config.Settings{
				AllowInlineCredentials:     allowInline,
				DefaultTimeoutMs:           120000,
				OutputMaxBytes:             65536,
				SftpProgressThresholdBytes: 10 * 1024 * 1024,
			},
			Servers: map[string]config.ServerConfig{},
		},
	}
}

// --------------------------------------------------------------------------
// Helpers specific to sftp/tunnel tests
// --------------------------------------------------------------------------

// sftpDeps returns a *Deps with AllowInlineCredentials=true.
func sftpDeps() *Deps {
	return minDeps(true)
}

// sftpDepsNoInline returns a *Deps with inline creds disabled.
func sftpDepsNoInline() *Deps {
	return minDeps(false)
}

// sftpDepsWithTunnel returns Deps with a real (empty) tunnel Manager.
func sftpDepsWithTunnel() *Deps {
	d := minDeps(true)
	d.TunnelMgr = tunnel.NewManager(nil) // dialer not needed for pre-validation tests
	return d
}

func sftpErrCode(r envelope.Response) string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

// --------------------------------------------------------------------------
// sftp_list tests
// --------------------------------------------------------------------------

// TestSftpList_RelativePath: path not starting with '/' → INVALID_ARGUMENT.
func TestSftpList_RelativePath(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
		"path":   "relative/path",
	})
	resp := handleSftpList(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpList_MissingPath: omitting path → INVALID_ARGUMENT.
func TestSftpList_MissingPath(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
	})
	resp := handleSftpList(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpList_InlineDisabled: inline creds when disabled → INLINE_CREDS_DISABLED.
func TestSftpList_InlineDisabled(t *testing.T) {
	args := mustJSON(map[string]any{
		"inline": map[string]any{"host": "h", "user": "u"},
		"path":   "/tmp",
	})
	resp := handleSftpList(context.Background(), sftpDepsNoInline(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInlineCredsDisabled {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInlineCredsDisabled)
	}
}

// TestSftpList_NeitherServerNorInline → INVALID_ARGUMENT.
func TestSftpList_NeitherServerNorInline(t *testing.T) {
	args := mustJSON(map[string]any{
		"path": "/tmp",
	})
	resp := handleSftpList(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// --------------------------------------------------------------------------
// sftp_read tests
// --------------------------------------------------------------------------

// TestSftpRead_RelativePath: relative path → INVALID_ARGUMENT.
func TestSftpRead_RelativePath(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
		"path":   "etc/passwd",
	})
	resp := handleSftpRead(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpRead_InvalidEncoding: unsupported encoding → INVALID_ARGUMENT.
func TestSftpRead_InvalidEncoding(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":   "dummy",
		"path":     "/etc/hosts",
		"encoding": "hex",
	})
	resp := handleSftpRead(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpRead_LengthExceeds16MiB → INVALID_ARGUMENT.
func TestSftpRead_LengthExceeds16MiB(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
		"path":   "/big/file",
		"length": sftpReadMaxBytes + 1,
	})
	resp := handleSftpRead(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpRead_InlineDisabled → INLINE_CREDS_DISABLED.
func TestSftpRead_InlineDisabled(t *testing.T) {
	args := mustJSON(map[string]any{
		"inline": map[string]any{"host": "h", "user": "u"},
		"path":   "/tmp/data",
	})
	resp := handleSftpRead(context.Background(), sftpDepsNoInline(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInlineCredsDisabled {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInlineCredsDisabled)
	}
}

// --------------------------------------------------------------------------
// sftp_stat tests
// --------------------------------------------------------------------------

// TestSftpStat_RelativePath → INVALID_ARGUMENT.
func TestSftpStat_RelativePath(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
		"path":   "relative",
	})
	resp := handleSftpStat(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpStat_MissingPath → INVALID_ARGUMENT.
func TestSftpStat_MissingPath(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
	})
	resp := handleSftpStat(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// --------------------------------------------------------------------------
// sftp_op tests
// --------------------------------------------------------------------------

// TestSftpOp_UnknownAction → INVALID_ARGUMENT.
func TestSftpOp_UnknownAction(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
		"action": "explode",
		"path":   "/tmp/foo",
	})
	resp := handleSftpOp(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpOp_RelativePath: write with relative path → INVALID_ARGUMENT.
func TestSftpOp_RelativePath(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":  "dummy",
		"action":  "write",
		"path":    "relative/file.txt",
		"content": "hello",
	})
	resp := handleSftpOp(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpOp_BadMode: non-octal mode string → INVALID_ARGUMENT.
func TestSftpOp_BadMode(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
		"action": "chmod",
		"path":   "/tmp/file",
		"mode":   "z777",
	})
	resp := handleSftpOp(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpOp_ChmodMissingMode: chmod without mode → INVALID_ARGUMENT.
func TestSftpOp_ChmodMissingMode(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
		"action": "chmod",
		"path":   "/tmp/file",
	})
	resp := handleSftpOp(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpOp_RenameMissingTo: rename without 'to' → INVALID_ARGUMENT.
func TestSftpOp_RenameMissingTo(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
		"action": "rename",
		"path":   "/tmp/old",
	})
	resp := handleSftpOp(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpOp_WriteInvalidBase64 → INVALID_ARGUMENT (bad base64).
func TestSftpOp_WriteInvalidBase64(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":   "dummy",
		"action":   "write",
		"path":     "/tmp/out",
		"content":  "not-valid-base64!!!",
		"encoding": "base64",
	})
	resp := handleSftpOp(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpOp_MissingAction → INVALID_ARGUMENT.
func TestSftpOp_MissingAction(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "dummy",
		"path":   "/tmp/foo",
	})
	resp := handleSftpOp(context.Background(), sftpDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// --------------------------------------------------------------------------
// tunnel tests
// --------------------------------------------------------------------------

// TestTunnel_UnknownAction → INVALID_ARGUMENT.
func TestTunnel_UnknownAction(t *testing.T) {
	args := mustJSON(map[string]any{
		"action": "teleport",
	})
	resp := handleTunnel(context.Background(), sftpDepsWithTunnel(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestTunnel_CloseNotFound: closing a non-existent tunnel_id → NOT_FOUND.
func TestTunnel_CloseNotFound(t *testing.T) {
	args := mustJSON(map[string]any{
		"action":    "close",
		"tunnel_id": "no-such-id-1234",
	})
	resp := handleTunnel(context.Background(), sftpDepsWithTunnel(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeNotFound {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeNotFound)
	}
}

// TestTunnel_CloseMissingTunnelID: close without tunnel_id → INVALID_ARGUMENT.
func TestTunnel_CloseMissingTunnelID(t *testing.T) {
	args := mustJSON(map[string]any{
		"action": "close",
	})
	resp := handleTunnel(context.Background(), sftpDepsWithTunnel(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestTunnel_CreateMissingKind → INVALID_ARGUMENT.
func TestTunnel_CreateMissingKind(t *testing.T) {
	args := mustJSON(map[string]any{
		"action": "create",
		"server": "dummy",
	})
	resp := handleTunnel(context.Background(), sftpDepsWithTunnel(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestTunnel_CreateMissingServer → INVALID_ARGUMENT.
func TestTunnel_CreateMissingServer(t *testing.T) {
	args := mustJSON(map[string]any{
		"action": "create",
		"kind":   "local",
	})
	resp := handleTunnel(context.Background(), sftpDepsWithTunnel(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestTunnel_ListEmpty: list with no active tunnels → OK with tunnels field.
func TestTunnel_ListEmpty(t *testing.T) {
	args := mustJSON(map[string]any{
		"action": "list",
	})
	resp := handleTunnel(context.Background(), sftpDepsWithTunnel(), args)
	if !resp.OK {
		t.Fatalf("expected OK, got error: %v", resp.Error)
	}
}

// TestTunnel_CreateLocalMissingPorts → INVALID_ARGUMENT.
func TestTunnel_CreateLocalMissingPorts(t *testing.T) {
	args := mustJSON(map[string]any{
		"action":   "create",
		"kind":     "local",
		"server":   "dummy",
		"dst_host": "db.internal",
		// dst_port and local_port intentionally omitted
	})
	resp := handleTunnel(context.Background(), sftpDepsWithTunnel(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// --------------------------------------------------------------------------
// parseOctalMode unit tests
// --------------------------------------------------------------------------

// TestParseOctalMode_Valid: well-formed octal strings parse correctly.
func TestParseOctalMode_Valid(t *testing.T) {
	cases := []struct {
		s    string
		want uint32
	}{
		{"0644", 0644},
		{"0755", 0755},
		{"0600", 0600},
		{"777", 0777},
	}
	for _, tc := range cases {
		mode, err := parseOctalMode(tc.s, 0)
		if err != nil {
			t.Errorf("parseOctalMode(%q): unexpected error: %v", tc.s, err)
			continue
		}
		if uint32(mode) != tc.want {
			t.Errorf("parseOctalMode(%q): got %04o, want %04o", tc.s, uint32(mode), tc.want)
		}
	}
}

// TestParseOctalMode_Invalid: non-octal strings return error.
func TestParseOctalMode_Invalid(t *testing.T) {
	invalids := []string{"abc", "0x644", "9999", "zxcv"}
	for _, s := range invalids {
		_, err := parseOctalMode(s, 0)
		if err == nil {
			t.Errorf("parseOctalMode(%q): expected error, got nil", s)
		}
	}
}

// TestParseOctalMode_Empty: empty string returns the default mode.
func TestParseOctalMode_Empty(t *testing.T) {
	mode, err := parseOctalMode("", 0644)
	if err != nil {
		t.Fatalf("parseOctalMode empty: unexpected error: %v", err)
	}
	if uint32(mode) != 0644 {
		t.Errorf("parseOctalMode empty: got %04o, want 0644", uint32(mode))
	}
}

// --------------------------------------------------------------------------
// H01 — allowed_paths enforcement tests
// --------------------------------------------------------------------------

// restrictedDeps returns Deps with a "restricted" named server whose
// allowed_paths = ["/tmp"].
func restrictedDeps() *Deps {
	d := minDeps(true)
	d.Cfg.Servers = map[string]config.ServerConfig{
		"restricted": {
			Name:         "restricted",
			Host:         "localhost",
			User:         "u",
			Auth:         "agent",
			AllowedPaths: []string{"/tmp"},
		},
	}
	return d
}

// TestSftpList_AllowedPaths_Denied: path outside allowed_prefixes → PERMISSION_DENIED.
func TestSftpList_AllowedPaths_Denied(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "restricted",
		"path":   "/etc/passwd",
	})
	resp := handleSftpList(context.Background(), restrictedDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodePermissionDenied {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodePermissionDenied)
	}
}

// TestSftpList_AllowedPaths_Allowed: path within allowed_prefixes → does NOT
// return PERMISSION_DENIED before the pool lookup (the pool lookup itself will
// panic/error when Pool is nil, so we verify the error is not PERMISSION_DENIED).
func TestSftpList_AllowedPaths_Allowed(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "restricted",
		"path":   "/tmp/subdir",
	})
	// Use a recover wrapper because Pool == nil will cause a panic in Get.
	// We only care that enforceAllowedPath did NOT reject the path.
	var resp envelope.Response
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Panic means we got past the allowed_paths check — that's the goal.
				resp = envelope.Err("CONN_FAILED", "nil pool (expected in unit test)", true)
			}
		}()
		resp = handleSftpList(context.Background(), restrictedDeps(), args)
	}()
	if sftpErrCode(resp) == envelope.CodePermissionDenied {
		t.Errorf("got PERMISSION_DENIED for allowed path /tmp/subdir")
	}
}

// TestSftpRead_AllowedPaths_Denied: read outside allowed_prefixes → PERMISSION_DENIED.
func TestSftpRead_AllowedPaths_Denied(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "restricted",
		"path":   "/etc/passwd",
	})
	resp := handleSftpRead(context.Background(), restrictedDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodePermissionDenied {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodePermissionDenied)
	}
}

// TestSftpStat_AllowedPaths_Denied: stat outside allowed_prefixes → PERMISSION_DENIED.
func TestSftpStat_AllowedPaths_Denied(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "restricted",
		"path":   "/etc/passwd",
	})
	resp := handleSftpStat(context.Background(), restrictedDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodePermissionDenied {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodePermissionDenied)
	}
}

// TestSftpOp_Write_AllowedPaths_Denied → PERMISSION_DENIED.
func TestSftpOp_Write_AllowedPaths_Denied(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":  "restricted",
		"action":  "write",
		"path":    "/etc/passwd",
		"content": "bad",
	})
	resp := handleSftpOp(context.Background(), restrictedDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodePermissionDenied {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodePermissionDenied)
	}
}

// TestSftpOp_Remove_AllowedPaths_Denied → PERMISSION_DENIED.
func TestSftpOp_Remove_AllowedPaths_Denied(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "restricted",
		"action": "remove",
		"path":   "/etc/important",
	})
	resp := handleSftpOp(context.Background(), restrictedDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodePermissionDenied {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodePermissionDenied)
	}
}

// TestSftpOp_Rename_DestDenied: destination path outside allowed_prefixes → PERMISSION_DENIED.
func TestSftpOp_Rename_DestDenied(t *testing.T) {
	args := mustJSON(map[string]any{
		"server": "restricted",
		"action": "rename",
		"path":   "/tmp/allowed_src",
		"to":     "/etc/target",
	})
	resp := handleSftpOp(context.Background(), restrictedDeps(), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodePermissionDenied {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodePermissionDenied)
	}
}

// TestSftpList_InlineNoAllowedPaths: inline path bypass — allowed_paths check
// must be skipped; error must NOT be PERMISSION_DENIED.
func TestSftpList_InlineNoAllowedPaths(t *testing.T) {
	args := mustJSON(map[string]any{
		"inline": map[string]any{"host": "x", "user": "u", "password": "p"},
		"path":   "/etc/passwd",
	})
	// Pool == nil → GetAdHoc will panic; recover and verify no PERMISSION_DENIED.
	var resp envelope.Response
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Panic means allowed_paths check was skipped (inline) — correct.
				resp = envelope.Err("CONN_FAILED", "nil pool (expected in unit test)", true)
			}
		}()
		resp = handleSftpList(context.Background(), sftpDeps(), args)
	}()
	if sftpErrCode(resp) == envelope.CodePermissionDenied {
		t.Error("inline path must not trigger PERMISSION_DENIED for allowed_paths check")
	}
}
