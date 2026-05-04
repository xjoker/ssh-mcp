// Tests for sftp_list, sftp_read, sftp_stat, sftp_op, tunnel tools.
// All tests exercise pre-validation (bad arguments, encoding mismatches, etc.)
// without making real SSH connections.
package tools

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
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

func TestSftpList_MaxEntriesLimit(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":      "dummy",
		"path":        "/tmp",
		"max_entries": sftpListMaxEntries + 1,
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

func TestSftpOp_WriteContentLimit(t *testing.T) {
	_, resp, ok := decodeSFTPWriteContent(sftpOpArgs{
		Action:   "write",
		Path:     "/tmp/out",
		Content:  strings.Repeat("x", sftpWriteMaxBytes+1),
		Encoding: "utf8",
	})
	if ok {
		t.Fatal("expected oversized write content to be rejected")
	}
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %+v", resp.Error)
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

func TestTunnel_CreateCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	args := mustJSON(map[string]any{
		"action":     "create",
		"kind":       "local",
		"server":     "dummy",
		"local_port": 10022,
		"dst_host":   "db.internal",
		"dst_port":   5432,
	})
	resp := handleTunnel(ctx, sftpDepsWithTunnel(), args)
	if resp.OK {
		t.Fatal("expected canceled create to fail")
	}
	if sftpErrCode(resp) != envelope.CodeTimeout {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeTimeout)
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
// R2-C01 — symlink-resistant allowed_paths via resolveAndCheckRemotePath
// --------------------------------------------------------------------------

// fakeRealpather implements remoteRealpather for unit tests.
type fakeRealpather struct {
	resolveFn func(p string) (safety.RemotePath, error)
}

func (f *fakeRealpather) Realpath(p string) (safety.RemotePath, error) {
	if f.resolveFn != nil {
		return f.resolveFn(p)
	}
	rp, err := safety.ValidateRemotePath(p)
	return rp, err
}

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

// SDD §13 / Codex R2-C01: a path that is itself inside the allow list
// but resolves (via symlink) to a path outside MUST be denied. The
// resolver consults the canonical form before checking the policy.
func TestResolveAndCheck_SymlinkEscapeDenied(t *testing.T) {
	deps := restrictedDeps()
	fr := &fakeRealpather{
		resolveFn: func(p string) (safety.RemotePath, error) {
			// /tmp/allowed_link is a symlink → /etc/shadow
			return safety.ValidateRemotePath("/etc/shadow")
		},
	}
	_, errResp, ok := resolveAndCheckRemotePath(deps, "restricted", fr, "/tmp/allowed_link", false)
	if ok {
		t.Fatal("expected denial of resolved /etc/shadow")
	}
	if errResp.Error == nil || errResp.Error.Code != envelope.CodePermissionDenied {
		t.Errorf("got %v want PERMISSION_DENIED", errResp.Error)
	}
}

// Path inside allowed prefix that resolves to a sibling within prefix → allowed.
func TestResolveAndCheck_SymlinkInsidePrefixAllowed(t *testing.T) {
	deps := restrictedDeps()
	fr := &fakeRealpather{
		resolveFn: func(p string) (safety.RemotePath, error) {
			return safety.ValidateRemotePath("/tmp/real_target")
		},
	}
	rp, _, ok := resolveAndCheckRemotePath(deps, "restricted", fr, "/tmp/link_to_target", false)
	if !ok {
		t.Fatal("expected allow")
	}
	if rp.String() != "/tmp/real_target" {
		t.Errorf("expected canonicalised path /tmp/real_target, got %s", rp.String())
	}
}

// Inline / temp server (allowed_paths empty) must bypass policy but still
// receive the canonicalised path.
func TestResolveAndCheck_InlineBypass(t *testing.T) {
	deps := minDeps(true)
	fr := &fakeRealpather{}
	rp, _, ok := resolveAndCheckRemotePath(deps, "", fr, "/etc/passwd", false)
	if !ok {
		t.Fatal("inline path must not be denied")
	}
	if rp.String() != "/etc/passwd" {
		t.Errorf("expected canonical /etc/passwd, got %s", rp.String())
	}
}

// allowMissing=true: target does not exist; helper falls back to parent
// realpath then re-applies the policy on parent + basename.
func TestResolveAndCheck_FallbackParentDenied(t *testing.T) {
	deps := restrictedDeps()
	fr := &fakeRealpather{
		resolveFn: func(p string) (safety.RemotePath, error) {
			if p == "/tmp/newfile" {
				return safety.RemotePath{}, fmt.Errorf("no such file")
			}
			// parent /tmp resolves to /etc (escape via parent symlink)
			if p == "/tmp" {
				return safety.ValidateRemotePath("/etc")
			}
			return safety.ValidateRemotePath(p)
		},
	}
	_, errResp, ok := resolveAndCheckRemotePath(deps, "restricted", fr, "/tmp/newfile", true)
	if ok {
		t.Fatal("expected denial when parent resolves outside allow list")
	}
	if errResp.Error == nil || errResp.Error.Code != envelope.CodePermissionDenied {
		t.Errorf("got %v want PERMISSION_DENIED", errResp.Error)
	}
}

func TestResolveAndCheck_FallbackParentAllowed(t *testing.T) {
	deps := restrictedDeps()
	fr := &fakeRealpather{
		resolveFn: func(p string) (safety.RemotePath, error) {
			if p == "/tmp/newfile" {
				return safety.RemotePath{}, fmt.Errorf("no such file")
			}
			return safety.ValidateRemotePath(p)
		},
	}
	rp, _, ok := resolveAndCheckRemotePath(deps, "restricted", fr, "/tmp/newfile", true)
	if !ok {
		t.Fatal("expected allow when parent /tmp is in allow list")
	}
	if rp.String() != "/tmp/newfile" {
		t.Errorf("got %s want /tmp/newfile", rp.String())
	}
}

// --------------------------------------------------------------------------
// H05 — resolveAndCheckRemotePathWalkUp tests
// --------------------------------------------------------------------------

// TestMkdirRecursive_DeepNonExistent_AllInAllowed: /tmp exists, /tmp/a and
// /tmp/a/b do not. walkUp("/tmp/a/b/c") should resolve ancestor /tmp (inside
// allowed prefix /tmp) then synthesise /tmp/a, /tmp/a/b, /tmp/a/b/c and
// check each segment — all are under /tmp, so it must be allowed.
func TestMkdirRecursive_DeepNonExistent_AllInAllowed(t *testing.T) {
	deps := restrictedDeps()
	fr := &fakeRealpather{
		resolveFn: func(p string) (safety.RemotePath, error) {
			switch p {
			case "/tmp":
				return safety.ValidateRemotePath("/tmp")
			default:
				return safety.RemotePath{}, fmt.Errorf("no such file or directory")
			}
		},
	}
	rp, _, ok := resolveAndCheckRemotePathWalkUp(deps, "restricted", fr, "/tmp/a/b/c")
	if !ok {
		t.Fatal("expected allow for deep path fully inside allowed prefix")
	}
	if rp.String() != "/tmp/a/b/c" {
		t.Errorf("got %s want /tmp/a/b/c", rp.String())
	}
}

// TestMkdirRecursive_DeepNonExistent_EscapesAllowed: ancestor /tmp resolves
// to /etc (symlink escape), causing every synthetic sub-path to land under
// /etc — must be denied.
func TestMkdirRecursive_DeepNonExistent_EscapesAllowed(t *testing.T) {
	deps := restrictedDeps()
	fr := &fakeRealpather{
		resolveFn: func(p string) (safety.RemotePath, error) {
			switch p {
			case "/tmp":
				// /tmp is a symlink to /etc — escape attempt
				return safety.ValidateRemotePath("/etc")
			default:
				return safety.RemotePath{}, fmt.Errorf("no such file or directory")
			}
		},
	}
	_, errResp, ok := resolveAndCheckRemotePathWalkUp(deps, "restricted", fr, "/tmp/a/b/c")
	if ok {
		t.Fatal("expected denial when ancestor resolves outside allowed prefix")
	}
	if errResp.Error == nil || errResp.Error.Code != envelope.CodePermissionDenied {
		t.Errorf("got code %v, want PERMISSION_DENIED", errResp.Error)
	}
}

// TestMkdirRecursive_TargetExists_FollowsCanonical: the full path resolves
// successfully (target already exists). Should follow the canonical check path
// and allow if within prefix.
func TestMkdirRecursive_TargetExists_FollowsCanonical(t *testing.T) {
	deps := restrictedDeps()
	fr := &fakeRealpather{
		resolveFn: func(p string) (safety.RemotePath, error) {
			// Full path exists and canonicalises to /tmp/existing
			return safety.ValidateRemotePath("/tmp/existing")
		},
	}
	rp, _, ok := resolveAndCheckRemotePathWalkUp(deps, "restricted", fr, "/tmp/existing")
	if !ok {
		t.Fatal("expected allow for existing canonical path inside prefix")
	}
	if rp.String() != "/tmp/existing" {
		t.Errorf("got %s want /tmp/existing", rp.String())
	}
}

func TestSplitPath(t *testing.T) {
	cases := []struct {
		in           string
		parent, base string
	}{
		{"/tmp/file", "/tmp", "file"},
		{"/file", "/", "file"},
		{"file", "", "file"},
		{"/tmp/sub/leaf", "/tmp/sub", "leaf"},
	}
	for _, c := range cases {
		p, b := splitPath(c.in)
		if p != c.parent || b != c.base {
			t.Errorf("splitPath(%q) = (%q,%q); want (%q,%q)", c.in, p, b, c.parent, c.base)
		}
	}
}
