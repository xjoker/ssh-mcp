// Tests for sftp_upload (docs/design/sftp-upload-tool.md).
// All tests here exercise pre-connection validation — the local-path
// allow-list gate, symlink-escape hardening, and regular-file check —
// which run before resolveClient/deps.Pool is ever touched, mirroring the
// pre-validation test style already used for sftp_op/sftp_read/sftp_stat
// in sftp_tools_test.go. The transmission path itself (WriteFrom byte-exact
// + sha256) is covered at the internal/sftp package level
// (ops_writefrom_test.go), since this package has no fake SFTP backend
// reachable through the unexported internal/sftp.Client.
package tools

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/ssh"
)

// uploadDeps returns a *Deps with the given upload allow-list and a real
// (dialer-less) SSH pool, so tests that pass the local-path gate and reach
// resolveClient get a connection-attempt error instead of a nil-pointer
// panic on deps.Pool.
func uploadDeps(allowedPaths []string) *Deps {
	d := minDeps(true)
	d.Cfg.Settings.UploadLocalAllowedPaths = allowedPaths
	d.Pool = ssh.NewPool(d.Cfg, nil)
	return d
}

// --------------------------------------------------------------------------
// Global fail-closed gate
// --------------------------------------------------------------------------

// TestSftpUpload_DisabledByDefault: empty upload_local_allowed_paths (the
// zero-value default) → UPLOAD_DISABLED, regardless of local_path/remote_path
// well-formedness.
func TestSftpUpload_DisabledByDefault(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":      "dummy",
		"local_path":  "/tmp/whatever.txt",
		"remote_path": "/srv/app/whatever.txt",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps(nil), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeUploadDisabled {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeUploadDisabled)
	}
}

// --------------------------------------------------------------------------
// Argument validation
// --------------------------------------------------------------------------

func TestSftpUpload_MissingLocalPath(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":      "dummy",
		"remote_path": "/srv/app/out.bin",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{"/tmp"}), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

func TestSftpUpload_MissingRemotePath(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":     "dummy",
		"local_path": "/tmp/in.bin",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{"/tmp"}), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

func TestSftpUpload_RelativeRemotePath(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":      "dummy",
		"local_path":  "/tmp/in.bin",
		"remote_path": "relative/out.bin",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{"/tmp"}), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

func TestSftpUpload_LocalPathNotAbsolute(t *testing.T) {
	args := mustJSON(map[string]any{
		"server":      "dummy",
		"local_path":  "relative/in.bin",
		"remote_path": "/srv/app/out.bin",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{"/tmp"}), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

func TestSftpUpload_BadMode(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "in.bin")
	if err := os.WriteFile(f, []byte("hi"), 0600); err != nil {
		t.Fatal(err)
	}
	args := mustJSON(map[string]any{
		"server":      "dummy",
		"local_path":  f,
		"remote_path": "/srv/app/out.bin",
		"mode":        "z777",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{dir}), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// --------------------------------------------------------------------------
// Local allow-list enforcement
// --------------------------------------------------------------------------

// TestSftpUpload_LocalPathOutsideAllowlist: allow-list is non-empty (feature
// enabled) but local_path falls outside every configured prefix →
// PERMISSION_DENIED, not UPLOAD_DISABLED.
func TestSftpUpload_LocalPathOutsideAllowlist(t *testing.T) {
	allowedDir := t.TempDir()
	outsideDir := t.TempDir()
	f := filepath.Join(outsideDir, "secret.bin")
	if err := os.WriteFile(f, []byte("hi"), 0600); err != nil {
		t.Fatal(err)
	}

	args := mustJSON(map[string]any{
		"server":      "dummy",
		"local_path":  f,
		"remote_path": "/srv/app/out.bin",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{allowedDir}), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodePermissionDenied {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodePermissionDenied)
	}
}

// TestSftpUpload_LocalPathInsideAllowlist_NotFound: path is under the
// allow-list prefix but does not exist → NOT_FOUND (proves the allow-list
// check itself passed and we got to the filesystem stat stage; connecting
// never happens because the handler fails before resolveClient).
func TestSftpUpload_LocalPathInsideAllowlist_NotFound(t *testing.T) {
	allowedDir := t.TempDir()
	missing := filepath.Join(allowedDir, "does-not-exist.bin")

	args := mustJSON(map[string]any{
		"server":      "dummy",
		"local_path":  missing,
		"remote_path": "/srv/app/out.bin",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{allowedDir}), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeNotFound {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeNotFound)
	}
}

// TestSftpUpload_LocalPathIsDirectory: local_path resolves to a directory,
// not a regular file → INVALID_ARGUMENT.
func TestSftpUpload_LocalPathIsDirectory(t *testing.T) {
	allowedDir := t.TempDir()
	sub := filepath.Join(allowedDir, "subdir")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}

	args := mustJSON(map[string]any{
		"server":      "dummy",
		"local_path":  sub,
		"remote_path": "/srv/app/out.bin",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{allowedDir}), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodeInvalidArgument {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodeInvalidArgument)
	}
}

// TestSftpUpload_SymlinkEscapeDenied: local_path is a symlink that lives
// inside the allow-listed directory but points to a regular file *outside*
// it (e.g. mimicking ~/.ssh/id_rsa symlinked into an allowed uploads dir).
// The prefix check must run against the EvalSymlinks-resolved real path, not
// the syntactic local_path, so this must be denied — this is the R2-C01-style
// hardening called out in the design doc §3.2.
func TestSftpUpload_SymlinkEscapeDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows CI")
	}
	allowedDir := t.TempDir()
	outsideDir := t.TempDir()

	secret := filepath.Join(outsideDir, "id_rsa")
	if err := os.WriteFile(secret, []byte("-----BEGIN PRIVATE KEY-----"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowedDir, "innocuous.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	args := mustJSON(map[string]any{
		"server":      "dummy",
		"local_path":  link,
		"remote_path": "/srv/app/out.bin",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{allowedDir}), args)
	if resp.OK {
		t.Fatal("expected error, got OK")
	}
	if sftpErrCode(resp) != envelope.CodePermissionDenied {
		t.Errorf("code: got %q, want %q", sftpErrCode(resp), envelope.CodePermissionDenied)
	}
}

// TestSftpUpload_SymlinkInsideAllowlistOK: a symlink inside the allow-listed
// directory that points to another file *within* the same allow-listed
// directory must be permitted through the local-path gate (it will still
// fail later at resolveClient/connect since deps.Pool is nil in these
// pre-validation-only tests — that failure is expected and out of scope
// here; asserting NOT PermissionDenied is sufficient to prove the allow-list
// check itself is not falsely rejecting legitimate same-prefix symlinks).
func TestSftpUpload_SymlinkInsideAllowlistOK(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows CI")
	}
	allowedDir := t.TempDir()
	real := filepath.Join(allowedDir, "real.bin")
	if err := os.WriteFile(real, []byte("hi"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowedDir, "link.bin")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	args := mustJSON(map[string]any{
		"server":      "dummy",
		"local_path":  link,
		"remote_path": "/srv/app/out.bin",
	})
	resp := handleSftpUpload(context.Background(), uploadDeps([]string{allowedDir}), args)
	if resp.OK {
		t.Fatal("expected an error since no real SSH pool is configured in this test, got OK")
	}
	if sftpErrCode(resp) == envelope.CodePermissionDenied {
		t.Errorf("legitimate same-prefix symlink was denied by the local-path gate")
	}
}

// TestIsUnderLocalAllowedPrefix_ComponentBoundary verifies that a sibling
// directory whose name merely starts with the allowed prefix as a string
// (e.g. "foobar" vs allowed "foo") is not treated as a descendant — the
// prefix match must land on a path-separator boundary. Review Fix 3.
func TestIsUnderLocalAllowedPrefix_ComponentBoundary(t *testing.T) {
	tmp := t.TempDir()
	allowed := filepath.Join(tmp, "foo")
	sibling := filepath.Join(tmp, "foobar", "x")

	if isUnderLocalAllowedPrefix(sibling, []string{allowed}) {
		t.Errorf("sibling path %q must not match allowed prefix %q", sibling, allowed)
	}

	// Sanity: a genuine descendant of the allowed prefix is still permitted.
	descendant := filepath.Join(allowed, "x")
	if !isUnderLocalAllowedPrefix(descendant, []string{allowed}) {
		t.Errorf("descendant path %q must match allowed prefix %q", descendant, allowed)
	}
}

// --------------------------------------------------------------------------
// Schema registration
// --------------------------------------------------------------------------

func TestSftpUpload_Registered(t *testing.T) {
	found := false
	for _, tl := range Registered {
		if tl.Name == "sftp_upload" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("sftp_upload not found in Registered tools")
	}
}
