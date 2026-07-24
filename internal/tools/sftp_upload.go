// sftp_upload implements the sftp_upload MCP tool: an MCP-native large-file
// upload path that streams straight from the local filesystem to the remote
// SFTP server, so file bytes never pass through the AI's JSON/token context.
// See docs/design/sftp-upload-tool.md for the full design rationale.
package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/safety"
	internalsftp "github.com/xjoker/ssh-mcp/internal/sftp"
)

var errDefaultUploadSymlink = errors.New("default upload directory is a symlink")

func init() {
	Registered = append(Registered, Tool{
		Name: "sftp_upload",
		Description: "Upload a local file to a remote server by streaming it directly through the MCP process " +
			"(no size limit, no base64/JSON overhead — bytes never enter the AI's context). " +
			"By default only ~/.ssh-mcp/uploads is allowed; set an explicit empty list to disable, and expand paths only by manually editing TOML. " +
			"Overwrites the destination file if it exists.",
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "server":      { "type": "string" },
    "inline":      { "type": "object" },
    "local_path":  { "type": "string", "description": "Absolute local filesystem path to the file to upload" },
    "remote_path": { "type": "string", "description": "Absolute remote destination path" },
    "mode":        { "type": "string", "description": "Octal string e.g. '0644', default '0644'" },
    "atomic":      { "type": "boolean", "default": true }
  },
  "required": ["local_path", "remote_path"]
}`),
		Handle: handleSftpUpload,
		Annotations: &Annotations{
			Title:           "Upload local file to remote",
			ReadOnlyHint:    false,
			DestructiveHint: true,
			IdempotentHint:  true,
			OpenWorldHint:   true,
		},
	})
}

type sftpUploadArgs struct {
	LocalPath  string `json:"local_path"`
	RemotePath string `json:"remote_path"`
	Mode       string `json:"mode"`
	Atomic     *bool  `json:"atomic"`
}

func handleSftpUpload(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	// Global fail-closed gate — checked before anything else parses/opens
	// local state, per SDD design §3.1: an empty allow-list means the
	// feature is off, full stop, regardless of what else the caller sent.
	if len(deps.Cfg.Settings.UploadLocalAllowedPaths) == 0 {
		return envelope.ErrWithHint(envelope.CodeUploadDisabled,
			"sftp_upload is disabled: settings.upload_local_allowed_paths is explicitly empty",
			"Ask the user to remove the explicit empty list to restore ~/.ssh-mcp/uploads, or manually configure a narrow absolute path in config.toml and restart ssh-mcp. "+
				"This cannot be enabled through any MCP tool call.",
			false)
	}

	var a sftpUploadArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "cannot parse args: "+err.Error(), false)
	}

	if a.LocalPath == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "local_path is required", false)
	}
	if a.RemotePath == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "remote_path is required", false)
	}
	if _, err := safety.ValidateRemotePath(a.RemotePath); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}

	mode, modeErr := parseOctalMode(a.Mode, 0644)
	if modeErr != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "mode: "+modeErr.Error(), false)
	}

	atomic := true
	if a.Atomic != nil {
		atomic = *a.Atomic
	}

	realLocalPath, errResp, ok := checkLocalUploadPath(deps, a.LocalPath)
	if !ok {
		return errResp
	}

	// Open the already-resolved real path (post EvalSymlinks) rather than
	// the caller-supplied one, and re-derive size from the open file
	// descriptor rather than the earlier Stat, narrowing the TOCTOU window
	// between the allow-list check and the actual read.
	f, err := os.Open(realLocalPath) // #nosec G304 -- realLocalPath is EvalSymlinks-resolved and prefix-checked against settings.upload_local_allowed_paths in checkLocalUploadPath
	if err != nil {
		return envelope.Err(envelope.CodeNotFound, fmt.Sprintf("local_path %q: %v", a.LocalPath, err), false)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return envelope.Err(envelope.CodeInternalError, fmt.Sprintf("local_path %q: stat: %v", a.LocalPath, err), false)
	}
	if !fi.Mode().IsRegular() {
		return envelope.Err(envelope.CodeInvalidArgument, fmt.Sprintf("local_path %q is not a regular file", a.LocalPath), false)
	}
	localSize := fi.Size()

	var connArgs sftpConnArgs
	_ = json.Unmarshal(args, &connArgs)
	serverName := ""
	if connArgs.Server != nil {
		serverName = *connArgs.Server
	}

	client, closeFn, errResp, ok := resolveClient(ctx, deps, args)
	if !ok {
		return errResp
	}
	defer closeFn()

	sftpClient, err := internalsftp.New(client.Underlying())
	if err != nil {
		return envelope.Err(envelope.CodeSftpError, "sftp subsystem: "+err.Error(), false)
	}
	defer sftpClient.Close()

	// R2-C01: canonicalise + enforce allowed_paths on the remote side,
	// exactly as sftp_op's write action does.
	rp, errResp, ok := resolveAndCheckRemotePath(deps, serverName, sftpClient, a.RemotePath, true)
	if !ok {
		return errResp
	}

	// Stream-hash the source while it is being read for the write, so the
	// sha256 in the response costs nothing beyond the upload itself.
	hasher := sha256.New()
	tee := io.TeeReader(f, hasher)

	var progressCb func(written, total int64)
	threshold := int64(deps.Cfg.Settings.SftpProgressThresholdBytes)
	if threshold <= 0 {
		threshold = 10 * 1024 * 1024
	}
	if deps.Progress != nil && localSize > threshold {
		progressCb = func(w, t int64) {
			deps.Progress(map[string]any{"bytes_written": w, "total": t})
		}
	}

	if err := sftpClient.WriteFrom(rp, tee, localSize, mode, atomic, progressCb); err != nil {
		return mapSFTPErr(err)
	}

	// Cheap post-write integrity check: compare remote size against what we
	// read locally. Catches truncation without a full remote read-back.
	remoteEntry, statErr := sftpClient.Stat(rp)
	if statErr != nil {
		return mapSFTPErr(statErr)
	}
	if remoteEntry.Size != localSize {
		// NOT COVERED BY A TEST (review Fix 3): this branch runs after
		// resolveClient/WriteFrom against a live *pkgsftp.Client, and
		// internalsftp.New only wraps that unexported concrete type — this
		// package (see file header) has no fake SFTP backend reachable from
		// here to force a post-write size mismatch. internal/sftp's own
		// fakeBackend (ops_writefrom_test.go) exercises WriteFrom's byte-exact
		// transfer at that lower layer instead.
		return envelope.Err(envelope.CodeSftpError,
			fmt.Sprintf("upload size mismatch: wrote %d bytes locally, remote reports %d bytes", localSize, remoteEntry.Size),
			true)
	}

	sha256Hex := hex.EncodeToString(hasher.Sum(nil))

	return envelope.OK(map[string]any{
		"bytes_written": localSize,
		"sha256":        sha256Hex,
		"remote_path":   rp.String(),
	}).WithAudit(envelope.AuditMeta{
		BytesIn:       localSize,
		AuthMode:      client.AuthMode(),
		ContentSHA256: sha256Hex,
	})
}

// checkLocalUploadPath enforces the sftp_upload local-side threat model
// (design doc §3.2/§3.3): local_path must be absolute, must resolve (via
// EvalSymlinks — hardening against a symlink planted inside an allowed
// directory pointing outside it) to a path under one of
// settings.upload_local_allowed_paths, and must be a regular file.
// Returns the resolved real path on success.
func checkLocalUploadPath(deps *Deps, localPath string) (string, envelope.Response, bool) {
	if !filepath.IsAbs(localPath) {
		return "", envelope.Err(envelope.CodeInvalidArgument, "local_path must be an absolute path", false), false
	}
	if err := ensureDefaultUploadDir(localPath, deps.Cfg.Settings.UploadLocalAllowedPaths); err != nil {
		if errors.Is(err, errDefaultUploadSymlink) {
			return "", envelope.Err(envelope.CodePermissionDenied, err.Error(), false), false
		}
		return "", envelope.Err(envelope.CodeInternalError, err.Error(), false), false
	}

	real, err := filepath.EvalSymlinks(filepath.Clean(localPath))
	if err != nil {
		if !os.IsNotExist(err) {
			return "", envelope.Err(envelope.CodeInternalError, fmt.Sprintf("resolve local_path %q: %v", localPath, err), false), false
		}
		return "", envelope.Err(envelope.CodeNotFound, fmt.Sprintf("local_path %q: %v", localPath, err), false), false
	}

	if !isUnderLocalAllowedPrefix(real, deps.Cfg.Settings.UploadLocalAllowedPaths) {
		return "", envelope.Err(envelope.CodePermissionDenied,
			fmt.Sprintf("local_path %q is not under any configured upload_local_allowed_paths prefix", localPath), false), false
	}

	return real, envelope.Response{}, true
}

func ensureDefaultUploadDir(localPath string, allowed []string) error {
	defaults := config.DefaultUploadLocalAllowedPaths()
	if len(defaults) != 1 || len(allowed) != 1 {
		return nil
	}
	def := defaults[0]
	clean := filepath.Clean(localPath)
	if !strings.HasPrefix(clean, def+string(filepath.Separator)) {
		return nil
	}
	if filepath.Clean(allowed[0]) != filepath.Clean(def) {
		return nil
	}
	parent := filepath.Dir(def)
	if _, err := os.Lstat(parent); os.IsNotExist(err) {
		if err := os.Mkdir(parent, 0700); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create default upload parent: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("stat default upload parent: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("stat default upload parent: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 {
		return errDefaultUploadSymlink
	}
	if !parentInfo.IsDir() {
		return fmt.Errorf("default upload parent is not a directory")
	}

	if _, err := os.Lstat(def); os.IsNotExist(err) {
		if err := os.Mkdir(def, 0700); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create default upload directory: %w", err)
		}
	} else {
		if err != nil {
			return fmt.Errorf("stat default upload directory: %w", err)
		}
	}
	info, err := os.Lstat(def)
	if err != nil {
		return fmt.Errorf("stat default upload directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errDefaultUploadSymlink
	}
	if !info.IsDir() {
		return fmt.Errorf("default upload directory is invalid")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(def, 0700); err != nil {
			return fmt.Errorf("secure default upload directory: %w", err)
		}
	}
	return nil
}

// isUnderLocalAllowedPrefix reports whether p (already EvalSymlinks-resolved
// by the caller) is equal to, or a descendant of, one of the given absolute
// prefixes. Each prefix is itself passed through EvalSymlinks (best-effort —
// a prefix that does not exist yet, or any other resolution error, falls
// back to its cleaned literal form) before comparing: on macOS /tmp (and
// t.TempDir()'s /var/folders/...) is itself a symlink into /private, so
// comparing an EvalSymlinks-resolved local_path against an un-resolved
// configured prefix would spuriously deny legitimate paths under that
// prefix. Mirrors safety.CheckAllowed's prefix semantics for the local
// filesystem case.
func isUnderLocalAllowedPrefix(p string, prefixes []string) bool {
	cleanedPath := filepath.Clean(p)
	for _, prefix := range prefixes {
		cleanedPrefix := filepath.Clean(prefix)
		if real, err := filepath.EvalSymlinks(cleanedPrefix); err == nil {
			cleanedPrefix = real
		}
		if cleanedPrefix == string(filepath.Separator) {
			return true
		}
		if cleanedPath == cleanedPrefix {
			return true
		}
		if strings.HasPrefix(cleanedPath, cleanedPrefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
