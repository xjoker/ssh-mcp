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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/safety"
	internalsftp "github.com/xjoker/ssh-mcp/internal/sftp"
)

func init() {
	Registered = append(Registered, Tool{
		Name: "sftp_upload",
		Description: "Upload a local file to a remote server by streaming it directly through the MCP process " +
			"(no size limit, no base64/JSON overhead — bytes never enter the AI's context). " +
			"Disabled by default: requires settings.upload_local_allowed_paths to be configured in config.toml.",
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
			"sftp_upload is disabled: settings.upload_local_allowed_paths is empty",
			"Ask the user to add settings.upload_local_allowed_paths = [\"/abs/local/dir\", ...] to config.toml "+
				"(absolute paths only; prefer a specific working directory, not $HOME) and restart ssh-mcp. "+
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
		return envelope.Err(envelope.CodeSftpError,
			fmt.Sprintf("upload size mismatch: wrote %d bytes locally, remote reports %d bytes", localSize, remoteEntry.Size),
			true)
	}

	return envelope.OK(map[string]any{
		"bytes_written": localSize,
		"sha256":        hex.EncodeToString(hasher.Sum(nil)),
		"remote_path":   rp.String(),
	}).WithAudit(envelope.AuditMeta{
		BytesIn:  localSize,
		AuthMode: client.AuthMode(),
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

	real, err := filepath.EvalSymlinks(filepath.Clean(localPath))
	if err != nil {
		return "", envelope.Err(envelope.CodeNotFound, fmt.Sprintf("local_path %q: %v", localPath, err), false), false
	}

	if !isUnderLocalAllowedPrefix(real, deps.Cfg.Settings.UploadLocalAllowedPaths) {
		return "", envelope.Err(envelope.CodePermissionDenied,
			fmt.Sprintf("local_path %q is not under any configured upload_local_allowed_paths prefix", localPath), false), false
	}

	return real, envelope.Response{}, true
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
