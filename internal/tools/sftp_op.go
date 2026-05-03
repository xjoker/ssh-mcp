// sftp_op implements the sftp_op MCP tool (SDD §6.8).
// Supported actions: write, mkdir, remove, rename, chmod, symlink, realpath.
package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	internalsftp "github.com/xjoker/mcp-ssh-bridge/internal/sftp"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
)

func init() {
	Registered = append(Registered, Tool{
		Name:        "sftp_op",
		Description: "Perform a write or management operation on the remote filesystem: write, mkdir, remove, rename, chmod, symlink, realpath.",
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "server":    { "type": "string" },
    "inline":    { "type": "object" },
    "action":    { "type": "string", "enum": ["write", "mkdir", "remove", "rename", "chmod", "symlink", "realpath"] },
    "path":      { "type": "string", "description": "Primary path (target of action)" },
    "content":   { "type": "string", "description": "(write only) UTF-8 or base64 content" },
    "encoding":  { "type": "string", "enum": ["utf8", "base64"], "default": "utf8" },
    "atomic":    { "type": "boolean", "default": true },
    "mode":      { "type": "string", "description": "Octal string e.g. '0644'" },
    "recursive": { "type": "boolean", "default": false },
    "to":        { "type": "string", "description": "(rename/symlink) Destination path" },
    "dry_run":   { "type": "boolean", "default": false }
  },
  "required": ["action", "path"]
}`),
		Handle: handleSftpOp,
	})
}

type sftpOpArgs struct {
	Action    string `json:"action"`
	Path      string `json:"path"`
	Content   string `json:"content"`
	Encoding  string `json:"encoding"`
	Atomic    *bool  `json:"atomic"`
	Mode      string `json:"mode"`
	Recursive bool   `json:"recursive"`
	To        string `json:"to"`
	DryRun    bool   `json:"dry_run"`
}

func handleSftpOp(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	// Parse and validate args BEFORE acquiring an SSH connection.
	var a sftpOpArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "cannot parse args: "+err.Error(), false)
	}

	if a.Action == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "action is required", false)
	}
	if a.Path == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "path is required", false)
	}

	// Validate action early (before connecting).
	switch a.Action {
	case "write", "mkdir", "remove", "rename", "chmod", "symlink":
		// These actions require an absolute path.
		if _, err := safety.ValidateRemotePath(a.Path); err != nil {
			return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
		}
	case "realpath":
		// realpath accepts relative paths — no ValidateRemotePath here.
	default:
		return envelope.Err(envelope.CodeInvalidArgument,
			fmt.Sprintf("unknown action %q; must be one of write, mkdir, remove, rename, chmod, symlink, realpath", a.Action),
			false)
	}

	// Additional per-action pre-validation before connecting.
	switch a.Action {
	case "write":
		if a.Encoding != "" && a.Encoding != "utf8" && a.Encoding != "base64" {
			return envelope.Err(envelope.CodeInvalidArgument, "encoding must be utf8 or base64", false)
		}
		if a.Encoding == "base64" {
			if _, err := base64.StdEncoding.DecodeString(a.Content); err != nil {
				return envelope.Err(envelope.CodeInvalidArgument, "base64 decode: "+err.Error(), false)
			}
		}
	case "chmod":
		if a.Mode == "" {
			return envelope.Err(envelope.CodeInvalidArgument, "mode is required for chmod", false)
		}
		if _, err := parseOctalMode(a.Mode, 0); err != nil {
			return envelope.Err(envelope.CodeInvalidArgument, "mode: "+err.Error(), false)
		}
	case "rename", "symlink":
		if a.To == "" {
			return envelope.Err(envelope.CodeInvalidArgument,
				fmt.Sprintf("to is required for %s", a.Action), false)
		}
		if _, err := safety.ValidateRemotePath(a.To); err != nil {
			return envelope.Err(envelope.CodeInvalidArgument, "to: "+err.Error(), false)
		}
	case "mkdir":
		if a.Mode != "" {
			if _, err := parseOctalMode(a.Mode, 0755); err != nil {
				return envelope.Err(envelope.CodeInvalidArgument, "mode: "+err.Error(), false)
			}
		}
	}

	// H01: enforce allowed_paths for named servers (inline = no restriction).
	// Performed after path validation but before connecting.
	{
		var connArgs sftpConnArgs
		_ = json.Unmarshal(args, &connArgs)
		serverName := ""
		if connArgs.Server != nil {
			serverName = *connArgs.Server
		}
		// Check primary path for actions that use an absolute path.
		if a.Action != "realpath" {
			rp, rpErr := safety.ValidateRemotePath(a.Path)
			if rpErr == nil { // already validated above; skip if somehow invalid
				if errResp, allowed := enforceAllowedPath(deps.Cfg, serverName, rp); !allowed {
					return errResp
				}
			}
		}
		// For rename: also check the destination path.
		if a.Action == "rename" && a.To != "" {
			toRP, rpErr := safety.ValidateRemotePath(a.To)
			if rpErr == nil {
				if errResp, allowed := enforceAllowedPath(deps.Cfg, serverName, toRP); !allowed {
					return errResp
				}
			}
		}
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

	switch a.Action {
	case "write":
		return sftpOpWrite(a, sftpClient, deps)
	case "mkdir":
		return sftpOpMkdir(a, sftpClient)
	case "remove":
		return sftpOpRemove(a, sftpClient)
	case "rename":
		return sftpOpRename(a, sftpClient)
	case "chmod":
		return sftpOpChmod(a, sftpClient)
	case "symlink":
		return sftpOpSymlink(a, sftpClient)
	case "realpath":
		return sftpOpRealpath(a, sftpClient)
	default:
		return envelope.Err(envelope.CodeInvalidArgument,
			fmt.Sprintf("unknown action %q; must be one of write, mkdir, remove, rename, chmod, symlink, realpath", a.Action),
			false)
	}
}

// --------------------------------------------------------------------------
// action: write
// --------------------------------------------------------------------------

func sftpOpWrite(a sftpOpArgs, sc *internalsftp.Client, deps *Deps) envelope.Response {
	rp, err := safety.ValidateRemotePath(a.Path)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}

	// Decode content.
	encoding := a.Encoding
	if encoding == "" {
		encoding = "utf8"
	}
	var data []byte
	switch encoding {
	case "base64":
		data, err = base64.StdEncoding.DecodeString(a.Content)
		if err != nil {
			return envelope.Err(envelope.CodeInvalidArgument, "base64 decode: "+err.Error(), false)
		}
	case "utf8":
		data = []byte(a.Content)
	default:
		return envelope.Err(envelope.CodeInvalidArgument, "encoding must be utf8 or base64", false)
	}

	// Parse mode; default 0644.
	mode, modeErr := parseOctalMode(a.Mode, 0644)
	if modeErr != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "mode: "+modeErr.Error(), false)
	}

	// Atomic defaults to true.
	atomic := true
	if a.Atomic != nil {
		atomic = *a.Atomic
	}

	// Progress callback.
	var progressCb func(written, total int64)
	threshold := int64(deps.Cfg.Settings.SftpProgressThresholdBytes)
	if threshold <= 0 {
		threshold = 10 * 1024 * 1024
	}
	if deps.Progress != nil && int64(len(data)) > threshold {
		progressCb = func(w, t int64) {
			deps.Progress(map[string]any{"bytes_written": w, "total": t})
		}
	}

	if err := sc.Write(rp, data, mode, atomic, progressCb); err != nil {
		return mapSFTPErr(err)
	}
	return envelope.OK(map[string]any{
		"bytes_written": len(data),
		"path":          rp.String(),
	})
}

// --------------------------------------------------------------------------
// action: mkdir
// --------------------------------------------------------------------------

func sftpOpMkdir(a sftpOpArgs, sc *internalsftp.Client) envelope.Response {
	rp, err := safety.ValidateRemotePath(a.Path)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}
	mode, modeErr := parseOctalMode(a.Mode, 0755)
	if modeErr != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "mode: "+modeErr.Error(), false)
	}
	if err := sc.Mkdir(rp, mode, a.Recursive); err != nil {
		return mapSFTPErr(err)
	}
	return envelope.OK(map[string]any{"created": true})
}

// --------------------------------------------------------------------------
// action: remove
// --------------------------------------------------------------------------

func sftpOpRemove(a sftpOpArgs, sc *internalsftp.Client) envelope.Response {
	rp, err := safety.ValidateRemotePath(a.Path)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}

	if a.DryRun {
		// Enumerate what would be removed without actually removing anything.
		removed, enumErr := enumerateForRemove(sc, rp, a.Recursive)
		if enumErr != nil {
			return mapSFTPErr(enumErr)
		}
		return envelope.OK(map[string]any{
			"removed":  removed,
			"dry_run":  true,
		})
	}

	// Collect paths before removal for reporting.
	removed, _ := enumerateForRemove(sc, rp, a.Recursive)

	if err := sc.Remove(rp, a.Recursive); err != nil {
		return mapSFTPErr(err)
	}
	return envelope.OK(map[string]any{
		"removed":  removed,
		"dry_run":  false,
	})
}

// enumerateForRemove returns the list of paths that would be affected.
func enumerateForRemove(sc *internalsftp.Client, rp safety.RemotePath, recursive bool) ([]string, error) {
	// Start with the root path.
	paths := []string{rp.String()}

	if !recursive {
		return paths, nil
	}

	// BFS to collect all children.
	queue := []safety.RemotePath{rp}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		entries, err := sc.List(cur)
		if err != nil {
			// May not be a directory; that's fine.
			continue
		}
		for _, e := range entries {
			paths = append(paths, e.Path)
			if e.IsDir {
				childRP, pathErr := safety.ValidateRemotePath(e.Path)
				if pathErr == nil {
					queue = append(queue, childRP)
				}
			}
		}
	}
	return paths, nil
}

// --------------------------------------------------------------------------
// action: rename
// --------------------------------------------------------------------------

func sftpOpRename(a sftpOpArgs, sc *internalsftp.Client) envelope.Response {
	from, err := safety.ValidateRemotePath(a.Path)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "path: "+err.Error(), false)
	}
	if a.To == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "to is required for rename", false)
	}
	to, err := safety.ValidateRemotePath(a.To)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "to: "+err.Error(), false)
	}
	if err := sc.Rename(from, to); err != nil {
		return mapSFTPErr(err)
	}
	return envelope.OK(map[string]any{
		"from": from.String(),
		"to":   to.String(),
	})
}

// --------------------------------------------------------------------------
// action: chmod
// --------------------------------------------------------------------------

func sftpOpChmod(a sftpOpArgs, sc *internalsftp.Client) envelope.Response {
	rp, err := safety.ValidateRemotePath(a.Path)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}
	if a.Mode == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "mode is required for chmod", false)
	}
	mode, modeErr := parseOctalMode(a.Mode, 0)
	if modeErr != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "mode: "+modeErr.Error(), false)
	}
	if err := sc.Chmod(rp, mode); err != nil {
		return mapSFTPErr(err)
	}
	return envelope.OK(map[string]any{
		"mode": fmt.Sprintf("%04o", uint32(mode)),
	})
}

// --------------------------------------------------------------------------
// action: symlink
// --------------------------------------------------------------------------

func sftpOpSymlink(a sftpOpArgs, sc *internalsftp.Client) envelope.Response {
	target, err := safety.ValidateRemotePath(a.Path)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "path: "+err.Error(), false)
	}
	if a.To == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "to is required for symlink (link path)", false)
	}
	linkPath, err := safety.ValidateRemotePath(a.To)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "to: "+err.Error(), false)
	}
	if err := sc.Symlink(target, linkPath); err != nil {
		return mapSFTPErr(err)
	}
	return envelope.OK(map[string]any{
		"target": target.String(),
		"link":   linkPath.String(),
	})
}

// --------------------------------------------------------------------------
// action: realpath
// --------------------------------------------------------------------------

func sftpOpRealpath(a sftpOpArgs, sc *internalsftp.Client) envelope.Response {
	// realpath accepts relative paths / ~ — do NOT ValidateRemotePath here.
	resolved, err := sc.Realpath(a.Path)
	if err != nil {
		return mapSFTPErr(err)
	}
	return envelope.OK(map[string]any{
		"resolved": resolved.String(),
	})
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// parseOctalMode parses an octal mode string. If s is empty, defaultMode is
// returned. Returns an error if s is non-empty but not a valid octal string.
func parseOctalMode(s string, defaultMode os.FileMode) (os.FileMode, error) {
	if s == "" {
		return defaultMode, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid octal mode %q: %w", s, err)
	}
	return os.FileMode(v), nil
}
