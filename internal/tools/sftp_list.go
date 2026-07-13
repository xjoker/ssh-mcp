// sftp_list implements the sftp_list MCP tool (SDD §6.5).
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/safety"
	internalsftp "github.com/xjoker/ssh-mcp/internal/sftp"
)

const (
	sftpListDefaultMaxEntries = 1000
	sftpListMaxEntries        = 10000
)

func init() {
	Registered = append(Registered, Tool{
		Name:        "sftp_list",
		Description: "List directory entries on a remote host with metadata. Supports recursive BFS traversal capped at max_entries.",
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "server":      { "type": "string", "description": "Configured server name" },
    "inline":      { "type": "object", "description": "Ad-hoc connection params (alternative to server)" },
    "path":        { "type": "string", "description": "Absolute remote path to list" },
    "recursive":   { "type": "boolean", "default": false },
    "max_entries": { "type": "integer", "default": 1000, "maximum": 10000 }
  },
  "required": ["path"]
}`),
		Handle: handleSftpList,
		Annotations: &Annotations{
			Title:           "List remote directory",
			ReadOnlyHint:    true,
			DestructiveHint: false,
			IdempotentHint:  false,
			OpenWorldHint:   true,
		},
	})
}

type sftpListArgs struct {
	Path       string `json:"path"`
	Recursive  bool   `json:"recursive"`
	MaxEntries int    `json:"max_entries"`
}

func handleSftpList(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	// Parse and validate args BEFORE acquiring an SSH connection.
	var a sftpListArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "cannot parse args: "+err.Error(), false)
	}

	if a.Path == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "path is required", false)
	}

	if _, err := safety.ValidateRemotePath(a.Path); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}

	maxEntries := a.MaxEntries
	if maxEntries <= 0 {
		maxEntries = sftpListDefaultMaxEntries
	}
	if maxEntries > sftpListMaxEntries {
		return envelope.Err(envelope.CodeInvalidArgument,
			fmt.Sprintf("max_entries exceeds %d limit", sftpListMaxEntries), false)
	}

	// extract server name for allowed_paths enforcement (inline = no restriction).
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

	// R2-C01: canonicalise through remote OS (follows symlinks) before
	// applying allowed_paths. Operate on the resolved path so a swap
	// between check and use cannot escape the policy.
	rp, errResp, ok := resolveAndCheckRemotePath(deps, serverName, sftpClient, a.Path, false)
	if !ok {
		return errResp
	}

	if !a.Recursive {
		entries, err := sftpClient.List(rp)
		if err != nil {
			return mapSFTPErr(err)
		}
		truncated := false
		if len(entries) > maxEntries {
			entries = entries[:maxEntries]
			truncated = true
		}
		return envelope.OK(map[string]any{
			"entries":   entries,
			"truncated": truncated,
		})
	}

	// BFS recursive traversal.
	var allEntries []internalsftp.Entry
	queue := []safety.RemotePath{rp}
	truncated := false

	for len(queue) > 0 && len(allEntries) < maxEntries {
		current := queue[0]
		queue = queue[1:]

		entries, listErr := sftpClient.List(current)
		if listErr != nil {
			// Skip unreadable dirs silently during recursive traversal.
			continue
		}

		for _, e := range entries {
			if len(allEntries) >= maxEntries {
				truncated = true
				break
			}
			allEntries = append(allEntries, e)
			if e.IsDir {
				childPath, pathErr := safety.ValidateRemotePath(e.Path)
				if pathErr == nil {
					queue = append(queue, childPath)
				}
			}
		}
	}

	if !truncated && len(queue) > 0 {
		truncated = true
	}

	return envelope.OK(map[string]any{
		"entries":   allEntries,
		"truncated": truncated,
	})
}
