// sftp_list implements the sftp_list MCP tool (SDD §6.5).
package tools

import (
	"context"
	"encoding/json"

	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	internalsftp "github.com/xjoker/mcp-ssh-bridge/internal/sftp"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
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

	rp, err := safety.ValidateRemotePath(a.Path)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}

	client, closeFn, errResp, ok := resolveClient(ctx, deps, args)
	if !ok {
		return errResp
	}
	defer closeFn()

	maxEntries := a.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 1000
	}

	sftpClient, err := internalsftp.New(client.Underlying())
	if err != nil {
		return envelope.Err(envelope.CodeSftpError, "sftp subsystem: "+err.Error(), false)
	}
	defer sftpClient.Close()

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
