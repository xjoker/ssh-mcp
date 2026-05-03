// sftp_stat implements the sftp_stat MCP tool (SDD §6.7).
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
		Name:        "sftp_stat",
		Description: "Get metadata for a single remote path (follows symlinks; reports symlink info via is_link/link_to).",
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "server": { "type": "string" },
    "inline": { "type": "object" },
    "path":   { "type": "string", "description": "Absolute remote path" }
  },
  "required": ["path"]
}`),
		Handle: handleSftpStat,
	})
}

type sftpStatArgs struct {
	Path string `json:"path"`
}

func handleSftpStat(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	// Parse and validate args BEFORE acquiring an SSH connection.
	var a sftpStatArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "cannot parse args: "+err.Error(), false)
	}

	if a.Path == "" {
		return envelope.Err(envelope.CodeInvalidArgument, "path is required", false)
	}
	if _, err := safety.ValidateRemotePath(a.Path); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}
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

	// R2-C01: canonicalise then enforce allowed_paths.
	rp, errResp, ok := resolveAndCheckRemotePath(deps, serverName, sftpClient, a.Path, false)
	if !ok {
		return errResp
	}

	entry, err := sftpClient.Stat(rp)
	if err != nil {
		return mapSFTPErr(err)
	}

	return envelope.OK(entry)
}
