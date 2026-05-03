// sftp_read implements the sftp_read MCP tool (SDD §6.6).
package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"unicode/utf8"

	"github.com/xjoker/mcp-ssh-bridge/internal/envelope"
	internalsftp "github.com/xjoker/mcp-ssh-bridge/internal/sftp"
	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
)

const sftpReadMaxBytes = 16 * 1024 * 1024 // 16 MiB

func init() {
	Registered = append(Registered, Tool{
		Name:        "sftp_read",
		Description: "Read a remote file (or a byte range). Supports partial reads via offset/length. Use encoding=base64 for binary files.",
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "server":   { "type": "string" },
    "inline":   { "type": "object" },
    "path":     { "type": "string", "description": "Absolute remote path" },
    "offset":   { "type": "integer", "default": 0, "description": "Byte offset; negative counts from EOF" },
    "length":   { "type": "integer", "minimum": 1, "maximum": 16777216, "default": 65536 },
    "encoding": { "type": "string", "enum": ["utf8", "base64"], "default": "utf8" }
  },
  "required": ["path"]
}`),
		Handle: handleSftpRead,
	})
}

type sftpReadArgs struct {
	Path     string `json:"path"`
	Offset   int64  `json:"offset"`
	Length   int64  `json:"length"`
	Encoding string `json:"encoding"`
}

func handleSftpRead(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	// Parse and validate args BEFORE acquiring an SSH connection.
	var a sftpReadArgs
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

	// Apply defaults.
	length := a.Length
	if length == 0 {
		length = 65536
	}
	if length > sftpReadMaxBytes {
		return envelope.Err(envelope.CodeInvalidArgument,
			"length exceeds 16 MiB limit", false)
	}

	encoding := a.Encoding
	if encoding == "" {
		encoding = "utf8"
	}
	if encoding != "utf8" && encoding != "base64" {
		return envelope.Err(envelope.CodeInvalidArgument,
			"encoding must be utf8 or base64", false)
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

	// Get file size via Stat.
	statEntry, err := sftpClient.Stat(rp)
	if err != nil {
		return mapSFTPErr(err)
	}
	fileSize := statEntry.Size

	// Build progress callback if file is large enough.
	var progressCb func(read, total int64)
	threshold := int64(deps.Cfg.Settings.SftpProgressThresholdBytes)
	if threshold <= 0 {
		threshold = 10 * 1024 * 1024
	}
	if deps.Progress != nil && length > threshold {
		progressCb = func(r, t int64) {
			deps.Progress(map[string]any{"bytes_read": r, "total": t})
		}
	}

	data, err := sftpClient.Read(rp, a.Offset, length, progressCb)
	if err != nil {
		return mapSFTPErr(err)
	}

	bytesRead := int64(len(data))

	var content string
	switch encoding {
	case "base64":
		content = base64.StdEncoding.EncodeToString(data)
	default: // utf8
		if !utf8.Valid(data) {
			return envelope.ErrWithHint(
				envelope.CodeInvalidArgument,
				"file content is not valid UTF-8",
				"retry with encoding=base64 for binary files",
				false,
			)
		}
		content = string(data)
	}

	return envelope.OK(map[string]any{
		"content":           content,
		"encoding":          encoding,
		"bytes_read":        bytesRead,
		"file_size":         fileSize,
		"is_truncated_view": bytesRead < fileSize,
	})
}
