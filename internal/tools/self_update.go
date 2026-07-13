// Package tools — self_update tool.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/updater"
)

func init() {
	Registered = append(Registered, toolSelfUpdate())
}

// --------------------------------------------------------------------------
// Input / output types
// --------------------------------------------------------------------------

type selfUpdateInput struct {
	// CheckOnly skips the download and only reports whether a newer version exists.
	CheckOnly bool `json:"check_only,omitempty"`
}

type selfUpdateOutput struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Updated        bool   `json:"updated"`
	Message        string `json:"message"`
}

// --------------------------------------------------------------------------
// Schema
// --------------------------------------------------------------------------

var selfUpdateSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "check_only": {
      "type": "boolean",
      "description": "If true, only check whether a newer version is available without downloading. Default false."
    }
  }
}`)

// --------------------------------------------------------------------------
// Tool descriptor
// --------------------------------------------------------------------------

func toolSelfUpdate() Tool {
	return Tool{
		Name: "self_update",
		Description: "Check for a newer ssh-mcp release and optionally download and install it. " +
			"After a successful update the MCP server process must be restarted to run the new binary. " +
			"Use check_only=true to inspect availability without downloading. " +
			"Replaces the running binary.",
		InputSchema: selfUpdateSchema,
		Handle:      handleSelfUpdate,
		Annotations: &Annotations{
			Title:           "Update ssh-mcp binary",
			ReadOnlyHint:    false,
			DestructiveHint: true,
			IdempotentHint:  false,
			OpenWorldHint:   true,
		},
	}
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

func handleSelfUpdate(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	var input selfUpdateInput
	if len(args) > 0 {
		if err := json.Unmarshal(args, &input); err != nil {
			return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
		}
	}

	current := deps.Version
	if current == "" {
		current = "dev"
	}

	// Dev builds include pre-releases so users on -dev can receive dev updates.
	// Match any version containing "-dev" (e.g. "0.0.1-dev.20260506.1").
	includePrerelease := strings.Contains(current, "-dev")

	rel, err := updater.CheckLatest(ctx, includePrerelease)
	if err != nil {
		return envelope.Err("UPDATE_CHECK_FAILED",
			fmt.Sprintf("failed to check for updates: %v", err), true)
	}

	if !updater.IsNewer(current, rel.Version) {
		return envelope.OK(selfUpdateOutput{
			CurrentVersion: current,
			LatestVersion:  rel.Version,
			Updated:        false,
			Message:        fmt.Sprintf("Already up to date (%s).", current),
		})
	}

	if input.CheckOnly {
		return envelope.OK(selfUpdateOutput{
			CurrentVersion: current,
			LatestVersion:  rel.Version,
			Updated:        false,
			Message:        fmt.Sprintf("New version available: %s → %s. Run without check_only=true to install.", current, rel.Version),
		})
	}

	exePath, err := os.Executable()
	if err != nil {
		return envelope.Err("UPDATE_FAILED",
			fmt.Sprintf("cannot resolve binary path: %v", err), false)
	}

	if err := updater.Download(ctx, rel, exePath); err != nil {
		return envelope.Err("UPDATE_FAILED",
			fmt.Sprintf("download failed: %v", err), true)
	}

	return envelope.OK(selfUpdateOutput{
		CurrentVersion: current,
		LatestVersion:  rel.Version,
		Updated:        true,
		Message:        fmt.Sprintf("Updated to %s. Please restart the MCP server to apply the new binary.", rel.Version),
	})
}
