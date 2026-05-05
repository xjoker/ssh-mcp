package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/updater"
)

func init() { registerSubcommand("update", updateCmd) }

func updateCmd(_ []string) int {
	fmt.Printf("mcp-ssh-bridge %s — checking for updates...\n", version)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Dev builds also check pre-releases so users on -dev can receive dev updates.
	rel, err := updater.CheckLatest(ctx, strings.HasSuffix(version, "-dev"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 1
	}

	if !updater.IsNewer(version, rel.Version) {
		fmt.Printf("Already up to date (%s).\n", version)
		return 0
	}

	fmt.Printf("New version available: %s → %s\n", version, rel.Version)

	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: resolve binary path: %v\n", err)
		return 1
	}

	fmt.Printf("Downloading %s...\n", rel.TagName)
	if err := updater.Download(ctx, rel, exePath); err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 1
	}

	fmt.Printf("Updated to %s. Restart the MCP server to apply.\n", rel.Version)
	return 0
}
