package main

// cli_install.go implements the `install` subcommand. Both Claude Code and
// Codex now ship official CLI commands for managing MCP servers, so the
// preferred path is to run those CLIs directly. We print the exact command
// for each target rather than emitting a JSON snippet that the user has to
// paste into the right config file.
//
// S-10: nothing we emit ever sets autoApprove. Both client CLIs honour
// the absence of that flag and require per-call human confirmation, which
// is the security posture we ship.

import (
	"fmt"
	"os"
	"runtime"
)

func init() {
	registerSubcommand("install", installCmd)
}

func installCmd(args []string) int {
	if len(args) == 0 {
		printInstallUsage()
		return 1
	}
	target := args[0]

	exePath, err := os.Executable()
	if err != nil {
		exePath = defaultBinaryPath()
	}

	switch target {
	case "claude-desktop":
		return installClaudeDesktop(exePath)
	case "claude-code":
		return installClaudeCode(exePath)
	case "codex":
		return installCodex(exePath)
	default:
		fmt.Fprintf(os.Stderr, "install: unknown target %q (valid: claude-desktop, claude-code, codex)\n", target)
		printInstallUsage()
		return 1
	}
}

func printInstallUsage() {
	fmt.Fprintln(os.Stderr, "usage: mcp-ssh-bridge install <target>")
	fmt.Fprintln(os.Stderr, "  Targets: claude-desktop  claude-code  codex")
	fmt.Fprintln(os.Stderr, "  Prints the official CLI command (or JSON/TOML snippet) to register")
	fmt.Fprintln(os.Stderr, "  this binary as an MCP server with the given client.")
}

// installClaudeDesktop prints the JSON snippet for Claude Desktop.
// Claude Desktop does not yet ship a `claude-desktop mcp add` CLI, so the
// snippet must be pasted manually. The path printed is the platform-default
// claude_desktop_config.json location.
func installClaudeDesktop(exePath string) int {
	configPath := claudeDesktopConfigPath()

	fmt.Printf("# Claude Desktop has no MCP-management CLI; paste this block manually.\n")
	fmt.Printf("# Edit: %s\n", configPath)
	fmt.Println("# WARNING: Do not add autoApprove for any of mcp-ssh-bridge tools.")
	fmt.Println()
	fmt.Println("{")
	fmt.Println(`  "mcpServers": {`)
	fmt.Println(`    "ssh-bridge": {`)
	fmt.Printf("      \"command\": %q,\n", exePath)
	fmt.Println(`      "args": []`)
	fmt.Println("    }")
	fmt.Println("  }")
	fmt.Println("}")
	return 0
}

// installClaudeCode prints the official `claude mcp add` command.
// Claude Code stores user-scoped MCP servers in ~/.claude.json under the
// top-level `mcpServers` key; the CLI handles that for us so we don't
// hard-code the path.
func installClaudeCode(exePath string) int {
	fmt.Println("# Claude Code ships an MCP-management CLI. Run this once:")
	fmt.Println()
	fmt.Printf("claude mcp add --transport stdio --scope user ssh-bridge -- %s\n", exePath)
	fmt.Println()
	fmt.Println("# Then verify with:")
	fmt.Println("claude mcp list")
	fmt.Println()
	fmt.Println("# Remove later with:")
	fmt.Println("claude mcp remove ssh-bridge")
	fmt.Println()
	fmt.Println("# WARNING: Do not add autoApprove for any of mcp-ssh-bridge tools.")
	return 0
}

// installCodex prints the official `codex mcp add` command.
// Codex stores MCP servers in ~/.codex/config.toml under
// [mcp_servers.<name>]; the CLI manages the file for us.
func installCodex(exePath string) int {
	fmt.Println("# Codex ships an MCP-management CLI. Run this once:")
	fmt.Println()
	fmt.Printf("codex mcp add ssh-bridge -- %s\n", exePath)
	fmt.Println()
	fmt.Println("# Then verify with:")
	fmt.Println("codex mcp list")
	fmt.Println()
	fmt.Println("# Remove later with:")
	fmt.Println("codex mcp remove ssh-bridge")
	fmt.Println()
	fmt.Println("# WARNING: Do not add autoApprove for any of mcp-ssh-bridge tools.")
	return 0
}

// claudeDesktopConfigPath returns the platform-appropriate path for the
// Claude Desktop configuration file (used only for the manual-paste
// fallback; Claude Code is handled by `claude mcp add`).
func claudeDesktopConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		return appData + `\Claude\claude_desktop_config.json`
	case "darwin":
		home, _ := os.UserHomeDir()
		return home + "/Library/Application Support/Claude/claude_desktop_config.json"
	default: // Linux / other
		home, _ := os.UserHomeDir()
		return home + "/.config/Claude/claude_desktop_config.json"
	}
}

// defaultBinaryPath returns the user-level install path the install
// scripts use. Only consulted if os.Executable() fails (rare).
func defaultBinaryPath() string {
	switch runtime.GOOS {
	case "windows":
		return os.Getenv("LOCALAPPDATA") + `\Programs\mcp-ssh-bridge\mcp-ssh-bridge.exe`
	default:
		home, _ := os.UserHomeDir()
		return home + "/.local/bin/mcp-ssh-bridge"
	}
}
