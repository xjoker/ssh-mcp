package main

// cli_install.go implements:
//   install claude-desktop
//   install claude-code
//   install codex
//
// S-10: generated snippets MUST NOT contain autoApprove for any
// mcp-ssh-bridge tool (ssh_exec, sftp_op, ssh_group_exec, etc.).
//
// Simplification (per SDD spec): all three variants print the recommended
// configuration snippet to stdout and show the target path. They do NOT
// merge or patch the target file, avoiding destructive mutations to existing
// client configurations.

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

func init() {
	registerSubcommand("install", installCmd)
}

// mcpServerEntry is the JSON shape for claude-desktop / claude-code MCP config.
// S-10: no autoApprove field — intentionally absent.
type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// mcpServersWrapper is the top-level JSON wrapper.
type mcpServersWrapper struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
}

// installCmd dispatches to a target-specific printer.
func installCmd(args []string) int {
	if len(args) == 0 {
		printInstallUsage()
		return 1
	}
	target := args[0]

	exePath, err := os.Executable()
	if err != nil {
		exePath = "/usr/local/bin/mcp-ssh-bridge"
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
}

// installClaudeDesktop prints the JSON snippet for Claude Desktop.
func installClaudeDesktop(exePath string) int {
	configPath := claudeDesktopConfigPath()

	entry := mcpServersWrapper{
		MCPServers: map[string]mcpServerEntry{
			"ssh-bridge": {
				Command: exePath,
				Args:    []string{},
			},
		},
	}
	// S-10: no autoApprove key in the struct or serialised output.
	out, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "install claude-desktop: marshal: %v\n", err)
		return 1
	}

	fmt.Printf("# Add this to: %s\n", configPath)
	fmt.Println("# WARNING: Do not add autoApprove for any of mcp-ssh-bridge tools.")
	fmt.Println("# The tools provided can have unbounded effects on remote systems.")
	fmt.Println()
	fmt.Println(string(out))
	return 0
}

// installClaudeCode prints the JSON snippet for Claude Code.
// The exact config path is undocumented in the SDD, so we print the snippet
// and instruct the user to paste it manually.
func installClaudeCode(exePath string) int {
	configPath := "~/.config/claude-code/mcp.json"

	entry := mcpServersWrapper{
		MCPServers: map[string]mcpServerEntry{
			"ssh-bridge": {
				Command: exePath,
				Args:    []string{},
			},
		},
	}
	out, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "install claude-code: marshal: %v\n", err)
		return 1
	}

	fmt.Printf("# Add this to: %s\n", configPath)
	fmt.Println("# (exact path may vary by Claude Code version; check your installation)")
	fmt.Println("# WARNING: Do not add autoApprove for any of mcp-ssh-bridge tools.")
	fmt.Println("# The tools provided can have unbounded effects on remote systems.")
	fmt.Println()
	fmt.Println(string(out))
	return 0
}

// installCodex prints the TOML snippet for Codex.
func installCodex(exePath string) int {
	fmt.Println("# Add this to your Codex configuration file.")
	fmt.Println("# WARNING: Do not add autoApprove for any of mcp-ssh-bridge tools.")
	fmt.Println("# The tools provided can have unbounded effects on remote systems.")
	fmt.Println()
	fmt.Printf("[mcp_servers.ssh-bridge]\n")
	fmt.Printf("command = %q\n", exePath)
	fmt.Printf("args = []\n")
	return 0
}

// claudeDesktopConfigPath returns the platform-appropriate path for the
// Claude Desktop configuration file.
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
