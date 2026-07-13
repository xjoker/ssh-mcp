package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/tools"
)

const (
	permissionTierReadOnly = "read-only"
	permissionTierStandard = "standard"
)

var standardApprovalTools = map[string]struct{}{
	"ssh_exec":        {},
	"ssh_group_exec":  {},
	"sftp_op":         {},
	"session_start":   {},
	"session_send":    {},
	"session_close":   {},
	"ssh_quick_setup": {},
}

// readOnlyApprovalTools is intentionally explicit rather than derived from
// annotations: a newly registered tool must receive a separate security
// review before this command starts recommending it for automatic approval.
var readOnlyApprovalTools = map[string]struct{}{
	"audit_query":  {},
	"list_servers": {},
	"sftp_list":    {},
	"sftp_read":    {},
	"sftp_stat":    {},
}

func init() { registerSubcommand("permissions", permissionsCmd) }

func permissionsCmd(args []string) int {
	if len(args) == 0 {
		printPermissionsUsage()
		return 1
	}

	target := args[0]
	flags := flag.NewFlagSet("permissions", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tier := flags.String("tier", permissionTierReadOnly, "approval tier: read-only or standard")
	serverName := flags.String("server-name", "ssh-bridge", "MCP server name configured in the client")
	flags.Usage = printPermissionsUsage
	if err := flags.Parse(args[1:]); err != nil {
		return 1
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return 1
	}
	if target != "claude-code" && target != "codex" {
		fmt.Fprintf(os.Stderr, "permissions: unknown target %q (valid: claude-code, codex)\n", target)
		return 1
	}
	if *tier != permissionTierReadOnly && *tier != permissionTierStandard {
		fmt.Fprintf(os.Stderr, "permissions: unknown tier %q (valid: read-only, standard)\n", *tier)
		return 1
	}
	if err := config.ValidateServerName(*serverName); err != nil {
		fmt.Fprintf(os.Stderr, "permissions: invalid server name: %v\n", err)
		return 1
	}

	names, err := recommendedApprovalTools(*tier)
	if err != nil {
		fmt.Fprintf(os.Stderr, "permissions: %v\n", err)
		return 1
	}
	switch target {
	case "claude-code":
		return printClaudeCodePermissions(*serverName, names)
	case "codex":
		return printCodexPermissions(*serverName, names)
	default:
		panic("validated permissions target reached unreachable branch")
	}
}

func printPermissionsUsage() {
	fmt.Fprintln(os.Stderr, "usage: ssh-mcp permissions <claude-code|codex> [--tier read-only|standard] [--server-name name]")
	fmt.Fprintln(os.Stderr, "  Prints a configuration fragment; it never edits client configuration.")
	fmt.Fprintln(os.Stderr, "  read-only (default): auto-approve tools whose MCP annotation is read-only.")
	fmt.Fprintln(os.Stderr, "  standard: also auto-approve reversible command/session tools; Tier 3 always prompts.")
}

func recommendedApprovalTools(tier string) ([]string, error) {
	names := make([]string, 0, len(tools.All()))
	registered := make(map[string]tools.Tool, len(tools.All()))
	for _, tool := range tools.All() {
		registered[tool.Name] = tool
		_, readOnly := readOnlyApprovalTools[tool.Name]
		_, standard := standardApprovalTools[tool.Name]
		if readOnly || (tier == permissionTierStandard && standard) {
			names = append(names, tool.Name)
		}
	}
	for name := range readOnlyApprovalTools {
		tool, ok := registered[name]
		if !ok {
			return nil, fmt.Errorf("approved read-only tool %q is not registered", name)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			return nil, fmt.Errorf("approved read-only tool %q lacks ReadOnlyHint", name)
		}
	}
	if tier == permissionTierStandard {
		for name := range standardApprovalTools {
			if _, ok := registered[name]; !ok {
				return nil, fmt.Errorf("approved standard tool %q is not registered", name)
			}
		}
	}
	sort.Strings(names)
	return names, nil
}

func printClaudeCodePermissions(serverName string, names []string) int {
	allow := make([]string, len(names))
	for i, name := range names {
		allow[i] = "mcp__" + serverName + "__" + name
	}
	payload := struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}{}
	payload.Permissions.Allow = allow

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintf(os.Stderr, "permissions: encode Claude Code fragment: %v\n", err)
		return 1
	}
	return 0
}

func printCodexPermissions(serverName string, names []string) int {
	fmt.Println("# Merge these entries into ~/.codex/config.toml.")
	fmt.Println("# Keep the server default at prompt; only the tools below use auto approval.")
	fmt.Printf("[mcp_servers.%s]\n", serverName)
	fmt.Println(`default_tools_approval_mode = "prompt"`)
	for _, name := range names {
		fmt.Println()
		fmt.Printf("[mcp_servers.%s.tools.%s]\n", serverName, name)
		fmt.Println(`approval_mode = "auto"`)
	}
	return 0
}
