package main

import (
	"fmt"
	"runtime"
)

func init() { registerSubcommand("version", versionCmd) }

func versionCmd(_ []string) int {
	fmt.Printf("mcp-ssh-bridge %s (commit %s)\n", version, commit)
	fmt.Printf("Go %s\n", runtimeVersion())
	return 0
}

func runtimeVersion() string { return runtime.Version() }
