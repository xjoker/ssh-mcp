// Package tools provides the MCP tool layer for mcp-ssh-bridge.
// Each tool file registers itself via init(); call All() to retrieve
// the full list for wiring into the MCP server.
package tools

// Registered is the global list of tools, populated by each tool file's init().
// D2 and D3 spokes append to this slice in their own init() functions.
var Registered []Tool

// All returns all registered tools.
func All() []Tool { return Registered }
