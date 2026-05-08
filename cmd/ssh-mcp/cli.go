package main

// SubcommandHandler accepts remaining argv and returns an exit code.
type SubcommandHandler func(args []string) int

// subcommands is the package-level registry. cli_*.go files register entries
// via init() so that the dispatcher in main.go can locate them.
var subcommands = map[string]SubcommandHandler{}

// registerSubcommand registers a top-level subcommand name (e.g. "trust",
// "server", "auth", "audit", "config", "migrate-from-legacy",
// "migrate-passwords", "install", "version"). Called from cli_*.go init().
func registerSubcommand(name string, h SubcommandHandler) {
	subcommands[name] = h
}

// lookupSubcommand returns the handler for the given name and a boolean
// indicating whether the name was found.
func lookupSubcommand(name string) (SubcommandHandler, bool) {
	h, ok := subcommands[name]
	return h, ok
}
