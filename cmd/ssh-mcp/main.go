package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/mcpserver"
	"github.com/xjoker/ssh-mcp/internal/updater"
)

// version and commit are injected at build time via -ldflags. The default
// reflects the current development line: when no ldflags override is
// provided (e.g. plain `go build`), this is what `version` prints.
//
// Branch convention: -dev suffix on dev/feature branches; release builds
// from main strip the suffix via -X main.version=<tag>.
var (
	version = "0.0.1-dev"
	commit  = "unknown"
)

func main() {
	// If argv[1] matches a known subcommand, run in CLI mode.
	if len(os.Args) > 1 {
		if h, ok := lookupSubcommand(os.Args[1]); ok {
			os.Exit(h(os.Args[2:]))
		}
	}
	// Otherwise start the MCP server over stdio.
	runMCPServer()
}

// checkForUpdate does a best-effort version check with a short timeout.
// Returns a non-empty notice string when a newer release is available,
// or "" when up-to-date or when the check cannot complete in time.
func checkForUpdate() string {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	rel, err := updater.CheckLatest(ctx, strings.HasSuffix(version, "-dev"))
	if err != nil {
		return "" // silently ignore: offline, rate-limited, etc.
	}
	if !updater.IsNewer(version, rel.Version) {
		return ""
	}
	return fmt.Sprintf(
		"[ssh-mcp] Update available: %s (current: %s). Run: ssh-mcp update",
		rel.Version, version,
	)
}

func runMCPServer() {
	cfgPath := os.Getenv("MCP_SSH_BRIDGE_CONFIG")
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load: %v\n", err)
		os.Exit(1)
	}
	cfg.PrintPlaintextWarning()

	server, err := mcpserver.New(cfg, "", checkForUpdate(), version) // empty auditDir → use platform default
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcpserver: %v\n", err)
		os.Exit(1)
	}
	if err := server.RegisterAll(); err != nil {
		fmt.Fprintf(os.Stderr, "register: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	serveErr := server.Serve(ctx)

	// 5-second deadline shutdown (SDD §4.5).
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sCancel()
	_ = shutdownCtx

	if err := server.Shutdown(); err != nil {
		fmt.Fprintf(os.Stderr, "shutdown: %v\n", err)
		os.Exit(1)
	}

	if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
		fmt.Fprintf(os.Stderr, "serve: %v\n", serveErr)
		os.Exit(1)
	}
	os.Exit(0)
}
