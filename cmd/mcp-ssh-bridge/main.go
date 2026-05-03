package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/config"
	"github.com/xjoker/mcp-ssh-bridge/internal/mcpserver"
)

// version and commit are injected at build time via -ldflags.
var (
	version = "dev"
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

	server, err := mcpserver.New(cfg, "") // empty auditDir → use platform default
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
