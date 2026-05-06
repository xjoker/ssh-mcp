// Package mcpserver bootstraps and runs the MCP server process.
// SDD §4.1–§4.5.
package mcpserver

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xjoker/ssh-mcp/internal/audit"
	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/session"
	sshpkg "github.com/xjoker/ssh-mcp/internal/ssh"
	"github.com/xjoker/ssh-mcp/internal/tools"
	"github.com/xjoker/ssh-mcp/internal/tunnel"
)

// stderrWriter is used by dispatch.go for runtime error logging.
// Exposed as a package-level var so tests can inject a replacement.
var stderrWriter io.Writer = os.Stderr

// Server is the top-level orchestrator that wires together all subsystems and
// runs the MCP stdio server.
type Server struct {
	cfg        *config.Config
	pool       *sshpkg.Pool
	sessionMgr *session.Manager
	tunnelMgr  *tunnel.Manager
	auditLog   *audit.Logger
	quickSetup *quickSetupRegistry
	deps       *tools.Deps

	mcpSrv *mcp.Server
	cancel context.CancelFunc
}

// New creates a Server, initialising all subsystems.
// auditDir overrides the default audit log directory (empty = use platform default).
// updateNotice, if non-empty, is injected into the MCP server instructions so
// connected clients (e.g. Claude Code) can display an update prompt.
// ver is the binary version string (e.g. "0.0.1-dev"), injected via ldflags.
func New(cfg *config.Config, auditDir, updateNotice, ver string) (*Server, error) {
	// 1. Audit logger.
	if auditDir == "" {
		auditDir = defaultAuditDir()
	}
	auditLog, err := audit.New(auditDir, cfg.Settings.AuditRetentionDays)
	if err != nil {
		return nil, fmt.Errorf("mcpserver.New: open audit log: %w", err)
	}

	// Health-check write (SDD §13 S-5): if we cannot write to the audit log
	// at startup, refuse to start.
	if err := auditLog.Record(audit.Entry{
		Timestamp: time.Now().UTC(),
		Tool:      "startup",
		Server:    "",
	}); err != nil {
		_ = auditLog.Close()
		return nil, fmt.Errorf("mcpserver.New: audit health-check failed: %w", err)
	}

	// 2. SSH pool first (no temp servers yet) so the QuickSetup registry
	//    can hold a reference for evict-callback. We construct credResolver
	//    with a back-reference; both circular fields are filled in below.
	resolver := &credResolver{
		allowPlaintext: cfg.Settings.AllowConfigPlaintextPassword,
	}
	pool := sshpkg.NewPool(cfg, resolver)

	// 3. QuickSetup registry. R2-C02: pass the static server name set so
	//    quick_setup cannot allocate a name that shadows a configured
	//    server, and wire onEvict → Pool.RemoveTempServer so a TTL-
	//    expired entry doesn't linger in the pool and keep masking the
	//    real server name.
	staticNames := make(map[string]struct{}, len(cfg.Servers))
	for n := range cfg.Servers {
		staticNames[n] = struct{}{}
	}
	qs := newQuickSetupRegistry(staticNames, pool.RemoveTempServer)
	resolver.quickSetup = qs

	// 4. Session manager.
	transport := &sshTransport{pool: pool}
	idleTimeout := time.Duration(cfg.Settings.SessionIdleSeconds) * time.Second
	sessionMgr := session.NewManagerWithLimit(transport, idleTimeout, cfg.Settings.MaxSessions)

	// 5. Tunnel manager.
	dialer := &sshDialer{pool: pool}
	tunnelMgr := tunnel.NewManager(dialer)

	// 6. Assemble tools.Deps.
	deps := &tools.Deps{
		Cfg:            cfg,
		Pool:           pool,
		SessionMgr:     sessionMgr,
		TunnelMgr:      tunnelMgr,
		Audit:          auditLog,
		QuickSetup:     qs,
		AllowPlaintext: cfg.Settings.AllowConfigPlaintextPassword,
		// Elicit and Progress are injected per-request by dispatch.go.
	}

	// 7. MCP SDK server.
	var srvOpts *mcp.ServerOptions
	if updateNotice != "" {
		srvOpts = &mcp.ServerOptions{Instructions: updateNotice}
	}
	if ver == "" {
		ver = "dev"
	}
	mcpSrv := mcp.NewServer(
		&mcp.Implementation{
			Name:    "ssh-mcp",
			Version: ver,
		},
		srvOpts,
	)

	s := &Server{
		cfg:        cfg,
		pool:       pool,
		sessionMgr: sessionMgr,
		tunnelMgr:  tunnelMgr,
		auditLog:   auditLog,
		quickSetup: qs,
		deps:       deps,
		mcpSrv:     mcpSrv,
	}
	return s, nil
}

// RegisterAll registers all tools from tools.All() with the MCP SDK server.
// Must be called before Serve.
func (s *Server) RegisterAll() error {
	return registerAll(s.mcpSrv, s.deps)
}

// Serve runs the MCP server over stdio, blocking until ctx is cancelled or
// the client disconnects. It sets s.cancel so Shutdown() can cancel in-flight
// requests.
//
// Serve also launches the connection reaper goroutine (SDD §12.3) which
// periodically closes idle SSH pool entries. The goroutine is bound to ctx
// and exits when ctx is cancelled (i.e. on Shutdown).
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	defer cancel()

	// Start the connection idle reaper. SDD §12.3.
	go s.runConnReaper(ctx)

	return s.mcpSrv.Run(ctx, &mcp.StdioTransport{})
}

// runConnReaper ticks every 60 seconds and closes pool entries that have been
// idle for longer than ConnIdleSeconds. The goroutine exits when ctx is done.
func (s *Server) runConnReaper(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	idleSecs := s.cfg.Settings.ConnIdleSeconds
	if idleSecs <= 0 {
		idleSecs = 600 // fallback to 10 minutes if not configured
	}
	threshold := time.Duration(idleSecs) * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pool.CloseIdle(threshold)
		}
	}
}

// Shutdown performs an orderly shutdown. SDD §4.5:
//  1. Cancel in-flight requests via context.
//  2. Close sessions.
//  3. Close tunnels.
//  4. Close pool.
//  5. Close audit log.
//  6. Stop quickSetup reaper.
//
// A 5-second deadline is applied; once exceeded the function returns regardless.
func (s *Server) Shutdown() error {
	done := make(chan error, 1)
	go func() {
		done <- s.shutdownInner()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		fmt.Fprintln(stderrWriter, "mcpserver: Shutdown: 5-second deadline exceeded, forcing exit")
		return fmt.Errorf("mcpserver: shutdown timed out")
	}
}

func (s *Server) shutdownInner() error {
	// 1. Cancel in-flight contexts.
	if s.cancel != nil {
		s.cancel()
	}

	// 2. Sessions.
	if s.sessionMgr != nil {
		s.sessionMgr.CloseAll()
	}

	// 3. Tunnels.
	if s.tunnelMgr != nil {
		s.tunnelMgr.CloseAll()
	}

	// 4. SSH pool.
	if s.pool != nil {
		_ = s.pool.Close()
	}

	// 5. Audit log.
	var auditErr error
	if s.auditLog != nil {
		auditErr = s.auditLog.Close()
	}

	// 6. QuickSetup reaper.
	if s.quickSetup != nil {
		s.quickSetup.Close()
	}

	return auditErr
}

// --------------------------------------------------------------------------
// Platform-specific audit directory
// --------------------------------------------------------------------------

// defaultAuditDir returns the platform-appropriate directory for audit logs.
// SDD §9.5.
func defaultAuditDir() string {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		return appData + `\ssh-mcp\audit`
	default:
		// macOS / Linux: use XDG_STATE_HOME or ~/.local/state
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "/tmp/ssh-mcp/audit"
			}
			stateHome = home + "/.local/state"
		}
		return stateHome + "/ssh-mcp"
	}
}
