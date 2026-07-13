// Per-server command policy wiring. SDD: docs/design/command-policy.md.
//
// internal/safety/policy.go is a pure engine that knows nothing about
// config.Config. This file bridges the two: given a Deps + server name it
// resolves the ServerConfig and compiles a *safety.Policy.
package tools

import "github.com/xjoker/ssh-mcp/internal/safety"

// PolicyForServer resolves and compiles the per-server command policy for
// name (docs/design/command-policy.md §4). Returns (nil, nil) when the
// server has no policy in effect:
//   - mode is "" / "unrestricted" (safety.CompilePolicy itself returns nil
//     for these — the zero-overhead path);
//   - name does not resolve to a static config.Servers entry at all. This
//     covers quick_setup temp servers (registered only in the SSH pool,
//     never in Cfg.Servers) and inline ad-hoc credentials (which have no
//     "server" name to look up in the first place) — both are unaffected
//     by command policy, matching pre-policy behaviour.
//
// config.Load already validates AllowPatterns/DenyPatterns as compilable
// regexes before a config is accepted, so a non-nil error here indicates
// a runtime invariant violation, not a user input error; callers should
// treat it as INTERNAL_ERROR.
//
// Patterns are compiled fresh on every call rather than cached: the built-in
// readonly allowlist is already a package-level precompiled var in
// internal/safety, so the only per-call cost is compiling the (typically
// small) user-authored allow/deny lists — cheap, and it keeps this function
// correct for free if config is ever hot-reloaded.
func PolicyForServer(deps *Deps, name string) (*safety.Policy, error) {
	if deps == nil || deps.Cfg == nil || name == "" {
		return nil, nil
	}
	srv, ok := deps.Cfg.Servers[name]
	if !ok {
		return nil, nil
	}
	return safety.CompilePolicy(srv.Mode, srv.AllowPatterns, srv.DenyPatterns)
}
