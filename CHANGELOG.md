# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Branch / version convention:
- Development happens on `dev`; releases are tagged on `main`.
- Dev versions carry a `-dev` suffix (e.g. `0.0.1-dev`); release versions
  drop the suffix (`0.0.1`). `make release VERSION=…` stamps the binary.

## [Unreleased]

### Added
- New `ssh_persistent_setup` tool: appends a `[servers.<name>]` block to
  `config.toml` so the entry survives restart and has no TTL. Plaintext
  password storage is gated by `settings.allow_config_plaintext_password`;
  validation failure restores the original file (atomic temp + rename).
  The new entry is also live in the current MCP session via
  `Pool.AddTempServer` with zero expiry — no restart required.
- `session_start` now accepts `pty: true` with optional `cols`, `rows`, `command`, and `init_wait_ms` parameters to open a PTY-backed interactive session (e.g. btop, htop, ncdu). Returns `mode: "pty"` and `initial_output` with the shell/command banner.
- `session_send` in PTY mode uses time-based output collection (`timeout_ms`) instead of the sentinel protocol. Supports `strip_ansi: true` to remove ANSI escape sequences.
- PTY sessions support interactive programs: send Ctrl-C as `"\x03"` to terminate TUI programs.

### Changed
- `ssh_quick_setup` description rewritten to drop the misleading
  "Prompts the user to confirm before registering" claim (the bridge
  itself never issued an MCP elicitation) and instead documents the
  TTL ceiling, the `host+port+user` dedup, and points at
  `ssh_persistent_setup` for long-lived registrations.
- README + README_zh: new *Why does Claude Code prompt every time?*
  section explaining that per-call confirmations come from the client's
  permission UI (not the bridge); `permissions.allow` examples now
  include `ssh_quick_setup` and `ssh_persistent_setup`.

### Fixed
- Regression tests for the b1201c7 dedup behaviour
  (`TestQuickSetupRegistry_ReuseSameHostPortUser`,
  `TestQuickSetupRegistry_DistinctTuplesGetDistinctNames`) lock in that
  repeated `ssh_quick_setup` calls for the same host/port/user reuse the
  existing registration, while differing tuples allocate distinct names.
- `quickSetupRegistry.Register` now documents that `r.mu` must remain a
  full `sync.Mutex` (not RWMutex) because the dedup scan and allocation
  share the same critical section.

### Changed
- Installers default to **user-level** install (no sudo / admin):
  `~/.local/bin/ssh-mcp` on macOS/Linux,
  `%LOCALAPPDATA%\Programs\ssh-mcp\ssh-mcp.exe` on Windows.
- New `scripts/install.ps1` for Windows (PowerShell one-liner).
- `ssh-mcp install claude-code` and `install codex` now print the
  official client-side CLI command (`claude mcp add ...` /
  `codex mcp add ...`) instead of a JSON/TOML snippet — those clients
  ship MCP-management CLIs as of late 2025/early 2026, and using them is
  safer than hand-editing `~/.claude.json` / `~/.codex/config.toml`.
- `install claude-desktop` still prints a JSON snippet (Claude Desktop
  has no MCP CLI yet); the snippet uses the user-level binary path.
- README + `examples/quick-start.md` updated with three-platform install
  paths, PowerShell snippet, and the official `claude mcp add` /
  `codex mcp add` registration commands.
- `scripts/quick-setup.sh` calls `claude mcp add` / `codex mcp add`
  directly when those CLIs are on PATH.

### Fixed
- `scripts/install.sh` repo URL corrected (`xjoker/ssh-mcp`).
- `cli_install.go` no longer prints the obsolete
  `~/.config/claude-code/mcp.json` path; Claude Code reads
  `~/.claude.json` and we no longer assert any specific path.

## [0.0.1-dev] — 2026-05-04

First public iteration. Targeted at internal smoke testing prior to the
`0.0.1` cut.

### Added
- MCP server with `ssh_exec`, `ssh_group_exec`, `sftp_op`, `sftp_list`,
  `sftp_read`, `sftp_stat`, `tunnel`, `session_*`, `ssh_quick_setup`,
  `list_servers`, `audit_query`.
- Append-only JSONL audit log with retention + read-only query path
  (`audit.NewReader`).
- OS keychain integration (macOS Keychain, libsecret, Windows Credential
  Manager) with fail-closed plaintext-password rejection.
- Persistent shell sessions with sentinel-based completion + concurrency
  cap (`settings.max_sessions`, default 16).
- Quick setup ad-hoc server registration with TTL eviction +
  cross-tool reachability through `Pool.LookupTempServer`.
- CLI: `config init` / `config validate` / `config add-server`, `auth
  set-keychain`, `trust`, `audit query`, `migrate-from-legacy`,
  `migrate-passwords`, `install <claude-desktop|claude-code|codex>`,
  `version`.
- One-liner `scripts/install.sh` and interactive
  `scripts/quick-setup.sh` wizard.
- AI assistant onboarding guide at `docs/AI_GUIDE.md`.
- CI workflow (GitHub Actions) on Ubuntu + macOS for `main` and `dev`.

### Security
- Inline credentials live only as long as the session/TTL window and are
  zeroed on close.
- SFTP `realpath` canonicalisation closes symlink TOCTOU around
  `allowed_paths`.
- `migrate-passwords` now strips `plaintext:` prefix correctly via
  `config.ParseCredRef`.
- Tunnel create does an SSH pre-flight so auth/host-key failures surface
  synchronously.

### Known limitations
- `audit query --limit` capped at 1000.
- `ListKeychain` is a stub on all backends.
