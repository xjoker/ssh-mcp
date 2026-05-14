# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Branch / version convention:
- Development happens on `dev`; releases are tagged on `main`.
- Dev versions carry a `-dev` suffix (e.g. `0.0.1-dev`); release versions
  drop the suffix (`0.0.1`). `make release VERSION=…` stamps the binary.

## [Unreleased]

## [0.0.5] — 2026-05-14

### Added
- **Installer SHA-256 verification.** `scripts/install.sh` now downloads the
  `checksums.sha256` file published alongside each GitHub release and verifies
  the binary before placing it on `PATH`. A checksum mismatch causes the
  installer to reject and delete the downloaded binary immediately, providing
  basic supply-chain assurance.

### Changed
- **`permissions.allow` guidance reclassified into three tiers.** The README
  previously showed `"mcp__ssh-bridge__*"` as the recommended quick-start
  setting; this wildcard pre-authorises every tool including destructive and
  security-boundary tools. The documentation now recommends a tiered approach:
  - **Tier 1** (safe to pre-authorise, no side effects): `list_servers`,
    `sftp_list`, `sftp_read`, `sftp_stat`, `audit_query`.
  - **Tier 2** (pre-authorise only if you understand the implications —
    remote command execution and file writes): `ssh_exec`, `sftp_op`,
    `session_start`, `session_send`, `session_close`, `ssh_group_exec`,
    `ssh_quick_setup`.
  - **Tier 3** (never wildcard-allow — persistent or irreversible effects):
    `tunnel`, `ssh_persistent_setup`, `self_update`.

### Security
- **`accept_new_host` removed from all MCP tool schemas.** The field has been
  dropped from `ssh_quick_setup`, `ssh_exec` (inline), `session_start`
  (inline), and `ssh_persistent_setup`. First-connection host-key trust can
  only be established via the CLI: `ssh-mcp trust <name>` or
  `ssh-mcp trust --host <h> --port <p>`. The CLI displays the SHA256
  fingerprint and requires explicit confirmation before writing to
  `known_hosts`. This closes the prompt-injection path where a model could
  silently establish TOFU trust by passing `accept_new_host=true`.
- **`self_update` pre-audit gate.** The update operation now writes a pending
  audit record before downloading or replacing the binary. If the audit write
  fails the update is aborted. Because `self_update` replaces the running
  binary (the security boundary itself), the action must be traceable before
  it executes.
- **`sftp_op realpath` now enforces `allowed_paths`.** Previously `realpath`
  was exempt from the path allow-list check, making it usable as a
  path-existence probe for directories outside the configured scope. It now
  goes through the same `allowedPathsForServer` check as all other `sftp_op`
  operations.
- **`list_servers refresh` and `ssh_persistent_setup` inherit `allowed_paths`
  policy.** Servers injected into the pool's temp map via `list_servers
  refresh=true` or registered by `ssh_persistent_setup` were previously not
  consulted by `allowedPathsForServer`, which only looked up the static
  `cfg.Servers` map. SFTP operations on these servers therefore bypassed the
  `allowed_paths` check. `allowedPathsForServer` now also queries the pool's
  temp map, so dynamically registered servers are subject to the same policy
  as statically configured ones.

## [0.0.4] — 2026-05-14

### Added
- **Command output captured in audit log.** Every `ssh_exec` / `session_send`
  / streaming exec now persists `stdout` + `stderr` (after secret redaction)
  alongside the existing metadata, so the AI agent and human operators can
  replay history without re-running the command. New settings:
  - `audit_record_output` (default `true`) — master switch.
  - `audit_output_max_bytes` (default `32768` = 32 KiB per stream) — per-entry
    cap. Oversized payloads are truncated with a `…[truncated, N bytes
    total]` marker preserving the original size. Truncation snaps to a
    valid UTF-8 rune boundary so multi-byte / CJK / emoji output survives.
- `ssh-mcp audit query` gained two output modes:
  - `--output` — expanded multi-line block showing stdout / stderr / args
    inline (human-friendly).
  - `--json` — one JSONL record per entry with all fields (jq-friendly).
- `safety.RedactSecret` now scrubs additional text-form secrets relevant
  to captured stdout: `Authorization: Bearer/Basic/Digest/Token …`,
  `Proxy-Authorization: …`, bare GitHub/OpenAI/Anthropic/npm/Slack tokens
  (`ghp_`, `sk-…`, `npm_`, `xox[bpars]-…`), and JWT triplets (`eyJ…`).
- New error code `SESSION_BUSY` (retriable). Distinct from `SESSION_DEAD`:
  the session is alive, the previous command is just still flushing tail
  output. Callers may retry, or `session_close` to abort. `mapSessionError`
  surfaces this with a hint instead of falling through to INTERNAL_ERROR.

### Fixed
- `ssh-mcp cp <Prod:/x> <prod:/x>` previously bypassed the same-server
  guard because the comparison was case-sensitive while `dialServer`
  lower-cases the name. The two would resolve to the same physical
  connection and `Create(dst)` could truncate the file being read.
  Comparison now uses `strings.EqualFold`.
- `upload` / `download` / `cp` / `fetch` were ignoring `dst.Close()`
  errors. SFTP and local-filesystem quota / disk-full conditions are
  routinely reported only at close — a swallowed error would falsely
  claim success on a truncated destination. Close errors now propagate.
- Session stdout pump no longer drops the completion sentinel when
  `lineCh` is full. Previously a backed-up pump could discard the
  sentinel of a timed-out command, leaving `staleNonces` permanently
  un-drainable so the session was stuck in `SESSION_BUSY` forever. The
  pump now never drops sentinel lines (blocks instead) and reaps oldest
  non-sentinel output to make room.
- `list_servers refresh=true` now also reaps temp-server shadows for
  entries that were deleted or renamed from `config.toml` since process
  start. Previously the stale shadow lingered (and could be invoked by
  `ssh_exec` against an authorised-key combination the operator has
  since revoked) until the next MCP restart.

## [0.0.3] — 2026-05-14

### Added
- **CLI file-transfer commands** (`cmd/ssh-mcp/cli_transfer.go`): four new
  subcommands that stream bytes directly via SFTP, bypassing the base64
  envelope `sftp_op` uses (so size is no longer bounded by JSON payload
  limits):
  - `ssh-mcp upload <server> <local> <remote>` — local → remote.
  - `ssh-mcp download <server> <remote> <local>` — remote → local.
  - `ssh-mcp cp <src_srv>:<path> <dst_srv>:<path>` — server-to-server via
    local pipe; **no SSH inter-trust required** between the two remotes.
  - `ssh-mcp fetch <server> <url> <remote>` — HTTP GET on the local host,
    stream the response into a remote file. Useful when the remote machine
    cannot reach the URL (GFW, egress restrictions) but the local can.
  All four reuse the existing `cliCredResolver` (config.toml + keychain /
  agent / key paths), so any server that works for `ssh_exec` works here
  too. A `progressWriter` prints throttled progress to stderr; `--mkdirs`
  (default true) auto-creates missing parent directories.
- `ssh_persistent_setup` now accepts `password_storage`: `"keychain"`
  (default) writes the password to the OS keychain and stores only a
  `keychain:<svc>:<acct>` reference in `config.toml`; `"plaintext"` is
  opt-in and still requires `settings.allow_config_plaintext_password=true`.
  The keychain write happens **after** the config rename succeeds, with
  rollback on failure, so a failed write never leaves an orphan keychain
  entry or partial config.
- `list_servers` now accepts `refresh` (default `true`): re-reads
  `config.toml` from disk so manual edits since process start are visible
  without restart, and injects new entries into the SSH pool as zero-expiry
  temp servers so subsequent `ssh_exec` / `session_start` resolves them
  immediately.

### Fixed
- **`ssh_persistent_setup` password mode**: previously refused every
  password registration with `"plaintext password/passphrase persistence
  is disabled"` and had no working keychain path, forcing manual
  `security add-generic-password` + hand-edited `config.toml`. With the
  new keychain-default flow above, the tool now fully owns the round-trip
  in one call.
- **`session_send` no longer poisons the session on command timeout**.
  Previously a per-Send timeout transitioned the session to error and
  closed the shell, so the next send returned `SESSION_DEAD` — forcing a
  new `session_start` for every long command. The session module now runs
  a persistent stdout pump and tags each command with a unique nonce;
  on timeout the nonce is stashed as "stale" and the next send drains the
  prior command's tail output before issuing its own. A bounded drain
  budget (5 s) returns `SESSION_BUSY` (not `SESSION_DEAD`) when the prior
  command is still running, so the caller can choose to wait or
  `session_close`. `SESSION_DEAD` is now reserved for actual shell EOF.
- **`session_send` supports heredoc commands**. The sentinel wrapper used
  to put the closing brace on the same line as the user's command, which
  collided with heredoc terminators (`EOF`) — the heredoc never closed
  and the shell hung. The wrapper now places the closing brace on its
  own line so `<<'EOF' ... EOF` and other multi-line constructs work
  cleanly.
- **`list_servers` reflects manual `config.toml` edits**. Previously the
  server map was a startup-time snapshot; new entries added by a text
  editor remained invisible until the MCP process restarted. See the
  `refresh` parameter above.

## [0.0.2] — 2026-05-08

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
- `updater.Download`: prevent double-close of the temp file handle; the
  explicit `f.Close()` now sets a `fileClosed` flag so the deferred
  cleanup does not attempt a second close.
- `updater.cmpVer`: replace lexicographic pre-release comparison with
  numeric parsing of `YYYYMMDD.N` suffixes so build 10 correctly sorts
  after build 9 on the same date.

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
