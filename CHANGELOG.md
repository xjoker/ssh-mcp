# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases up to and including `0.0.7` used [Semantic Versioning](https://semver.org/spec/v2.0.0.html);
from the next release onward the project uses **date-based versioning**
(`YYYYMMDD.V`, see below). Breaking changes are still called out in a
`### Breaking` section of the affected release.

Branch / version convention:
- Development happens on `dev`; releases are tagged on `main`.
- **Versioning scheme `YYYYMMDD.V`** (e.g. `20260713.1`; `.V` increments for
  multiple releases on the same day). The root `VERSION` file is the single
  source of truth; release tags are `vYYYYMMDD.V` and CI verifies the tag
  matches `VERSION`. Dev-line builds carry a `-dev` suffix. `make release`
  stamps the binary from `VERSION`; CI stamps from the matching tag.
- The self-update version comparison spans both schemes, so upgrading from a
  legacy `0.0.x` build to a `YYYYMMDD.V` release is ordered correctly.

## [Unreleased]

### Changed
- **Versioning scheme is now `YYYYMMDD.V`** (date-stamped) instead of semver
  `X.Y.Z`. Added a root `VERSION` file as the single source of truth; release
  workflows match `vYYYYMMDD.V` tags and verify the tag agrees with `VERSION`.
  The `internal/updater` comparison was rewritten to order both schemes (and
  the legacy→new transition) correctly.
- **Audit storage now uses SQLite** with durable writes and a read-only,
  idempotent migration path from legacy JSONL logs. Runtime state is reported
  into the same local store for lightweight management visibility.
- Configuration writes and host-key trust updates now share validated,
  atomic core operations instead of duplicating persistence logic in CLI
  handlers.

### Added
- **Local management TUI** via `ssh-mcp tui` for inspecting servers, audit
  activity, runtime state, and command policies without a separate daemon.
- **MCP standard tool annotations** on every tool (`readOnlyHint` /
  `destructiveHint` / `idempotentHint` / `openWorldHint`) so MCP clients can
  present risk-appropriate confirmation UX.
- **Per-server command policy** — `mode = "readonly" | "restricted"` plus
  optional `allow_patterns` / `deny_patterns` on `[servers.<name>]`. Opt-in
  command filtering: `readonly` permits a built-in observation allowlist and
  rejects shell metacharacters; `restricted` requires an `allow_patterns`
  match with `deny_patterns` winning; empty allow denies all (fail-closed).
  Write-channel tools (`sftp_op`/`sftp_upload`/`tunnel`) are denied on any
  moded server. Denials are audited as `POLICY_DENIED`. Defense-in-depth, not
  a sandbox — see SECURITY.md.
- **Opt-in remote timeout termination** for `ssh_exec` and `ssh_group_exec`.
  `terminate_on_timeout: true` launches a remote `setsid + timeout` watchdog
  that sends TERM and then KILL to the command process group. It is disabled
  by default, rejected for PTY commands, and fails before executing the user
  command when the required remote utilities are unavailable.
- **Permission fragment export** via
  `ssh-mcp permissions <claude-code|codex>`. It prints explicit read-only or
  standard per-tool approval lists without editing client configuration;
  persistent/high-impact Tier 3 tools are always excluded.

## [0.0.7] — 2026-07-11

### Added
- **`sftp_upload` MCP tool — large-file upload without a size limit.** The AI
  passes `(server, local_path, remote_path)`; the ssh-mcp process opens the
  local file itself and streams it to the remote over SFTP, so file bytes
  never transit the model context (unlike `sftp_op`'s base64 path with its
  16 MiB cap). Works transparently with `ssh_quick_setup` temporary servers.
  Fail-closed by design: the new `settings.upload_local_allowed_paths`
  allowlist defaults to empty (tool disabled) and must be enabled by hand in
  `config.toml`; local paths are symlink-resolved before the prefix check and
  must be regular files; the remote path goes through the same
  realpath + `allowed_paths` check as `sftp_op`. Uploads are audited as
  destructive operations with size and streaming SHA-256 recorded
  (`content_sha256`), and the remote size is verified after the atomic write.
- `list_servers refresh=true` now also hot-reloads `[proxies.<name>]`
  tables, closing the v0.0.6 known limitation (new proxies previously
  required an MCP restart).
- `HOST_KEY_UNKNOWN` errors now carry an actionable hint pointing at
  `ssh-mcp trust <host>[:port]`.
- Windows added to the CI test matrix; community files
  (issue/PR templates, CODEOWNERS) and the pre-1.0 versioning policy.

### Fixed
- **Connection pool races:** `CloseIdle` no longer blocks unrelated servers
  while a dial is in flight, no longer evicts entries created moments
  earlier, and `Get` retries instead of returning a connection that a
  concurrent eviction just closed.
- **Proxy chain:** direct-mode `ssh` proxies no longer leak the throwaway
  SSH client; chain-lookup failures suggest a config refresh.
- **Tunnel:** TCP half-close (`CloseWrite`) now propagates in both
  directions instead of tearing the stream down early, and forward dials
  time out after 30s instead of hanging.
- **Safety:** `allowed_paths = ["/"]` now allows everything instead of
  denying everything; space-separated `--password <value>` redaction no
  longer leaks a prefix of the secret into audit logs.
- **Audit:** per-line reads are bounded (8 MiB; oversized lines skipped like
  malformed ones), `--limit` keeps the newest entries in a sliding window
  instead of growing without bound, retention is enforced at startup and on
  daily rotation, and `audit query --since` rejects negative durations.
- **Config:** `[servers.<name>]` duplicate detection is line-anchored (a
  name mentioned in a comment no longer blocks registration), server/proxy
  names that collide after case-folding are rejected at load, and all three
  config writers (`config add-server`, `ssh_persistent_setup`, `server add`)
  stage writes through create-temp → validate → atomic rename.
- Session output lines are capped at 256 KiB; the session reaper survives a
  double `CloseAll`; the connection reaper tick honours idle thresholds
  below 60s.

### Security
- Bumped `golang.org/x/crypto` and `golang.org/x/net`, closing all 14
  Dependabot alerts (7 critical, including SSH auth-bypass and DoS issues);
  pinned Go toolchain 1.26.5 for the crypto/tls fix (GO-2026-5856). Routine
  follow-up bump to x/crypto 0.54.0 / x/net 0.57.0 / go-sdk 1.6.1.
- Self-updater: the downloaded binary is created `0600` with `O_EXCL` and
  only marked executable after its SHA-256 checksum verifies (closes a
  TOCTOU window where a half-written binary was briefly executable).
- SAST pass (govulncheck / gosec / staticcheck) with real findings fixed.

## [0.0.6] — 2026-05-14

### Added
- **Proxy Chain (`proxy_chain`).** A new top-level `[proxies.<name>]` table lets
  you describe named proxy hops. Any `[servers.<name>]` can reference them via
  `proxy_chain = ["hop1", "hop2", …]` (outer-to-inner order, max 8 hops).
  The full TCP dial path to the remote SSH server passes through every hop in
  the chain; tunnel port-forwards inherit the chain transparently.
- **Four proxy protocols supported:**
  - `http` — HTTP CONNECT (plaintext), optional Basic auth.
  - `https` — HTTP CONNECT over TLS; `insecure_skip_verify = true` opt-in for
    development environments only.
  - `socks5` — SOCKS5 via `golang.org/x/net/proxy`; optional user/password auth.
    (`golang.org/x/net` dependency already present; no new top-level dependency
    introduced.)
  - `ssh` — SSH tunnel in two modes: `server = "<name>"` reuses an existing
    `[servers.<name>]` entry (recommended; inherits its auth, host-key, and
    nested chain); or direct `host`/`port`/`user`/`auth` for standalone hops.
- **CredRef auth for proxy credentials.** The `password` field in
  `[proxies.<name>]` accepts the same CredRef strings as server credentials
  (`keychain:…`, `plaintext:…`, bare strings with the plaintext guard).
  Proxy passwords are stored in the OS keychain by default. Encrypted SSH
  private keys are not supported for `type = "ssh"` direct-mode proxies in
  this release — use `ssh-agent` forwarding instead, or reference an existing
  `[servers.<name>]` (which DOES support `key_passphrase`) via `server = "…"`.
- **Cycle detection extended to SSH proxy chains.** The existing
  `detectProxyJumpCycles` logic is extended to cover `ssh`-type proxy entries
  that reference other servers via `server = "<name>"`, preventing infinite
  dial recursion.
- **Config-layer validation for `proxy_chain`.** Validated at load time:
  proxy names must match `^[a-z0-9][a-z0-9_-]*$`; `type` must be one of the
  four values above; chain elements must all exist in `cfg.Proxies`; chain
  length ≤ 8; no duplicate names within a chain; `insecure_skip_verify` is
  rejected on non-`https` types; SSH direct mode requires exactly one of
  `server` or `host`/`port`/`user`/`auth`.

### Compatibility
- **`proxy_jump` retained.** Servers that use `proxy_jump` continue to work
  without changes. `proxy_chain` takes precedence when both fields are present
  on the same server entry; a lint warning is emitted by `config validate`.

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

### Breaking
- **`accept_new_host` removed from all MCP tool schemas.** Listed under
  Breaking because callers that previously passed `accept_new_host=true`
  must drop the field; first-contact host trust is now CLI-only. See the
  Security entry below for the full rationale.

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
