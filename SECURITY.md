# Security Policy

## Supported Versions

Only the latest tagged release on `main` is supported. Reported vulnerabilities are fixed in a new patch release; there is no LTS commitment yet.

| Version | Status |
|---------|--------|
| `0.0.6` | Current — security fixes land here |
| `< 0.0.6` | Use `ssh-mcp update` to upgrade; older binaries are not patched |

Each release tag (`vX.Y.Z`) is built by GitHub Actions from `main` and ships SHA-256 checksums alongside the binaries. The installer (`scripts/install.sh`) verifies the SHA-256 automatically.

## Reporting a Vulnerability

Email the maintainer directly (see the GitHub profile contact) rather than opening a public issue.

Include in your report:

- A description of the vulnerability and the affected component
- Steps to reproduce (minimal reproducer preferred)
- Potential impact and exploitability assessment

**Response timeline:**

- **72 hours** — acknowledgement that the report was received
- **14 days** — target for a fix or a confirmed disclosure timeline

Do not disclose the vulnerability publicly until a coordinated fix has been released.

## Threat Model

`ssh-mcp` is a stdio MCP server that runs SSH commands on behalf of an AI assistant. The primary trust boundary is between the AI client (Claude Desktop, Claude Code, Codex) and the set of servers listed in `config.toml`. The bridge acts as a policy enforcement point between the AI and those servers.

Key assumptions:

- The local machine running the bridge is trusted (same-user process).
- The MCP client (AI assistant host) is trusted; the **AI model output is not** — prompt injection from remote content can flow into tool calls.
- Remote servers are administered independently; their security is out of scope.
- The `known_hosts` file is the source of truth for host identity. First-contact trust is a **human action**, not an AI action.

## Security Features

- **Host key verification** — all connections are checked against `~/.ssh/known_hosts` (or the path in config). `HOST_KEY_MISMATCH` is a hard stop; the bridge never auto-accepts changed keys. `accept_new_host` is **not** exposed on any MCP tool schema (`ssh_quick_setup`, `ssh_exec.inline`, `session_start.inline`, `ssh_persistent_setup`) — first-contact trust must go through `ssh-mcp trust <name>` (or `--host <h> --port <p>`), which prints the SHA-256 fingerprint before pinning.
- **Credential lifecycle** — inline credentials (via `session_start.inline` or `ssh_quick_setup`) are promoted to TTL-bounded in-memory temp servers and zeroed on expiry or shutdown. Plaintext passwords in `config.toml` are rejected unless `allow_config_plaintext_password = true`; the keychain backend is the default for `ssh_persistent_setup` (`password_storage="keychain"`).
- **Append-only audit log** — every destructive tool call is pre-recorded before execution; `self_update` is included in the destructive set so binary replacements always leave a trail. The audit log captures `stdout` + `stderr` of executed commands (after redaction) so history is replayable — toggle with `settings.audit_record_output`, cap per-entry size with `audit_output_max_bytes`. Query path uses a read-only opener (`audit.NewReader`).
- **Secret redaction in audit** — both `args_redacted` and the captured `stdout` / `stderr` run through `safety.RedactSecret`. The redactor matches PEM blocks, `password=`/`token=`/`api_key=` style key-value pairs, URL userinfo, AWS access keys, `sshpass`/`-p` CLI patterns, `Authorization: Bearer/Basic/Digest`, GitHub (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`), OpenAI/Anthropic (`sk-…`), npm (`npm_…`), Slack (`xox[bpars]-…`), and JWT triplets (`eyJ…`). Output truncation snaps to a UTF-8 rune boundary so multi-byte content stays valid.
- **`RemoteCommand` sanitisation** — command strings are validated and sent verbatim over the SSH exec channel (not constructed via local `/bin/sh -c`), preventing local shell-injection. The remote SSH server interprets the exec request through the user's login shell, so standard quoting rules still apply on the remote side.
- **`allowed_paths` enforcement** — SFTP paths are canonicalised through the remote SFTP `realpath` RPC before `allowed_paths` policy is applied, closing symlink TOCTOU. The `realpath` action itself is now subject to the same gate, so it cannot be used to probe paths outside the allow-list. Servers injected dynamically via `list_servers refresh=true` or `ssh_persistent_setup` inherit `allowed_paths` through the SSH pool's temp-server fallback.
- **`sftp_upload` local allowlist, fail-closed by default** — `sftp_upload` streams an arbitrary local file to a remote server, which is a local-data-exfiltration primitive (e.g. an injected/compromised AI uploading `~/.ssh/id_rsa` or a browser credential export). It is gated by `settings.upload_local_allowed_paths` (a list of absolute local directory prefixes), which defaults to **empty** — every call returns `UPLOAD_DISABLED` until an operator hand-edits `config.toml`. This list cannot be populated through `ssh_persistent_setup`, `ssh_quick_setup`, or any other MCP tool call; it requires direct file access, matching the trust level of a human sitting at the keyboard. Once enabled, `local_path` is resolved via `filepath.EvalSymlinks` before the prefix check, so a symlink planted inside an allowed directory that points outside it is denied — the same TOCTOU hardening `allowed_paths` applies on the remote side. `local_path` must also resolve to a regular file (no directories, FIFOs, devices). The remote destination goes through the identical `resolveAndCheckRemotePath` + `allowed_paths` gate as `sftp_op action=write`. Prefer scoping `upload_local_allowed_paths` to a specific working directory — never `$HOME` or `/`.
- **Proxy chain credentials (v0.0.6)** — `[proxies.<name>] password` is a `CredRef` string with the same guard as server credentials (keychain by default; plaintext requires `allow_config_plaintext_password = true`). Cycle detection covers `proxy_jump` and `proxy_chain` together, including `ssh`-type proxies that reference configured servers. `type="ssh"` direct-mode entries do not support encrypted private keys in v0.0.6 — use `ssh-agent` or reference an existing `[servers.<name>]` (which supports `key_passphrase`).
- **Session limits** — concurrent session count is capped (`settings.max_sessions`, default 16) to limit blast radius from runaway automation.
- **`permissions.allow` is tiered, not wildcard** — the README guides users away from `mcp__ssh-bridge__*`. Tier 1 (read-only) is safe to pre-authorise; Tier 2 (writes / exec) requires explicit intent; Tier 3 (`tunnel`, `ssh_persistent_setup`, `self_update`) must stay on the human-confirmation path.
- **Installer integrity** — `scripts/install.sh` downloads `checksums.sha256` from the same GitHub release and verifies the binary; mismatch → reject and delete the downloaded file. This is the supply-chain bar for a single-binary tool; signed releases (cosign / SLSA) are not currently planned.
- **No `autoApprove`** — the example client configurations intentionally omit `autoApprove`. Destructive tools remain on the human-confirmation path.

## Out of Scope

- Security of the remote servers themselves (OS hardening, user permissions, etc.)
- Authentication of the MCP client to the bridge — stdio MCP trusts its peer by design. If you need a multi-tenant boundary, place an authenticating proxy in front and run `ssh-mcp` as a per-tenant child process.
- Vulnerabilities in SSH server implementations on the remote hosts
- Cryptographic signing of release artifacts (cosign / minisign / SLSA provenance) — SHA-256 checksums are the current bar
- Tamper-evident audit log (hash chain / remote append-only sink). The local log uses `0600` file permissions and `fsync` after each entry, but a local attacker with write access to the audit directory can modify it.
