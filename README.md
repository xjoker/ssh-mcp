# ssh-mcp

SSH operations as MCP tools for AI assistants — run commands, manage files, open tunnels, maintain persistent sessions.

**[中文文档 →](README_zh.md)** (translated; English is the authoritative version)

> **Pre-1.0 status.** `ssh-mcp` is on the `0.x.y` line. Functionality is stable enough for personal / small-team use (see `SECURITY.md` for the threat model), but breaking changes can still ship between minor releases when a security or design fix calls for it — they're always called out under `### Breaking` in `CHANGELOG.md`. The `1.0.0` release will lock in standard semver compatibility.

---

## Let Your AI Assistant Install This

> Already running Claude Code or Codex? Paste the **Phase 1** prompt to install and register ssh-mcp. After restarting your AI client, use the **Phase 2** prompt to add servers — no more shell commands needed.

### Phase 1 — Install & Register (Claude Code)

```
Install ssh-mcp on my machine using only shell commands (MCP is not yet available):

1. Call the GitHub releases API to find the latest release tag:
   GET https://api.github.com/repos/xjoker/ssh-mcp/releases
   Use releases[0].tag_name as the version.

2. Detect my OS and architecture, then download the matching binary:
   URL: https://github.com/xjoker/ssh-mcp/releases/download/{tag}/ssh-mcp_{os}_{arch}
   os values : linux | darwin | windows
   arch values: amd64 | arm64  (windows supports amd64 only)
   Append .exe on Windows.

3. Install the binary:
   macOS/Linux → ~/.local/bin/ssh-mcp  (chmod +x, create dir if needed)
   Windows     → %LOCALAPPDATA%\Programs\ssh-mcp\ssh-mcp.exe

4. Run: ssh-mcp config init

5. Register with Claude Code:
   claude mcp add --transport stdio --scope user ssh-bridge -- ~/.local/bin/ssh-mcp
   (Windows: use the full .exe path from step 3)

6. Confirm with: ssh-mcp version

Then tell me: "Done — please restart Claude Code to activate the MCP server."
```

> After restarting Claude Code, the `ssh-mcp` MCP tools are available. Use **Phase 2** to add servers.

### Phase 2 — Add a Server (via MCP tool)

After restart, paste this:

```
Before we start: add the following to ~/.claude/settings.json so low-risk
ssh-mcp tools run without confirmation prompts on every call:

  {
    "permissions": {
      "allow": [
        "mcp__ssh-bridge__list_servers",
        "mcp__ssh-bridge__sftp_list",
        "mcp__ssh-bridge__sftp_read",
        "mcp__ssh-bridge__sftp_stat",
        "mcp__ssh-bridge__audit_query"
      ]
    }
  }

Then use the ssh_quick_setup MCP tool to connect me to my SSH server.
Ask me for: host, port, username, and auth method (agent / key / password).
```

> `ssh_quick_setup` registers an ad-hoc server in memory (TTL up to 4 hours). For servers you use regularly, add them permanently to `config.toml` instead — the AI can then call tools with `server: "<name>"` directly without any confirmation prompt.
>
> **Updates:** Call the `self_update` MCP tool — no shell commands needed. Use `check_only: true` to inspect first.

### Codex

Phase 1 — replace step 5 with:
```
codex mcp add ssh-bridge -- ~/.local/bin/ssh-mcp
```
Phase 2 — same as above.

---

## Manual Install

**macOS / Linux:**

```sh
curl -fsSL https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.sh | bash
```

**Windows (PowerShell):**

```powershell
iwr -useb https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.ps1 | iex
```

No Go, no build tools, no admin rights. The binary is downloaded directly from [GitHub Releases](https://github.com/xjoker/ssh-mcp/releases).

| Platform | Default install path |
|----------|----------------------|
| macOS / Linux | `~/.local/bin/ssh-mcp` |
| Windows | `%LOCALAPPDATA%\Programs\ssh-mcp\ssh-mcp.exe` |

Override with `PREFIX=...` (bash) or `$env:PREFIX=...` (PowerShell).

**From source:**

```sh
git clone https://github.com/xjoker/ssh-mcp.git
cd ssh-mcp
make build   # binary at bin/ssh-mcp
```

---

## Post-install Setup

```sh
ssh-mcp config init
ssh-mcp config add-server prod --host example.com --user alice --auth agent
ssh-mcp trust prod

# Register with your AI client:
claude mcp add --transport stdio --scope user ssh-bridge -- ~/.local/bin/ssh-mcp
codex  mcp add ssh-bridge -- ~/.local/bin/ssh-mcp
```

For password auth:

```sh
ssh-mcp config add-server prod --host example.com --user alice --auth password
ssh-mcp auth set ssh-password:prod
# prompts for password; nothing sensitive lands in config.toml
```

### Manage machines in the operations console

Launch the English-only TUI against the default configuration:

```sh
ssh-mcp tui
```

Use a different configuration when needed:

```sh
ssh-mcp tui --path /path/to/config.toml
```

The console keeps the machine list, selected-machine status, and next actions
on one screen. Use `j`/`k` or the arrow keys to select a machine, `/` to
search, `a` to add, `r` to reload, and `Enter` to open the machine actions:

| Key | Action |
| --- | --- |
| `t` | Test the SSH connection |
| `c` | Leave the console temporarily and open an interactive SSH shell |
| `e` | Edit the machine, account, authentication, jump host, tags, and command policy |
| `p` | Store, replace, or delete the password in the OS keychain |
| `k` | Preview and explicitly trust an unknown host key |
| `d` | Delete the machine after confirmation and create a configuration backup |

Passwords are never displayed or written to `config.toml`; the console shows
only `Stored`, `Missing`, or `Unavailable`. Connection tests and shells remain
fail-closed until the host key is trusted. A changed host key is blocked and
must be repaired outside the console after independent verification.

### Pre-authorise tools (avoid per-call permission prompts)

By default Claude Code asks for confirmation on every MCP tool call. You can pre-authorise individual tools by adding them to `permissions.allow` in `~/.claude/settings.json` (user-wide) or `.claude/settings.json` (project-only).

> `permissions.allow` pre-approves specific tools — distinct from `autoApprove` in the MCP config, which bypasses all confirmation globally and is intentionally omitted from ssh-mcp examples.

**Do not use the wildcard `"mcp__ssh-bridge__*"`.** A wildcard pre-authorises every tool including destructive and security-boundary tools, removing the human confirmation step that limits the blast radius of prompt injection or model mistakes.

Instead, use the tiered approach below:

Generate the matching client fragment instead of copying the lists manually:

```sh
ssh-mcp permissions claude-code                 # safe read-only tools
ssh-mcp permissions codex                       # safe read-only tools
ssh-mcp permissions claude-code --tier standard # include Tier 2
```

The command only prints configuration; it never edits client files. Use
`--server-name` if the MCP server is registered under a name other than
`ssh-bridge`.

#### Tier 1 — Safe to pre-authorise (read-only, no side effects)

```json
{
  "permissions": {
    "allow": [
      "mcp__ssh-bridge__list_servers",
      "mcp__ssh-bridge__sftp_list",
      "mcp__ssh-bridge__sftp_read",
      "mcp__ssh-bridge__sftp_stat",
      "mcp__ssh-bridge__audit_query"
    ]
  }
}
```

#### Tier 2 — Pre-authorise only if you understand the implications

These tools execute commands or write files on remote servers. Pre-authorising them removes the per-call confirmation that would otherwise catch unintended operations.

```json
{
  "permissions": {
    "allow": [
      "mcp__ssh-bridge__ssh_exec",
      "mcp__ssh-bridge__sftp_op",
      "mcp__ssh-bridge__session_start",
      "mcp__ssh-bridge__session_send",
      "mcp__ssh-bridge__session_close",
      "mcp__ssh-bridge__ssh_group_exec",
      "mcp__ssh-bridge__ssh_quick_setup"
    ]
  }
}
```

#### Tier 3 — Never wildcard-allow; require manual confirmation every time

These tools cross persistent or local-machine security boundaries: `tunnel` establishes long-lived port forwards, `sftp_upload` reads a local file and sends it remotely, `ssh_persistent_setup` writes permanent server credentials, and `self_update` replaces the running binary (the security boundary itself). Always confirm these manually.

- `mcp__ssh-bridge__tunnel`
- `mcp__ssh-bridge__sftp_upload`
- `mcp__ssh-bridge__ssh_persistent_setup`
- `mcp__ssh-bridge__self_update`

#### Why does Claude Code prompt every time I call `ssh_quick_setup`?

The confirmation dialog you see (host-key trust / "register temp server …") comes from **Claude Code's own tool-permission UI**, not from ssh-mcp. The bridge does not issue MCP elicitations of its own — there is no per-call confirmation in the server code. Two consequences:

1. Adding the tool to `permissions.allow` (above) silences the prompt across every call.
2. If you frequently use the same host, prefer `ssh_persistent_setup` once over `ssh_quick_setup` repeatedly. Permanent entries are addressed by `name` in subsequent `ssh_exec` / `sftp_*` calls and don't go through the setup tool again.

Repeated `ssh_quick_setup` calls for the same `host+port+user` already dedup internally — they reuse the existing in-memory registration and do not allocate a new name — but they still go through Claude Code's per-tool-call permission check.

---

## What ssh-mcp Can Do

### Command Execution

| Tool | Description |
|------|-------------|
| `ssh_exec` | Run a command on a single server. Supports PTY mode for TUI programs (htop, btop, ncdu) with ANSI stripping. |
| `ssh_group_exec` | Run the same command on multiple servers in parallel — select by name list or tag. |

For a one-shot command that must not continue after the client-side deadline,
set `terminate_on_timeout: true`. This explicit opt-in wraps the command in a
remote `setsid + timeout` watchdog: TERM is sent after the deadline and KILL
five seconds later. The remote host must provide both utilities; otherwise the
call fails before running the command. It is incompatible with `pty: true` and
only guarantees termination of processes that remain in the launched process
group—daemonized or re-sessioned descendants can escape. Persistent
`session_send` keeps its existing timeout semantics and is not affected.

### File Operations (SFTP)

| Tool | Description |
|------|-------------|
| `sftp_op` | Upload, download, mkdir, delete, move, copy, symlink, stat, realpath. Small payloads only (base64 / JSON-bounded — use `sftp_upload` or the CLI commands below for large files). The `realpath` operation is subject to `allowed_paths` enforcement — it cannot be used to probe paths outside the configured allow-list. |
| `sftp_upload` ⚠️ | Upload a local file of **any size** to a remote server — streams straight from disk through the MCP process (no base64/JSON overhead, no size limit). **Disabled by default**: requires `settings.upload_local_allowed_paths` (absolute local directory prefixes) in `config.toml`; empty list → every call returns `UPLOAD_DISABLED`. Cannot be enabled via any MCP tool — hand-edit `config.toml` and restart. See [SECURITY.md](SECURITY.md) for the full threat model. Tier 3 — never wildcard-allow. |
| `sftp_list` | List a remote directory with metadata. |
| `sftp_read` | Read a remote file with byte-offset support (tail / seek). |
| `sftp_stat` | Stat a single remote path. |

For **server-to-server** transfers, downloading a remote file locally, or
fetching a URL through the remote host, use the CLI (no size limit, streams
directly via SFTP — no base64):

| Command | Purpose |
|---------|---------|
| `ssh-mcp upload <server> <local> <remote>` | Local → server (also available as the `sftp_upload` MCP tool above). |
| `ssh-mcp download <server> <remote> <local>` | Server → local. |
| `ssh-mcp cp <src_srv>:<path> <dst_srv>:<path>` | Server ↔ server via local pipe (no SSH inter-trust needed). |
| `ssh-mcp fetch <server> <url> <remote>` | HTTP GET on the local host, stream to remote. Useful when the remote can't reach the URL (GFW, egress restrictions). |

### Persistent Shell Sessions

| Tool | Description |
|------|-------------|
| `session_start` | Open a persistent shell — **sentinel mode** (waits for command exit) or **PTY mode** (time-based drain for interactive programs). |
| `session_send` | Send input to an active session and collect output. |
| `session_close` | Close a session and free its resources. |

Sessions are stateful: run `cd`, set environment variables, activate virtualenvs — the state carries across `session_send` calls.

**Timeout / busy semantics (v0.0.4):** A `session_send` `TIMEOUT` no longer poisons the session. The session keeps the shell open and stashes the running command's completion marker as "stale"; the next `session_send` first drains that tail output (5 s budget) before issuing its own command. If the prior command is still producing output past the budget, the next call returns `SESSION_BUSY` (retriable) — the caller can wait and retry, or call `session_close` to abort. The genuine `SESSION_DEAD` code is reserved for actual shell EOF (remote disconnect).

### Tunnels

| Tool | Description |
|------|-------------|
| `tunnel` ⚠️ | Open a local or remote port-forward. Local: `localhost:{port} → server:{remotePort}`. Remote: `server:{port} → localhost:{localPort}`. Tier 3 — never wildcard-allow. |

### Server Management

| Tool | Description |
|------|-------------|
| `list_servers` | List configured servers with optional tag filter. Re-reads `config.toml` from disk by default (`refresh=true`) so manual edits are visible without restart; newly discovered entries are also injected into the SSH pool so `ssh_exec` / `session_start` can use them immediately. |
| `ssh_quick_setup` | Register an ad-hoc server using inline credentials — stored in memory with a TTL (max 4 hours), never written to disk. Repeated calls for the same `host+port+user` reuse the existing registration. |
| `ssh_persistent_setup` ⚠️ | Append a `[servers.<name>]` block to `config.toml` so the entry survives restart and has no TTL. Passwords go to the OS keychain by default (`password_storage="keychain"`); set `"plaintext"` (with `settings.allow_config_plaintext_password=true`) to store the literal value instead. Tier 3 — never wildcard-allow. |

### Audit

| Tool | Description |
|------|-------------|
| `audit_query` | Search the append-only JSONL audit log by server, tool, time range, exit code, or error status. The entry includes the executed command's `stdout` + `stderr` (after secret redaction) so the AI can replay history without re-running the command. Toggle with `settings.audit_record_output` (default `true`); cap per-entry size with `audit_output_max_bytes` (default `32 KiB`). |

The CLI offers two extra view modes on top of the default table:

```sh
ssh-mcp audit query --since 1h --output    # expanded; stdout/stderr/args inline
ssh-mcp audit query --since 1h --json      # one JSONL record per entry (jq-friendly)
```

### Self-Update

| Tool | Description |
|------|-------------|
| `self_update` ⚠️ | Check for a newer release and install it atomically. Use `check_only: true` to inspect availability without downloading. After update, restart the MCP server to apply the new binary. Tier 3 — never wildcard-allow. |

---

## Proxy Chain

For complex network topologies, `proxy_chain` lets you route a server's TCP dial path through one or more proxies — HTTP CONNECT, HTTPS CONNECT, SOCKS5, or another SSH host — chained in outer-to-inner order.

### Supported proxy types

| `type` | Protocol | Notes |
|--------|----------|-------|
| `http` | HTTP CONNECT (plaintext) | Optional Basic auth via `user` + `password` (CredRef) |
| `https` | HTTP CONNECT over TLS | `insecure_skip_verify = true` available for dev only |
| `socks5` | SOCKS5 | Optional `user` + `password` auth |
| `ssh` | SSH tunnel | Two modes: `server = "<name>"` (recommended) or direct `host`/`port`/`user`/`auth` |

For SSH proxies, prefer the `server = "<name>"` form — it reuses the referenced server's full auth config, host-key pinning, and any nested proxy chain.

### Configuration example

```toml
[proxies.corp-http]
type     = "http"
host     = "proxy.corp"
port     = 8080
user     = "alice"
password = "keychain:ssh-mcp:proxy-pass:corp"

[proxies.tor]
type = "socks5"
host = "127.0.0.1"
port = 9050

[proxies.bastion-via-server]
type   = "ssh"
server = "bastion"   # reuses [servers.bastion] auth + host-key

[proxies.bastion-direct]
type = "ssh"
host = "jump.example.com"
port = 22
user = "deploy"
auth = "agent"

[servers.internal-db]
host        = "10.0.0.50"
user        = "dba"
auth        = "key"
key_path    = "~/.ssh/id_ed25519"
proxy_chain = ["corp-http", "tor", "bastion-via-server"]   # outer → inner
```

`proxy_chain` items are resolved left-to-right, outer to inner: `corp-http` is dialled first, then `tor` is tunnelled through it, then `bastion-via-server`, and finally `internal-db` is reached through the last hop.

### Rules and limits

- `proxy_chain` and `proxy_jump` are **mutually exclusive** on a server. When `proxy_chain` is present it takes precedence; `proxy_jump` is retained for backward compatibility.
- Maximum chain length: **8 hops**.
- Duplicate proxy names within a single chain are rejected at config-load time.
- SSH proxy `server` references are cycle-detected (extends the existing `proxy_jump` cycle check).
- Tunnel port-forwards transparently use the server's `proxy_chain` — no extra configuration needed.
- Proxy `password` is a CredRef string (same security level as server credentials — keychain by default). Encrypted SSH private keys aren't supported for direct-mode `ssh` proxies in v0.0.6 — use `ssh-agent` or reference a configured server via `server = "…"`.

---

## Highlights

**Multi-hop SSH chains**
Route through bastion hosts transparently via `proxy_jump`. Chains of arbitrary depth work — A → B → C requires only `proxy_jump` entries in `config.toml`. For mixed HTTP/SOCKS5/SSH chains see [Proxy Chain](#proxy-chain) above.

**PTY support**
Full pseudo-terminal allocation for `ssh_exec` and `session_start`. Run `htop`, `btop`, `ncdu`, `vim` and other TUI programs; use `strip_ansi` to get clean text back.

**OS keychain integration**
Passwords are stored in macOS Keychain, Linux libsecret, or Windows Credential Manager — never in `config.toml`. `ssh-mcp auth set` handles enrollment.

**Tag-based group operations**
Tag servers (`tags = ["prod", "eu"]`) and target entire fleets with a single `ssh_group_exec` call.

**TTL-bounded inline credentials**
`ssh_quick_setup` accepts a password or private key inline for ad-hoc sessions. Credentials live in memory and are zeroed on TTL expiry or shutdown.

**Append-only audit trail**
Every tool call is pre-recorded in a JSONL audit log before execution. `audit_query` provides structured search; credentials appear only as `{"redacted":true}`.

**Self-update**
`ssh-mcp update` fetches the latest release binary, verifies its SHA-256, and atomically replaces the running binary. The bridge also surfaces an update notice on startup when a newer version is available.

---

## Security

- **No `autoApprove`** — example client configs intentionally omit it. SSH operations have unbounded remote effects and must stay on the human-confirmation path.
- **Host key verification** — `HOST_KEY_MISMATCH` is a hard stop; the bridge never auto-accepts changed keys.
- **First-connection trust via CLI only** — `accept_new_host` has been removed from all MCP tool schemas (`ssh_quick_setup`, `ssh_exec`, `session_start`, `ssh_persistent_setup`). New hosts must be trusted through the CLI: `ssh-mcp trust <name>` or `ssh-mcp trust --host <h> --port <p>`. The CLI displays the SHA256 fingerprint and requires manual confirmation before writing to `known_hosts`. This prevents a prompt-injected instruction from silently establishing TOFU trust through the model.
- **`allowed_paths` enforcement** — SFTP paths are canonicalised through SFTP `realpath` before policy is applied, closing symlink TOCTOU. This includes the `realpath` operation itself — it cannot probe paths outside the allow-list.
- **`self_update` pre-audit** — the update operation records a pending audit entry before replacing the binary. If the audit write fails, the update is aborted. This ensures the action that replaces the security boundary is always traceable.
- **Plaintext password guard** — rejected unless `allow_config_plaintext_password = true`; keychain is the default.
- See [`SECURITY.md`](SECURITY.md) for the full threat model and disclosure policy.

---

## Configuration

Default locations (no admin / sudo required):

| OS | Config | Audit log |
|----|--------|-----------|
| macOS / Linux | `~/.config/ssh-mcp/config.toml` | `~/.local/state/ssh-mcp/` |
| Windows | `%APPDATA%\ssh-mcp\config.toml` | `%LOCALAPPDATA%\ssh-mcp\audit\` |

Override with `MCP_SSH_BRIDGE_CONFIG=/path/to/config.toml`.

Minimal config:

```toml
[servers.prod]
host = "example.com"
user = "alice"
auth = "agent"
```

Jump-host chain:

```toml
[servers.bastion]
host = "bastion.example.com"
user = "ops"
auth = "key"
key_path = "~/.ssh/id_ed25519"

[servers.internal]
host = "10.0.1.50"
user = "ops"
auth = "key"
key_path = "~/.ssh/id_ed25519"
proxy_jump = "bastion"
```

Enable `sftp_upload` (disabled by default — see [SECURITY.md](SECURITY.md)):

```toml
[settings]
upload_local_allowed_paths = ["/Users/alice/deploy-artifacts"]  # absolute paths only; not $HOME
```

Full example: [`examples/config.toml`](examples/config.toml)

---

## CLI Reference

```sh
# Config & server management
ssh-mcp tui
ssh-mcp config init
ssh-mcp config validate
ssh-mcp config add-server <name> --host H --user U --auth agent|key|password
ssh-mcp trust <name>
ssh-mcp auth set ssh-password:<name>
ssh-mcp server list
ssh-mcp server test <name>

# File transfers (stream via SFTP, no size limit)
ssh-mcp upload   <server> <local_path> <remote_path>
ssh-mcp download <server> <remote_path> <local_path>
ssh-mcp cp       <src_srv>:<src_path> <dst_srv>:<dst_path>
ssh-mcp fetch    <server> <url> <remote_path>

# Audit & updates
ssh-mcp audit query --tool ssh_exec --since 24h            # metadata table
ssh-mcp audit query --tool ssh_exec --since 1h --output    # expanded: stdout/stderr inline
ssh-mcp audit query --since 24h --json | jq                # JSONL for tooling
ssh-mcp update
ssh-mcp install claude-code     # print claude mcp add command
ssh-mcp install codex           # print codex mcp add command
ssh-mcp install claude-desktop  # print JSON snippet
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `HOST_KEY_UNKNOWN` | `ssh-mcp trust <name>` |
| `unable to authenticate` (password) | `ssh-mcp auth set ssh-password:<name>` |
| `SESSION_LIMIT` | Close idle sessions or raise `settings.max_sessions` in config |
| `UPLOAD_DISABLED` (from `sftp_upload`) | Set `settings.upload_local_allowed_paths` in `config.toml` and restart `ssh-mcp` |
| Bridge not appearing in AI client | Restart the AI client after `mcp add` |
| `config: no such file` | `ssh-mcp config init` |

---

## Documentation

- [`docs/AI_GUIDE.md`](docs/AI_GUIDE.md) — paste into your AI assistant after connecting; teaches tool selection, error handling, and the no-autoApprove discipline
- [`examples/`](examples/) — config and client snippets
- [`SECURITY.md`](SECURITY.md) — threat model and disclosure policy
- [`SDD.md`](SDD.md) — system design document

---

## License

Apache 2.0. See [LICENSE](LICENSE).
