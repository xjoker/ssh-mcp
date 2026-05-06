# ssh-mcp

SSH operations as MCP tools for AI assistants — run commands, manage files, open tunnels, maintain persistent sessions.

**[中文文档 →](README_zh.md)**

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
Use the ssh_quick_setup MCP tool to connect me to my SSH server.
Ask me for: host, port, username, and auth method (agent / key / password).
```

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

---

## What ssh-mcp Can Do

### Command Execution

| Tool | Description |
|------|-------------|
| `ssh_exec` | Run a command on a single server. Supports PTY mode for TUI programs (htop, btop, ncdu) with ANSI stripping. |
| `ssh_group_exec` | Run the same command on multiple servers in parallel — select by name list or tag. |

### File Operations (SFTP)

| Tool | Description |
|------|-------------|
| `sftp_op` | Upload, download, mkdir, delete, move, copy, symlink, stat, realpath. |
| `sftp_list` | List a remote directory with metadata. |
| `sftp_read` | Read a remote file with byte-offset support (tail / seek). |
| `sftp_stat` | Stat a single remote path. |

### Persistent Shell Sessions

| Tool | Description |
|------|-------------|
| `session_start` | Open a persistent shell — **sentinel mode** (waits for command exit) or **PTY mode** (time-based drain for interactive programs). |
| `session_send` | Send input to an active session and collect output. |
| `session_close` | Close a session and free its resources. |

Sessions are stateful: run `cd`, set environment variables, activate virtualenvs — the state carries across `session_send` calls.

### Tunnels

| Tool | Description |
|------|-------------|
| `tunnel` | Open a local or remote port-forward. Local: `localhost:{port} → server:{remotePort}`. Remote: `server:{port} → localhost:{localPort}`. |

### Server Management

| Tool | Description |
|------|-------------|
| `list_servers` | List configured servers with optional tag filter. |
| `ssh_quick_setup` | Register an ad-hoc server using inline credentials — stored in memory with a TTL (max 4 hours), never written to disk. |

### Audit

| Tool | Description |
|------|-------------|
| `audit_query` | Search the append-only JSONL audit log by server, tool, time range, exit code, or error status. |

### Self-Update

| Tool | Description |
|------|-------------|
| `self_update` | Check for a newer release and install it atomically. Use `check_only: true` to inspect availability without downloading. After update, restart the MCP server to apply the new binary. |

---

## Highlights

**Multi-hop SSH chains**
Route through bastion hosts transparently via `proxy_jump`. Chains of arbitrary depth work — A → B → C requires only `proxy_jump` entries in `config.toml`.

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
- **`allowed_paths` enforcement** — SFTP paths are canonicalised through SFTP `realpath` before policy is applied, closing symlink TOCTOU.
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

Full example: [`examples/config.toml`](examples/config.toml)

---

## CLI Reference

```sh
ssh-mcp config init
ssh-mcp config validate
ssh-mcp config add-server <name> --host H --user U --auth agent|key|password
ssh-mcp trust <name>
ssh-mcp auth set ssh-password:<name>
ssh-mcp server list
ssh-mcp server test <name>
ssh-mcp audit query --tool ssh_exec --since 24h
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
