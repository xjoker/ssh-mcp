# mcp-ssh-bridge

SSH operations as MCP tools for AI assistants — run commands, manage files, open tunnels, maintain persistent sessions.

**[中文文档 →](README_zh.md)**

---

## Let Your AI Assistant Install This

> Already running Claude Code or Codex? Skip the manual steps — paste the prompt below and let the AI handle the entire installation, configuration, and registration in one shot.

### Claude Code

```
Install mcp-ssh-bridge on my machine by following these steps exactly:

1. Call the GitHub releases API to find the latest release tag:
   GET https://api.github.com/repos/xjoker/ssh-mcp/releases
   Use releases[0].tag_name as the version.

2. Detect my OS and architecture, then download the matching binary:
   URL: https://github.com/xjoker/ssh-mcp/releases/download/{tag}/mcp-ssh-bridge_{os}_{arch}
   os values : linux | darwin | windows
   arch values: amd64 | arm64  (windows supports amd64 only)
   Append .exe on Windows.

3. Install the binary:
   macOS/Linux → ~/.local/bin/mcp-ssh-bridge  (chmod +x, create dir if needed)
   Windows     → %LOCALAPPDATA%\Programs\mcp-ssh-bridge\mcp-ssh-bridge.exe

4. Run: mcp-ssh-bridge config init

5. Ask me for my SSH server details (host, user, auth method), then run:
   mcp-ssh-bridge config add-server <name> --host <host> --user <user> --auth <agent|key|password>
   For password auth also run: mcp-ssh-bridge auth set-keychain mcp-ssh-bridge ssh-password:<name>

6. Run: mcp-ssh-bridge trust <name>

7. Register with Claude Code:
   claude mcp add --transport stdio --scope user ssh-bridge -- ~/.local/bin/mcp-ssh-bridge
   (Windows: use the full .exe path from step 3)

8. Confirm by running: mcp-ssh-bridge config validate
```

### Codex

Same prompt as above — replace step 7 with:
```
codex mcp add ssh-bridge -- ~/.local/bin/mcp-ssh-bridge
```

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
| macOS / Linux | `~/.local/bin/mcp-ssh-bridge` |
| Windows | `%LOCALAPPDATA%\Programs\mcp-ssh-bridge\mcp-ssh-bridge.exe` |

Override with `PREFIX=...` (bash) or `$env:PREFIX=...` (PowerShell).

**From source:**

```sh
git clone https://github.com/xjoker/ssh-mcp.git
cd ssh-mcp
make build   # binary at bin/mcp-ssh-bridge
```

---

## Post-install Setup

```sh
mcp-ssh-bridge config init
mcp-ssh-bridge config add-server prod --host example.com --user alice --auth agent
mcp-ssh-bridge trust prod

# Register with your AI client:
claude mcp add --transport stdio --scope user ssh-bridge -- ~/.local/bin/mcp-ssh-bridge
codex  mcp add ssh-bridge -- ~/.local/bin/mcp-ssh-bridge
```

For password auth:

```sh
mcp-ssh-bridge config add-server prod --host example.com --user alice --auth password
mcp-ssh-bridge auth set-keychain mcp-ssh-bridge ssh-password:prod
# prompts for password; nothing sensitive lands in config.toml
```

---

## What mcp-ssh-bridge Can Do

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

---

## Highlights

**Multi-hop SSH chains**
Route through bastion hosts transparently via `proxy_jump`. Chains of arbitrary depth work — A → B → C requires only `proxy_jump` entries in `config.toml`.

**PTY support**
Full pseudo-terminal allocation for `ssh_exec` and `session_start`. Run `htop`, `btop`, `ncdu`, `vim` and other TUI programs; use `strip_ansi` to get clean text back.

**OS keychain integration**
Passwords are stored in macOS Keychain, Linux libsecret, or Windows Credential Manager — never in `config.toml`. `mcp-ssh-bridge auth set-keychain` handles enrollment.

**Tag-based group operations**
Tag servers (`tags = ["prod", "eu"]`) and target entire fleets with a single `ssh_group_exec` call.

**TTL-bounded inline credentials**
`ssh_quick_setup` accepts a password or private key inline for ad-hoc sessions. Credentials live in memory and are zeroed on TTL expiry or shutdown.

**Append-only audit trail**
Every tool call is pre-recorded in a JSONL audit log before execution. `audit_query` provides structured search; credentials appear only as `{"redacted":true}`.

**Self-update**
`mcp-ssh-bridge update` fetches the latest release binary, verifies its SHA-256, and atomically replaces the running binary. The bridge also surfaces an update notice on startup when a newer version is available.

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
| macOS / Linux | `~/.config/mcp-ssh-bridge/config.toml` | `~/.local/state/mcp-ssh-bridge/` |
| Windows | `%APPDATA%\mcp-ssh-bridge\config.toml` | `%LOCALAPPDATA%\mcp-ssh-bridge\audit\` |

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
mcp-ssh-bridge config init
mcp-ssh-bridge config validate
mcp-ssh-bridge config add-server <name> --host H --user U --auth agent|key|password
mcp-ssh-bridge trust <name>
mcp-ssh-bridge auth set-keychain mcp-ssh-bridge ssh-password:<name>
mcp-ssh-bridge server list
mcp-ssh-bridge server test <name>
mcp-ssh-bridge audit query --tool ssh_exec --since 24h
mcp-ssh-bridge update
mcp-ssh-bridge install claude-code     # print claude mcp add command
mcp-ssh-bridge install codex           # print codex mcp add command
mcp-ssh-bridge install claude-desktop  # print JSON snippet
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `HOST_KEY_UNKNOWN` | `mcp-ssh-bridge trust <name>` |
| `unable to authenticate` (password) | `mcp-ssh-bridge auth set-keychain mcp-ssh-bridge ssh-password:<name>` |
| `SESSION_LIMIT` | Close idle sessions or raise `settings.max_sessions` in config |
| Bridge not appearing in AI client | Restart the AI client after `mcp add` |
| `config: no such file` | `mcp-ssh-bridge config init` |

---

## Documentation

- [`docs/AI_GUIDE.md`](docs/AI_GUIDE.md) — paste into your AI assistant after connecting; teaches tool selection, error handling, and the no-autoApprove discipline
- [`examples/`](examples/) — config and client snippets
- [`SECURITY.md`](SECURITY.md) — threat model and disclosure policy
- [`SDD.md`](SDD.md) — system design document

---

## License

Apache 2.0. See [LICENSE](LICENSE).
