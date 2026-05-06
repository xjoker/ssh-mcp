# mcp-ssh-bridge

An MCP (Model Context Protocol) server that exposes SSH operations as tools for
AI assistants — Claude Desktop, Claude Code, Codex.

> **Using this with an AI assistant?** After the install steps below,
> point your assistant at [`docs/AI_GUIDE.md`](docs/AI_GUIDE.md) — it
> codifies tool-selection heuristics, error-handling expectations, and
> the no-autoApprove discipline so the model behaves predictably.

## TL;DR — four commands and you're online

```sh
# 1. Install to ~/.local/bin (no sudo, no PATH surgery needed by MCP)
curl -fsSL https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.sh | bash

# 2. Interactive wizard: config → server → trust → MCP client entry
bash <(curl -fsSL https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/quick-setup.sh)
```

On Windows (PowerShell):

```powershell
iwr -useb https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.ps1 | iex
```

Prefer explicit steps?

```sh
mcp-ssh-bridge config init
mcp-ssh-bridge config add-server prod --host example.com --user alice --auth agent
mcp-ssh-bridge trust prod                                  # accept host key

# Register with your AI client using its official CLI:
claude mcp add --transport stdio --scope user ssh-bridge -- ~/.local/bin/mcp-ssh-bridge
codex  mcp add ssh-bridge -- ~/.local/bin/mcp-ssh-bridge
```

For password auth, swap the `add-server` line for:

```sh
mcp-ssh-bridge config add-server prod --host example.com --user alice --auth password
mcp-ssh-bridge auth set-keychain mcp-ssh-bridge ssh-password:prod
```

The keychain command prompts for the password without echoing it; nothing
sensitive ever lands in `config.toml`.

## Features

- `ssh_exec`, `ssh_group_exec` — run commands on one or many remote servers
- `sftp_op` — file transfer / directory operations
- Local & remote port-forward tunnels
- Persistent shell sessions with sentinel-based completion detection
- `ssh_quick_setup` — register an ad-hoc server during a chat (TTL-bounded)
- Append-only JSONL audit log; passwords stored in OS keychain
  (macOS Keychain, libsecret, Windows Credential Manager)

## Install

### One-liner (recommended)

**macOS / Linux:**

```sh
curl -fsSL https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.sh | bash
```

**Windows (PowerShell):**

```powershell
iwr -useb https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.ps1 | iex
```

Both scripts install **user-level — no sudo / admin elevation**. The MCP
binary is just a stdio process spawned by your AI client; it does not
need a system path.

| Platform | Default install path |
|----------|----------------------|
| macOS / Linux | `~/.local/bin/mcp-ssh-bridge` |
| Windows | `%LOCALAPPDATA%\Programs\mcp-ssh-bridge\mcp-ssh-bridge.exe` |

Override with `PREFIX=...` (bash) or `$env:PREFIX=...` (PowerShell).

### `go install`

```sh
go install github.com/xjoker/mcp-ssh-bridge/cmd/mcp-ssh-bridge@latest
```

### From source

```sh
git clone https://github.com/xjoker/mcp-ssh-bridge.git
cd mcp-ssh-bridge
make build       # binary at bin/mcp-ssh-bridge
```

## CLI cheat sheet

```sh
# Configuration
mcp-ssh-bridge config init                                 # write a starter config.toml
mcp-ssh-bridge config validate                             # confirm the file parses + validates
mcp-ssh-bridge config add-server <name> --host H --user U --auth agent

# Trust + auth
mcp-ssh-bridge trust <name>                                # accept first-seen host key
mcp-ssh-bridge auth set-keychain mcp-ssh-bridge ssh-password:<name>

# Register with your AI client (use the client's own CLI; no file editing)
claude mcp add --transport stdio --scope user ssh-bridge -- ~/.local/bin/mcp-ssh-bridge
codex  mcp add ssh-bridge -- ~/.local/bin/mcp-ssh-bridge

# Or print the right command/snippet for any of three targets:
mcp-ssh-bridge install claude-code     # → prints `claude mcp add ...`
mcp-ssh-bridge install codex           # → prints `codex mcp add ...`
mcp-ssh-bridge install claude-desktop  # → JSON snippet to paste (Desktop has no MCP CLI)

# Migration / audit
mcp-ssh-bridge migrate-from-legacy /path/to/.env
mcp-ssh-bridge migrate-passwords
mcp-ssh-bridge audit query --tool ssh_exec --since 24h
```

`mcp-ssh-bridge config add-server --help` for the full flag list (proxy_jump,
default_dir, allowed_paths, tags, …).

## Config file layout

Default locations (all user-level — no admin / sudo required):

| OS | Binary | Config | Audit log |
|----|--------|--------|-----------|
| macOS / Linux | `~/.local/bin/mcp-ssh-bridge` | `$XDG_CONFIG_HOME/mcp-ssh-bridge/config.toml` (default `~/.config/...`) | `$XDG_STATE_HOME/mcp-ssh-bridge/` (default `~/.local/state/...`) |
| Windows | `%LOCALAPPDATA%\Programs\mcp-ssh-bridge\mcp-ssh-bridge.exe` | `%APPDATA%\mcp-ssh-bridge\config.toml` | `%LOCALAPPDATA%\mcp-ssh-bridge\audit\` |

Override the config path with `MCP_SSH_BRIDGE_CONFIG=/path/to/config.toml`.
Override the audit dir with `MCP_SSH_BRIDGE_AUDIT_DIR=/path/to/audit/`.

Minimal example (`examples/config-min.toml`):

```toml
[servers.prod]
host = "example.com"
user = "alice"
auth = "agent"
```

A two-server example with tags and keychain auth lives at
`examples/config.toml`.

### Jump-host (bastion) configuration

Use `proxy_jump` to chain through a bastion host:

```toml
# Jump through a bastion host to reach internal-server
[servers.bastion]
host = "bastion.example.com"
port = 22
user = "ops"
auth = "key"
key_path = "~/.ssh/id_ed25519"

[servers.internal]
host = "10.0.1.50"
port = 22
user = "ops"
auth = "key"
key_path = "~/.ssh/id_ed25519"
proxy_jump = "bastion"
```

`proxy_jump` chains are recursive — A → B → C works by setting
`proxy_jump = "B"` on C and `proxy_jump = "A"` on B. Host keys for every
hop in the chain must be present in `known_hosts`; run
`mcp-ssh-bridge trust <name>` for each hop before first use.

## Security

- **Never add `autoApprove`** for any mcp-ssh-bridge tool — the example
  client snippets intentionally omit it. SSH operations have unbounded
  remote effects and must stay on the human-confirmation path.
- Plaintext passwords in config are rejected unless
  `allow_config_plaintext_password = true`. Use the keychain instead.
- Inline credentials passed via `session_start.inline` or `ssh_quick_setup`
  become TTL-bounded in-memory temp servers and are zeroed on expiry/shutdown.
- `allowed_paths` per server caps SFTP / cwd reach; symlink TOCTOU is closed
  by canonicalising through SFTP `realpath` before policy enforcement.

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `config: read ...: no such file or directory` on startup | Run `mcp-ssh-bridge config init` first. |
| `HOST_KEY_UNKNOWN` on first connection | `mcp-ssh-bridge trust <name>` to add the key to `known_hosts`. |
| `unable to authenticate` for `auth=password` | Run `mcp-ssh-bridge auth set-keychain mcp-ssh-bridge ssh-password:<name>` and confirm with `auth get-keychain`. |
| `config: validation errors:` on `add-server` | The CLI atomically aborts the write. Read the printed reason and re-issue with corrected flags. |
| Audit query hangs or returns stale | The CLI now uses the read-only opener (`audit.NewReader`). If you used a build before this change, upgrade. |
| `SESSION_LIMIT` from `session_start` | Hit the concurrency cap (default 16). Close idle sessions or raise `settings.max_sessions` in config. |

When in doubt, `mcp-ssh-bridge config validate` first — it catches almost
every "why won't it start" question.

## Migrating from a legacy `.env` setup

If you have an older SSH-tooling configuration in a flat `.env` file
(`SSH_HOST=`, `SSH_USER=`, `SSH_PASSWORD=`, …), import it once:

```sh
mcp-ssh-bridge migrate-from-legacy /path/to/legacy.env
mcp-ssh-bridge migrate-passwords     # turn any leftover plaintext into keychain refs
```

## Documentation

- **[`docs/AI_GUIDE.md`](docs/AI_GUIDE.md)** — paste this into your AI
  assistant's context once after connecting the bridge. It teaches the
  model how to pick the right tool, when to ask for confirmation, how to
  react to each error code, and what never to do (autoApprove, echoing
  passwords, etc.).
- `examples/quick-start.md` — concrete walkthrough from zero to first call
- `examples/` — config + MCP client snippets
- `SDD.md` — full system design document
- `SECURITY.md` — threat model & disclosure policy

### Onboarding an AI assistant

After installing the MCP server in your client, give the assistant a
single setup message like:

> "Read `docs/AI_GUIDE.md` from the mcp-ssh-bridge repo and follow it for
> the rest of this session. Then run `list_servers` to see what's
> available."

That single line gets the assistant onto the right rails: tool selection
heuristics, error handling, no-autoApprove discipline, and the
keychain-only secret rule.

## License

Apache 2.0. See [LICENSE](LICENSE).
