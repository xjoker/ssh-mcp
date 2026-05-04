# mcp-ssh-bridge

An MCP (Model Context Protocol) server that exposes SSH operations as tools for
AI assistants — Claude Desktop, Claude Code, Codex.

## TL;DR — three commands and you're online

```sh
# 1. Install (auto-detects sudo / falls back to ~/.local/bin)
curl -fsSL https://raw.githubusercontent.com/xjoker/mcp-ssh-bridge/main/scripts/install.sh | bash

# 2. Interactive wizard: config → server → trust → MCP client entry
bash <(curl -fsSL https://raw.githubusercontent.com/xjoker/mcp-ssh-bridge/main/scripts/quick-setup.sh)

# 3. Restart your MCP client. Done.
```

Prefer the manual path? Same flow, four explicit steps:

```sh
mcp-ssh-bridge config init
mcp-ssh-bridge config add-server prod --host example.com --user alice --auth agent
mcp-ssh-bridge trust prod                    # accepts the host key into known_hosts
mcp-ssh-bridge install claude-desktop        # or claude-code / codex
```

That's a working agent + key auth setup. For password auth swap step 2 for:

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

```sh
curl -fsSL https://raw.githubusercontent.com/xjoker/mcp-ssh-bridge/main/scripts/install.sh | bash
```

The script clones, builds with `go`, installs the binary to `/usr/local/bin`
(sudo) or `~/.local/bin` (falls back automatically), and prints the next steps.

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

# Install MCP client config
mcp-ssh-bridge install claude-desktop
mcp-ssh-bridge install claude-code
mcp-ssh-bridge install codex

# Migration / audit
mcp-ssh-bridge migrate-from-legacy /path/to/.env
mcp-ssh-bridge migrate-passwords
mcp-ssh-bridge audit query --tool ssh_exec --since 24h
```

`mcp-ssh-bridge config add-server --help` for the full flag list (proxy_jump,
default_dir, allowed_paths, tags, …).

## Config file layout

Default location:

| OS         | Path                                              |
|------------|---------------------------------------------------|
| macOS/Linux | `$XDG_CONFIG_HOME/mcp-ssh-bridge/config.toml` (default `~/.config/...`) |
| Windows    | `%APPDATA%\mcp-ssh-bridge\config.toml`            |

Override with `MCP_SSH_BRIDGE_CONFIG=/path/to/config.toml`.

Minimal example (`examples/config-min.toml`):

```toml
[servers.prod]
host = "example.com"
user = "alice"
auth = "agent"
```

A two-server example with tags and keychain auth lives at
`examples/config.toml`.

## Security

- **Never add `autoApprove`** for any mcp-ssh-bridge tool — the example
  client snippets intentionally omit it. SSH operations have unbounded
  remote effects and must stay on the human-confirmation path.
- Plaintext passwords in config are rejected unless
  `allow_config_plaintext_password = true`. Use the keychain instead.
- Inline credentials passed via `session_start.inline` or `ssh_quick_setup`
  live only as long as the session/TTL window and are zeroed on exit.
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

## Migrating from legacy-ssh-tool

```sh
mcp-ssh-bridge migrate-from-legacy /path/to/.env
mcp-ssh-bridge migrate-passwords     # turn any leftover plaintext into keychain refs
```

## Documentation

- `examples/quick-start.md` — concrete walkthrough from zero to first call
- `examples/` — config + MCP client snippets
- `SDD.md` — full system design document
- `SECURITY.md` — threat model & disclosure policy

## License

Apache 2.0. See [LICENSE](LICENSE).
