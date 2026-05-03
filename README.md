# mcp-ssh-bridge

An MCP (Model Context Protocol) server that exposes SSH operations as tools for
AI assistants such as Claude Desktop, Claude Code, and Codex.

## Features

- `ssh_exec` — run commands on remote servers
- `sftp_op` — file transfer operations
- `ssh_group_exec` — run commands across multiple servers in parallel
- Port-forwarding / tunnel support
- Append-only audit log (JSONL)
- Credentials stored in the OS keychain (macOS Keychain, GNOME libsecret, Windows Credential Manager)

## Installation

```sh
go install github.com/xjoker/mcp-ssh-bridge/cmd/mcp-ssh-bridge@latest
```

Or build from source:

```sh
git clone https://github.com/xjoker/mcp-ssh-bridge.git
cd mcp-ssh-bridge
go build -o bin/mcp-ssh-bridge ./cmd/mcp-ssh-bridge
```

## Quick Start

1. Copy `examples/config-min.toml` to `~/.config/mcp-ssh-bridge/config.toml` and fill in your server details.
2. Register with your AI client:

```sh
mcp-ssh-bridge install claude-desktop
# or
mcp-ssh-bridge install claude-code
# or
mcp-ssh-bridge install codex
```

3. Follow the printed instructions to add the snippet to your client config.

## Security

- **Do not add `autoApprove`** for any mcp-ssh-bridge tool. See `examples/` for safe configuration templates.
- Passwords should be stored in the OS keychain, not in config files. Use `mcp-ssh-bridge migrate-passwords` to migrate existing plaintext credentials.

## Migrating from legacy-ssh-tool

```sh
mcp-ssh-bridge migrate-from-legacy /path/to/.env
```

## Documentation

- `SDD.md` — full system design document
- `examples/` — example configurations

## License

Apache 2.0. See [LICENSE](LICENSE).
