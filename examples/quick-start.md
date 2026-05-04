# Quick Start

Five minutes from zero to your first agent-driven `ssh_exec`.

## 1. Install

```sh
curl -fsSL https://raw.githubusercontent.com/xjoker/mcp-ssh-bridge/main/scripts/install.sh | bash
```

Or, from a local checkout, just `bash scripts/install.sh`.

Verify:

```sh
mcp-ssh-bridge version
```

## 2. Pick your auth flow

### a) SSH agent (no secrets in config)

```sh
mcp-ssh-bridge config init
mcp-ssh-bridge config add-server prod \
    --host example.com --user alice --auth agent \
    --tags prod,web --description "primary web box"
mcp-ssh-bridge trust prod
```

### b) Public key on disk

```sh
mcp-ssh-bridge config init
mcp-ssh-bridge config add-server prod \
    --host example.com --user alice \
    --auth key --key-path ~/.ssh/id_ed25519
mcp-ssh-bridge trust prod
```

### c) Password (stored in OS keychain, never in config)

```sh
mcp-ssh-bridge config init
mcp-ssh-bridge config add-server prod \
    --host example.com --user alice --auth password
mcp-ssh-bridge auth set-keychain mcp-ssh-bridge ssh-password:prod
mcp-ssh-bridge trust prod
```

`set-keychain` reads the password from stdin without echoing.

## 3. Plug into your MCP client

Pick one — the CLI prints the snippet and exact target path:

```sh
mcp-ssh-bridge install claude-desktop
mcp-ssh-bridge install claude-code
mcp-ssh-bridge install codex
```

Paste the printed block into the indicated config file. **Do not add
`autoApprove`** for any of the tools — the printed snippet intentionally
omits it.

Restart your MCP client.

## 4. Validate before first use

```sh
mcp-ssh-bridge config validate     # parses + applies all SDD rules
mcp-ssh-bridge audit query --since 1h     # confirms audit dir + read path
```

## 5. First call

In your AI client, ask the agent something like:

> Use ssh_exec on server `prod` to run `uname -a`.

The agent prompts you to confirm; on approval the command runs and the
result is returned. Each invocation appends a row to the JSONL audit
log under `~/.local/state/mcp-ssh-bridge/` (Linux/macOS) or
`%LOCALAPPDATA%\mcp-ssh-bridge\audit\` (Windows).

## Common follow-ups

- Add a second server: re-run `config add-server <name> ...`. The command
  refuses to overwrite an existing block, atomic-renames on success, and
  re-validates the file before commit.
- Group commands across servers with the same tag:
  > Run `df -h /` on every server tagged `prod` via `ssh_group_exec`.
- Restrict reachable paths per server with the `--allowed-paths` flag (or
  edit the TOML directly to set `allowed_paths = ["/var/www", "/tmp"]`).
- Promote a quick_setup ad-hoc registration to a permanent entry:
  re-run `config add-server` with the same host/user.

## Wizard mode

Prefer prompts to flags?

```sh
bash scripts/quick-setup.sh
```

The wizard walks you through `config init` → `add-server` → `trust` →
`install <client>` and reminds you about the keychain step when relevant.
