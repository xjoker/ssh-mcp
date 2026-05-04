# Quick Start

Five minutes from zero to your first agent-driven `ssh_exec`.

## 1. Install

**macOS / Linux:**

```sh
curl -fsSL https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.sh | bash
```

**Windows (PowerShell):**

```powershell
iwr -useb https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.ps1 | iex
```

Both install user-level — no sudo / admin elevation. Defaults:
- macOS / Linux: `~/.local/bin/mcp-ssh-bridge`
- Windows: `%LOCALAPPDATA%\Programs\mcp-ssh-bridge\mcp-ssh-bridge.exe`

Or, from a local checkout: `bash scripts/install.sh` (or `.\scripts\install.ps1`).

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

Both Claude Code and Codex ship a CLI for managing MCP servers — use
that, no file-editing required:

```sh
# Claude Code (user scope = available in every project)
claude mcp add --transport stdio --scope user ssh-bridge -- ~/.local/bin/mcp-ssh-bridge

# Codex
codex mcp add ssh-bridge -- ~/.local/bin/mcp-ssh-bridge
```

Verify:

```sh
claude mcp list      # ssh-bridge should show "✓ Connected"
codex  mcp list      # ssh-bridge should show "enabled"
```

Claude **Desktop** (the macOS / Windows app) does not yet ship an MCP
CLI, so paste a small JSON snippet manually:

```sh
mcp-ssh-bridge install claude-desktop
```

Then copy the printed block into the file the command names. **Never add
`autoApprove`** for any of the tools — the printed snippet intentionally
omits it.

Restart whichever client you registered with.

## 4. Validate before first use

```sh
mcp-ssh-bridge config validate     # parses + applies all SDD rules
mcp-ssh-bridge audit query --since 1h     # confirms audit dir + read path
```

## 5. Onboard your AI assistant (one-time)

In your AI client's first message of the session:

> Read `docs/AI_GUIDE.md` from the mcp-ssh-bridge repo and follow it for
> the rest of this session. Then call `list_servers` to see what's
> available.

`docs/AI_GUIDE.md` teaches the model the read-only-vs-destructive split,
which tool to pick for which job, how to react to every error code, and
the security rules (no autoApprove, no password echoing). Doing this
once dramatically reduces back-and-forth on later requests.

## 6. First call

In your AI client, ask the agent something like:

> Use ssh_exec on server `prod` to run `uname -a`.

The agent prompts you to confirm; on approval the command runs and the
result is returned. Each invocation appends a row to the JSONL audit
log under `~/.local/state/mcp-ssh-bridge/` (Linux/macOS) or
`%LOCALAPPDATA%\mcp-ssh-bridge\audit\` (Windows).

## 7. Common follow-ups

- Add a second server: re-run `config add-server <name> ...`. The command
  refuses to overwrite an existing block, atomic-renames on success, and
  re-validates the file before commit.
- Group commands across servers with the same tag:
  > Run `df -h /` on every server tagged `prod` via `ssh_group_exec`.
- Restrict reachable paths per server with the `--allowed-paths` flag (or
  edit the TOML directly to set `allowed_paths = ["/var/www", "/tmp"]`).
- Promote a quick_setup ad-hoc registration to a permanent entry:
  re-run `config add-server` with the same host/user.

## 8. Wizard mode

Prefer prompts to flags?

```sh
bash scripts/quick-setup.sh
```

The wizard walks you through `config init` → `add-server` → `trust` →
`install <client>` and reminds you about the keychain step when relevant.
