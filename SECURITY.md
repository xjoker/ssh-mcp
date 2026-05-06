# Security Policy

## Supported Versions

| Version | Status |
|---------|--------|
| `0.0.x-dev` | Active development — patches applied to `dev` branch, no LTS commitment yet |

There are no LTS releases yet. Once `0.0.1` is tagged on `main`, that line will be updated.

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

`mcp-ssh-bridge` is a stdio MCP server that runs SSH commands on behalf of an AI assistant. The primary trust boundary is between the AI client (Claude Desktop, Claude Code, Codex) and the set of servers listed in `config.toml`. The bridge acts as a policy enforcement point between the AI and those servers.

Key assumptions:

- The local machine running the bridge is trusted (same-user process).
- The MCP client (AI assistant host) is trusted; the AI model output is not.
- Remote servers are administered independently; their security is out of scope.
- The `known_hosts` file is the source of truth for host identity.

## Security Features

- **Host key verification** — all connections are checked against `~/.ssh/known_hosts` (or the path in config). `HOST_KEY_MISMATCH` is a hard stop; the bridge never auto-accepts changed keys.
- **Credential lifecycle** — inline credentials (via `session_start.inline` or `ssh_quick_setup`) are promoted to TTL-bounded in-memory temp servers and zeroed on expiry or shutdown. Plaintext passwords in `config.toml` are rejected unless `allow_config_plaintext_password = true`; the keychain backend is the default.
- **Append-only audit log** — every destructive tool call is pre-recorded before execution. The query path uses a read-only file opener (`audit.NewReader`).
- **RemoteCommand sanitisation** — no shell expansion is performed on command strings passed to `ssh_exec`. Commands are sent verbatim over the SSH exec channel, not via `/bin/sh -c`.
- **allowed_paths enforcement** — SFTP paths are canonicalised through the remote SFTP `realpath` RPC before `allowed_paths` policy is applied, closing symlink TOCTOU.
- **Session limits** — concurrent session count is capped (`settings.max_sessions`, default 16) to limit blast radius from runaway automation.
- **No autoApprove** — the example client configurations intentionally omit `autoApprove`. Destructive tools remain on the human-confirmation path.

## Out of Scope

- Security of the remote servers themselves (OS hardening, user permissions, etc.)
- Authentication of the MCP client to the bridge (the bridge trusts its stdin/stdout peer)
- Vulnerabilities in SSH server implementations on the remote hosts
