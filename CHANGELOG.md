# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Branch / version convention:
- Development happens on `dev`; releases are tagged on `main`.
- Dev versions carry a `-dev` suffix (e.g. `0.0.1-dev`); release versions
  drop the suffix (`0.0.1`). `make release VERSION=…` stamps the binary.

## [0.0.1-dev] — 2026-05-04

First public iteration. Targeted at internal smoke testing prior to the
`0.0.1` cut.

### Added
- MCP server with `ssh_exec`, `ssh_group_exec`, `sftp_op`, `sftp_list`,
  `sftp_read`, `sftp_stat`, `tunnel`, `session_*`, `ssh_quick_setup`,
  `list_servers`, `audit_query`.
- Append-only JSONL audit log with retention + read-only query path
  (`audit.NewReader`).
- OS keychain integration (macOS Keychain, libsecret, Windows Credential
  Manager) with fail-closed plaintext-password rejection.
- Persistent shell sessions with sentinel-based completion + concurrency
  cap (`settings.max_sessions`, default 16).
- Quick setup ad-hoc server registration with TTL eviction +
  cross-tool reachability through `Pool.LookupTempServer`.
- CLI: `config init` / `config validate` / `config add-server`, `auth
  set-keychain`, `trust`, `audit query`, `migrate-from-legacy`,
  `migrate-passwords`, `install <claude-desktop|claude-code|codex>`,
  `version`.
- One-liner `scripts/install.sh` and interactive
  `scripts/quick-setup.sh` wizard.
- AI assistant onboarding guide at `docs/AI_GUIDE.md`.
- CI workflow (GitHub Actions) on Ubuntu + macOS for `main` and `dev`.

### Security
- Inline credentials live only as long as the session/TTL window and are
  zeroed on close.
- SFTP `realpath` canonicalisation closes symlink TOCTOU around
  `allowed_paths`.
- `migrate-passwords` now strips `plaintext:` prefix correctly via
  `config.ParseCredRef`.
- Tunnel create does an SSH pre-flight so auth/host-key failures surface
  synchronously.

### Known limitations
- `audit query --limit` capped at 1000.
- `ListKeychain` is a stub on all backends.
