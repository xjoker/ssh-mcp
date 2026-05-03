# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release: MCP server with ssh_exec, sftp_op, ssh_group_exec, tunnel tools
- Append-only audit log (JSONL)
- OS keychain integration for credential storage
- CLI subcommands: server, auth, trust, config, audit, migrate-from-legacy, migrate-passwords, install
- CI workflow (GitHub Actions, ubuntu + macos)
- Example configurations in examples/
