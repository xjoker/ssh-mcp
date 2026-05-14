# Contributing to ssh-mcp

## Development Setup

Requirements: **Go 1.25+** (see `go.mod` for the canonical minimum; CI runs the latest 1.26.x for the stdlib CVE fixes — set up a recent toolchain locally to match).

```sh
git clone https://github.com/xjoker/ssh-mcp.git
cd ssh-mcp
go build ./...          # compile everything
go test ./...           # run the test suite
```

No additional toolchain setup is required for basic development.

## Running Tests

```sh
go test -race ./...            # full suite with race detector (required before PR)
bash scripts/check-deps.sh     # verify dependency hygiene
```

All tests must pass with `-race` before a PR is considered ready.

## Code Style

- Format with `gofmt` (or `goimports`). No external linters are required.
- Zero tolerance for `TODO` / `FIXME` comments in submitted code — either
  fix the issue or open a GitHub issue and reference it in a comment.
- Keep functions short and focused; prefer explicit error returns over panics.

## Commit Format

Conventional Commits are preferred:

```
feat: add PTY session support to session_start
fix: zero inline credentials on session close
docs: expand SECURITY.md with threat model
test: add sentinel detection edge case
chore: bump golang.org/x/crypto to v0.23.0
```

Use the imperative mood in the subject line. Keep the subject under 72 characters.

## Pull Request Checklist

- [ ] `go test -race ./...` passes locally
- [ ] New features include unit tests covering the happy path and at least one error path
- [ ] Security-sensitive changes (credential handling, host key logic, audit path) include a note in the PR description explaining the threat being addressed or mitigated
- [ ] No new `TODO` / `FIXME` comments
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` if the change is user-visible

## Security

Do not commit credentials, private keys, or test passwords — even in test fixtures. Use placeholder strings like `"REDACTED"` or generate throwaway keys in `TestMain`.

To report a security vulnerability, follow the process in [SECURITY.md](SECURITY.md) rather than opening a public issue.
