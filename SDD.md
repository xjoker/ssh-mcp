# mcp-ssh-bridge — Software Design Document

**Version:** 1.0 (MVP design lock)
**Status:** Approved for implementation
**Last updated:** 2026-05-03
**Document type:** Software Design Document (SDD)
**License:** Apache-2.0
**Target language:** Go 1.22+

---

## Table of Contents

1. [Goals and Non-Goals](#1-goals-and-non-goals)
2. [Background and Motivation](#2-background-and-motivation)
3. [Threat Model](#3-threat-model)
4. [Architecture Overview](#4-architecture-overview)
5. [Module Specifications](#5-module-specifications)
6. [Tool Specifications](#6-tool-specifications)
7. [Configuration Specification](#7-configuration-specification)
8. [Authentication and Credential Handling](#8-authentication-and-credential-handling)
9. [Audit Log Specification](#9-audit-log-specification)
10. [Error Model](#10-error-model)
11. [CLI Subcommands](#11-cli-subcommands)
12. [Connection and Session Lifecycle](#12-connection-and-session-lifecycle)
13. [Security Hard Constraints](#13-security-hard-constraints)
14. [Project Layout and Build](#14-project-layout-and-build)
15. [Testing Strategy](#15-testing-strategy)
16. [Release and Versioning](#16-release-and-versioning)
17. [Appendix A: Dependency Pinning](#appendix-a-dependency-pinning)
18. [Appendix B: Migration Guide from legacy-ssh-tool](#appendix-b-migration-guide-from-legacy-ssh-tool)

---

## 1. Goals and Non-Goals

### 1.1 Goals

`mcp-ssh-bridge` is a Model Context Protocol (MCP) server that exposes SSH and
SFTP capabilities to LLM clients (Claude Desktop, Claude Code, OpenAI Codex,
Cursor, etc.) through a small, security-first tool surface.

The MVP must:

1. Provide a minimal, composable set of SSH/SFTP tools that an LLM can use to
   manage remote Linux/Unix servers.
2. Enforce strict host key verification on every connection — no TOFU
   shortcuts, no "auto-accept" defaults.
3. Keep credentials out of plaintext storage by default. Where plaintext is
   permitted (ad-hoc and explicit opt-in), the credential lifetime is bounded
   and visible to the user.
4. Maintain an append-only audit log that the LLM itself can query, so it has
   accurate context about prior actions.
5. Refuse to enable patterns that turn an LLM into an unconfined remote
   command executor (no `sudo` tool, no SQL "safety" theater, no autoApprove
   templates).
6. Ship as a single static binary with no runtime dependencies except a
   working OS keychain (macOS Keychain, Linux Secret Service, or Windows
   Credential Manager).

### 1.2 Non-Goals (MVP)

The following are explicitly out of scope for v1.0:

- Multi-user or role-based access control
- Database-specific tools (no `mysql_dump`, `pg_query`, `mongo_*`)
- Health monitoring tools (no `health_check`, `service_status`,
  `process_manager`) — these are all expressible through `ssh_exec`
- Backup scheduling or cron management
- Hook system, profile system, command alias system
- SQLite mirror for audit log (planned for v0.2)
- Web UI or management interface
- Resumable upload / download
- Server-side cron scheduling
- Kerberos / GSSAPI authentication
- SSH protocol v1 support (refuse outright)

### 1.3 Audience

This document is written for:

- The author (V) implementing the project
- Future contributors performing code review
- Security reviewers auditing the project
- LLM coding agents (Claude Code, Codex) assisting implementation

---

## 2. Background and Motivation

This project exists in response to a security review of
`a-legacy-ssh-tool`, a popular MCP SSH server that ships with the
following defects (verified by source inspection on 2026-05-03):

| Defect in original project | Severity | Our response |
|---|---|---|
| `hostVerifier` returns `true` for unknown hosts; for known hosts a `TODO` admits no fingerprint comparison is performed | Critical | Strict `knownhosts` callback, fail-closed |
| `cwd` parameter interpolated directly into `cd ${cwd} && ...` — shell injection | Critical | Newtype `RemotePath`; resolved via SFTP `realpath`, never via shell concatenation |
| Sudo password passed via `echo "$pwd" \| sudo -S ...` — leaks via `ps`, breaks on quoting | Critical | No sudo tool exposed; users configure NOPASSWD or use sessions |
| `isSafeQuery` checks substrings — both false-positive and bypassable; query interpolated into shell | Critical | No DB tools |
| Default cipher list includes `ssh-rsa`, `*-cbc`, `hmac-sha1`, `dh-group14-sha1` | High | Modern algorithm defaults; weak algorithms require explicit opt-in |
| Plaintext credentials in `.env` / `config.toml` with no migration path | High | Default-rejected; opt-in flag with persistent warning; keychain helper for migration |
| `examples/claude-code-config.example.json` recommends auto-approving `ssh_execute_sudo`, `ssh_deploy`, etc. | High | We do not ship an autoApprove example. README explicitly recommends against it. |
| 4,700-line `index.js`; 38 tools; no decomposition | Medium | 13 tools; per-module package boundaries; <250 LOC per file target |

The motivation is not to "rewrite the project better" but to **publish a
counter-example**: a small, auditable, default-secure SSH bridge that
demonstrates what MCP servers handling privileged operations should look
like.

---

## 3. Threat Model

This section is **mandatory reading** for anyone reviewing or extending this
project. Every other section depends on it.

### 3.1 Trust Boundaries

```
┌────────────────────────────────┐
│   User (operator)              │  TRUSTED — initiates session
└──────────────┬─────────────────┘
               │
┌──────────────▼─────────────────┐
│   LLM client (Claude/Codex)    │  PARTIALLY TRUSTED — may be prompt-
│   - has access to user data,   │  injected via files, web content,
│     web content, files         │  email, etc. that it reads during
└──────────────┬─────────────────┘  the conversation
               │ stdio JSON-RPC
┌──────────────▼─────────────────┐
│   mcp-ssh-bridge process       │  TRUSTED — is the policy enforcer
│   (THIS PROJECT)               │
└──────────────┬─────────────────┘
               │ SSH/SFTP
┌──────────────▼─────────────────┐
│   Remote SSH server            │  PARTIALLY TRUSTED — may be
│                                │  attacker-controlled (especially in
│                                │  ad-hoc connections to unknown IPs)
└────────────────────────────────┘
```

### 3.2 Adversaries

We design against the following adversaries:

**A1 — Prompt-injection adversary.** Indirect prompt injection in a document,
webpage, repo README, email, or chat log that the LLM ingests. The adversary
controls a fragment of the LLM's input but not the user's typed messages.
This is the **primary** adversary.

**A2 — Compromised remote host.** A remote SSH server (especially one used
ad-hoc) under attacker control, attempting to deceive the bridge or exfiltrate
local credentials.

**A3 — Local filesystem reader.** A process or user with read access to the
operator's home directory, looking for stored credentials.

**A4 — Network MITM.** An attacker on the path between bridge and remote SSH
server.

We explicitly do **not** defend against:

- A user who has already root on the operator's local machine
- A user who has compromised the LLM provider's infrastructure
- Side-channel attacks against the SSH cipher suite

### 3.3 Attack Goals and Mitigations

| Goal | Adversary | Mitigation |
|---|---|---|
| Execute commands on the operator's production server through prompt injection | A1 | Strict tool surface; no autoApprove example; ad-hoc credentials require explicit user typing; audit log makes post-hoc detection possible |
| Inject shell metacharacters via tool arguments (`cwd`, `path`, `query`) | A1 | All paths typed as `RemotePath`; never concatenated into shell strings; SFTP-level path resolution |
| Steal SSH credentials by getting the LLM to connect to attacker-controlled host | A1, A2 | Strict `known_hosts` enforcement; first-time connections require explicit `trust` CLI command or `accept_new_host: true` flag; audit log records all connection attempts |
| Leak passwords via process list (`ps aux`) | A2 (remote) | No `echo PASSWORD \| sudo -S`; passwords passed only via SSH protocol (not shell) |
| MITM a connection on first use | A4 | Strict host-key check by default; new hosts require explicit operator action |
| Exfiltrate credentials via audit log | A3 | Audit log is `0600`; passwords scrubbed via redactor; ad-hoc inline credentials never written to disk |
| Persist plaintext credentials via casual configuration | A3 | Config plaintext rejected by default; opt-in requires explicit flag; warning printed at every startup |
| Cause LLM context overflow / DoS via huge command output | A2 | All `ssh_exec` outputs truncated at configurable size; SFTP reads bounded |

### 3.4 Defense Posture

The bridge is **fail-closed**. When in doubt:

- Reject the operation
- Return a typed error
- Log the rejection
- Never silently substitute a less-safe alternative

The bridge is **not** the last line of defense. The remote system's own
permissions (file ACLs, sudo policy, SELinux/AppArmor) are still required.
But the bridge must not weaken those.

---

## 4. Architecture Overview

### 4.1 Process Model

`mcp-ssh-bridge` is a single Go binary running as a child process of the LLM
client (Claude Desktop, Claude Code, etc.) over stdio.

```
                     stdio (JSON-RPC 2.0)
   ┌─────────────┐ ◄──────────────────────► ┌─────────────────────┐
   │ LLM client  │                          │ mcp-ssh-bridge      │
   └─────────────┘                          │  ┌──────────────┐   │
                                            │  │ MCP layer    │   │
                                            │  │ (go-sdk)     │   │
                                            │  └──────┬───────┘   │
                                            │         │           │
                                            │  ┌──────▼───────┐   │
                                            │  │ tool dispatch│   │
                                            │  │ + audit MW   │   │
                                            │  └──────┬───────┘   │
                                            │         │           │
                                            │  ┌──────▼───────┐   │
                                            │  │ ssh / sftp / │   │
                                            │  │ session pool │   │
                                            │  └──────┬───────┘   │
                                            └─────────┼───────────┘
                                                      │ SSH/SFTP
                                                      ▼
                                              ┌──────────────┐
                                              │ remote hosts │
                                              └──────────────┘
```

A second invocation mode exists for CLI subcommands (`trust`, `auth set`,
`migrate-passwords`, etc.); see [§11](#11-cli-subcommands).

### 4.2 Layered Module Map

```
                   ┌──────────────────────────────┐
   entry           │ cmd/mcp-ssh-bridge           │
                   │  main.go (MCP) │ cli.go (CLI)│
                   └───────────┬──────────────────┘
                               │
                   ┌───────────▼──────────────────┐
   tool layer     │ internal/tools                │
                   │  one file per tool            │
                   │  uses envelope + audit MW     │
                   └───────────┬──────────────────┘
                               │
                   ┌───────────▼──────────────────┐
   service layer  │ internal/ssh, sftp,           │
                   │ session, tunnel              │
                   └───────────┬──────────────────┘
                               │
                   ┌───────────▼──────────────────┐
   support layer  │ internal/auth, config, audit, │
                   │ safety, envelope             │
                   └──────────────────────────────┘
```

Dependencies flow downward only. No upward import is permitted (enforced via
`go vet` + a custom dependency check in CI).

### 4.3 Data Flow for a Typical Command

For `ssh_exec(server="prod-web", command="df -h", cwd="/var/log")`:

```
1. MCP layer  : decode tool call, invoke registered handler
2. Tool layer : ssh_exec.Handle()
                 ├─ validate args (jsonschema)
                 ├─ resolve server config (config.Resolve)
                 ├─ resolve credentials (auth.Resolve)
                 │   - agent? key? keychain ref? env ref? plaintext?
                 ├─ acquire connection (ssh.Pool.Get)
                 │   - reuse if alive, dial if not
                 │   - host key check via knownhosts (strict)
                 ├─ resolve cwd to absolute path (sftp.Realpath)
                 │   - NOT shell concatenation
                 ├─ build remote command (safety.RemoteCommand)
                 │   - cd via SSH "exec" channel env, not shell
                 ├─ execute (ssh.ExecBuffered or ssh.ExecStreaming)
                 ├─ truncate output if needed
                 └─ return envelope { ok, data, error }
3. Audit MW   : write JSONL line (with redaction)
4. MCP layer  : encode response, send to client
```

Every step has a typed error path that returns an envelope; no panics escape
to the MCP layer (handled via `recover` middleware).

### 4.4 Concurrency Model

- One goroutine per active MCP request (managed by the SDK).
- Connection pool uses `sync.Mutex` + per-server `sync.RWMutex` for state
  transitions; SSH `*ssh.Client` is goroutine-safe for parallel session
  creation per the upstream docs.
- Sessions (`internal/session`) are owned by a single goroutine reading
  output; commands are serialized via a per-session command queue.
- Tunnels run independent goroutines; closure is via `context.CancelFunc`.
- All `time.AfterFunc` timers and goroutines are tracked so that on shutdown
  they can be drained within a 5s deadline.

### 4.5 Shutdown

On `SIGINT` / `SIGTERM` / stdio EOF:

1. Stop accepting new tool calls.
2. Cancel all in-flight commands (their contexts).
3. Close all sessions (`session.CloseAll`).
4. Close all tunnels (`tunnel.CloseAll`).
5. Close all SSH clients (`ssh.Pool.Close`).
6. Flush audit log (`audit.Flush`).
7. Exit code 0 on clean shutdown, 1 on forced kill.

A 5s deadline applies to steps 2–6; anything still running is force-killed.


---

## 5. Module Specifications

Each module is a Go package under `internal/`. This section defines public
interfaces. Implementation details that don't affect the contract are left to
the implementer.

### 5.1 `internal/envelope`

The response envelope used uniformly by all tools.

```go
package envelope

// Response is the unified response shape returned by every tool.
// It maps onto MCP CallToolResult.Content as a single TextContent
// containing JSON-encoded Response.
type Response struct {
    OK    bool        `json:"ok"`
    Data  any         `json:"data,omitempty"`
    Error *Error      `json:"error,omitempty"`
}

type Error struct {
    Code      string `json:"code"`       // see §10
    Message   string `json:"message"`    // human-readable, may quote remote stderr
    Retriable bool   `json:"retriable"`
    Hint      string `json:"hint,omitempty"` // optional remediation guidance
}

// Helpers
func OK(data any) Response { return Response{OK: true, Data: data} }
func Err(code, msg string, retriable bool) Response {
    return Response{OK: false, Error: &Error{Code: code, Message: msg, Retriable: retriable}}
}
func ErrWithHint(code, msg, hint string, retriable bool) Response { ... }
```

The MCP `isError` flag is set to `true` whenever `OK == false`, so MCP-aware
clients see consistent semantics. The structured `error.code` is the source
of truth for programmatic / LLM consumption.

### 5.2 `internal/config`

Loads, validates, and resolves TOML configuration.

```go
package config

type Settings struct {
    AllowConfigPlaintextPassword bool          `toml:"allow_config_plaintext_password"` // default false
    AllowInlineCredentials       bool          `toml:"allow_inline_credentials"`        // default true
    AllowQuickSetup              bool          `toml:"allow_quick_setup"`               // default true
    DefaultTimeoutMs             int           `toml:"default_timeout_ms"`              // default 120000
    MaxTimeoutMs                 int           `toml:"max_timeout_ms"`                  // default 1800000
    OutputMaxBytes               int           `toml:"output_max_bytes"`                // default 65536
    SftpProgressThresholdBytes   int           `toml:"sftp_progress_threshold_bytes"`   // default 10*1024*1024
    SessionIdleSeconds           int           `toml:"session_idle_seconds"`            // default 3600
    ConnIdleSeconds              int           `toml:"conn_idle_seconds"`               // default 600
    AuditRetentionDays           int           `toml:"audit_retention_days"`            // default 90
    WeakAlgorithmsOptIn          []string      `toml:"weak_algorithms_opt_in"`          // default empty
}

type ServerConfig struct {
    Name           string   // map key, lowercased
    Host           string   `toml:"host"`            // required
    Port           int      `toml:"port"`            // default 22
    User           string   `toml:"user"`            // required
    Auth           string   `toml:"auth"`            // "agent" | "key" | "password"
    KeyPath        string   `toml:"key_path"`
    KeyPassphrase  CredRef  `toml:"key_passphrase"`  // see §8
    Password       CredRef  `toml:"password"`        // see §8
    DefaultDir     string   `toml:"default_dir"`
    Description    string   `toml:"description"`
    ProxyJump      string   `toml:"proxy_jump"`      // name of another server
    AllowedPaths   []string `toml:"allowed_paths"`
    Tags           []string `toml:"tags"`
}

type Config struct {
    Settings Settings
    Servers  map[string]ServerConfig
}

// Load reads from path, validates, returns Config or error.
// Validation includes:
//   - required fields present
//   - auth method consistent with provided credential fields
//   - plaintext passwords rejected unless Settings.AllowConfigPlaintextPassword
//   - proxy_jump references resolve to defined servers
//   - no cycles in proxy_jump chains
//   - each `tags` entry matches /^[a-z0-9_-]+$/
//   - paths in allowed_paths are absolute
func Load(path string) (*Config, error)

// DefaultPath returns the OS-appropriate config path:
//   macOS:   $XDG_CONFIG_HOME/mcp-ssh-bridge/config.toml or ~/.config/...
//   Linux:   $XDG_CONFIG_HOME/mcp-ssh-bridge/config.toml or ~/.config/...
//   Windows: %APPDATA%\mcp-ssh-bridge\config.toml
func DefaultPath() string

// PrintPlaintextWarning emits the stderr warning when plaintext passwords
// are present and the opt-in flag is true. Called once at startup.
func (c *Config) PrintPlaintextWarning()
```

`CredRef` is parsed from a string and represents one of:

| String form | Meaning |
|---|---|
| `keychain:<service>:<account>` | macOS Keychain / Linux Secret Service / Windows CM lookup |
| `env:VAR_NAME` | environment variable lookup |
| `plaintext:<value>` | inline plaintext (rejected unless opt-in) |
| `<bareword>` | shorthand for `plaintext:<bareword>` (also rejected without opt-in) |

The bareword shorthand exists only to give a meaningful error when users
write `password = "abc123"`: the validator says "this is plaintext, set
`allow_config_plaintext_password = true` to permit, or use a `keychain:`
reference."

### 5.3 `internal/auth`

Resolves a `CredRef` into an actual secret in memory, with zero persistence.

```go
package auth

// Secret is a wrapper around []byte that scrubs itself on Close.
// Always use Bytes() inside a defer s.Close() pattern.
type Secret struct { /* opaque */ }

func (s *Secret) Bytes() []byte
func (s *Secret) String() string  // panics — secrets must not be stringified
func (s *Secret) Close()           // overwrites with zeros and releases

// Resolve resolves a CredRef to a Secret.
// Errors:
//   - ErrKeychainUnavailable
//   - ErrKeyNotFound
//   - ErrPlaintextDisabled (when opt-in is false)
func Resolve(ctx context.Context, ref config.CredRef, allowPlaintext bool) (*Secret, error)

// SetKeychain stores a secret. Used by 'mcp-ssh-bridge auth set'.
func SetKeychain(service, account string, secret []byte) error
func DeleteKeychain(service, account string) error
func ListKeychain(service string) ([]string, error)

// Agent returns an active ssh-agent client if SSH_AUTH_SOCK is set, else nil.
func Agent() agent.ExtendedAgent

// LoadPrivateKey parses a PEM private key, optionally with passphrase.
// Detects passphrase requirement and returns ErrPassphraseRequired if so.
func LoadPrivateKey(pem []byte, passphrase *Secret) (ssh.Signer, error)
```

The `Secret` type's contract:

- `Bytes()` returns the raw secret as a slice. Caller must not retain
  references beyond the immediate use.
- `String()` panics — secrets must never be formatted as strings (no
  `fmt.Sprintf("%v", ...)` accidents).
- `Close()` overwrites the underlying buffer with zeros via
  `crypto/subtle.ConstantTimeCompare` style memset and calls
  `runtime.KeepAlive` to prevent compiler optimization.
- Passing a `Secret` over the network (e.g., to ssh.ClientConfig.Auth) is
  done via `ssh.Password(string(s.Bytes()))` only at the moment of
  connection, then `s.Close()` is called immediately after the connection
  is established.

### 5.4 `internal/safety`

Centralizes all input-validation and escape logic. **Every other module
must use this package**, never its own ad-hoc validation.

```go
package safety

// RemotePath is a validated absolute POSIX path on a remote host.
// Construction goes through ValidateRemotePath; once constructed,
// it is safe to use in SFTP calls but NEVER in shell-string
// interpolation.
type RemotePath struct { p string }
func (r RemotePath) String() string { return r.p }

// ValidateRemotePath parses and rejects:
//   - empty strings
//   - non-absolute paths (after expansion)
//   - paths containing NUL bytes
//   - paths exceeding 4096 bytes
//
// It does NOT resolve `~` here — that requires a live connection;
// see ssh.ResolveHome for that path.
func ValidateRemotePath(p string) (RemotePath, error)

// CheckAllowed returns nil if path is within any of allowedPrefixes,
// else ErrPathNotAllowed. Empty allowedPrefixes means "all allowed".
// Comparison uses cleaned paths and is prefix-aware (allowed=/var
// permits /var/log but not /var-other).
func CheckAllowed(path RemotePath, allowedPrefixes []string) error

// RedactSecret scans a byte slice for known secret patterns and
// replaces them with "***REDACTED***". Patterns include:
//   - PEM blocks (-----BEGIN ... -----END ...)
//   - lines matching (?i)(password|passwd|secret|token|apikey|api_key)\s*[:=]\s*\S+
//   - URLs with userinfo (https://user:pass@host)
//   - AWS/GCP/Azure key prefixes (best effort)
// Used by audit log writer.
func RedactSecret(b []byte) []byte

// HostKeyCallback returns a callback for ssh.ClientConfig.HostKeyCallback
// that reads from ~/.ssh/known_hosts (and optionally a project-local
// known_hosts file) and rejects mismatches.
//
// If acceptNew is true, unknown hosts are accepted AND appended to
// the known_hosts file. acceptNew must only be set by:
//   - the CLI 'trust' command
//   - an ad-hoc tool call with explicit accept_new_host: true
//
// Mismatch is always rejected, regardless of acceptNew.
func HostKeyCallback(acceptNew bool) ssh.HostKeyCallback

// ModernAlgorithms returns ssh.Config{KeyExchanges, Ciphers, MACs,
// HostKeyAlgorithms} excluding deprecated entries (no ssh-rsa SHA1,
// no CBC, no SHA1 HMAC, no DH-group14-SHA1).
//
// optIn is consulted to re-enable specific deprecated algorithms by
// exact name. Any name in optIn that is unknown produces a startup
// warning but is silently dropped.
func ModernAlgorithms(optIn []string) ssh.Config
```

`safety` has zero dependencies on any other internal package (besides
`config.CredRef` types if needed) so it can be unit-tested in isolation.

### 5.5 `internal/ssh`

Wraps `golang.org/x/crypto/ssh` with our specific semantics.

```go
package ssh

// Pool manages reusable connections, keyed by server name.
// Ad-hoc connections are NOT stored in the pool.
type Pool struct { /* opaque */ }

func NewPool(cfg *config.Config) *Pool

// Get returns an alive *Client for the named server, dialing if needed.
// Concurrent Get() calls for the same server are coalesced.
func (p *Pool) Get(ctx context.Context, name string) (*Client, error)

// GetAdHoc dials a one-shot connection. Caller is responsible for
// calling client.Close() when done; the connection is not pooled.
func (p *Pool) GetAdHoc(ctx context.Context, params AdHocParams) (*Client, error)

// CloseIdle closes connections idle longer than threshold.
// Called by the idle reaper goroutine.
func (p *Pool) CloseIdle(threshold time.Duration)

func (p *Pool) Close() error

type AdHocParams struct {
    Host             string
    Port             int
    User             string
    Auth             AuthMethod   // PrivateKey | Password | Agent
    AcceptNewHost    bool
}

type Client struct { /* wraps *ssh.Client + metadata */ }

// ExecBuffered runs cmd to completion and returns full stdout/stderr.
// Output exceeding outputMax is truncated; truncated flag is set.
// Cancellation via ctx (sends SIGTERM via signal channel, then closes).
func (c *Client) ExecBuffered(ctx context.Context, cmd RemoteCommand, opts ExecOpts) (*ExecResult, error)

// ExecStreaming runs cmd and invokes onStdout/onStderr for each chunk.
// onStdout receives chunks of up to chunkSize bytes; the final call
// has eof=true. Used by the stream=true path of ssh_exec.
func (c *Client) ExecStreaming(ctx context.Context, cmd RemoteCommand, opts StreamOpts) error

type RemoteCommand struct {
    // Built via safety.NewRemoteCommand to ensure no shell injection.
    // The cwd, if set, is applied via SFTP-resolved absolute path
    // and prepended as `cd <quoted> && ` ONLY through this constructor,
    // which uses single-quote escaping of the absolute path.
    raw string  // unexported
}

type ExecResult struct {
    Stdout    []byte
    Stderr    []byte
    ExitCode  int
    Signal    string
    Truncated bool
    Duration  time.Duration
}

// SFTP returns a per-connection SFTP client (lazily created, one per
// *Client, closed with the client).
func (c *Client) SFTP() (*sftp.Client, error)

// ResolveHome runs a single, parameter-free `pwd` after `cd ~` to
// determine the user's home directory. Cached on the Client. Used
// to expand `~` in user-supplied paths before they hit safety.RemotePath.
func (c *Client) ResolveHome(ctx context.Context) (string, error)
```

The `RemoteCommand` type is the **only** way to construct a command string.
Its constructor in `safety` is:

```go
// NewRemoteCommand builds a command, optionally prefixed with `cd <dir>`.
// The dir, if non-empty, must be an absolute path (use SFTP realpath
// upstream); it is single-quoted before being used in a shell command.
// The cmd argument is the user-supplied command verbatim — we trust the
// LLM to write valid shell, but we do NOT splice arbitrary user input
// into shell metasyntax ourselves.
func NewRemoteCommand(cmd string, dir string) (RemoteCommand, error)
```

The reason the `cmd` itself is not escape-processed: an LLM legitimately
needs to write things like `df -h | grep /var | awk '{print $5}'`. Trying
to whitelist or escape these would cripple the tool. Our injection
defense applies to the **argument** values we splice (cwd, paths),
not to the command body.

### 5.6 `internal/sftp`

A thin wrapper over `pkg/sftp` adding our path validation, progress
notifications, and result types.

```go
package sftp

type Client struct { /* wraps *sftp.Client */ }

func New(sshClient *ssh.Client) (*Client, error)

// List returns directory entries with stat info already populated.
func (c *Client) List(path safety.RemotePath) ([]Entry, error)

// Stat returns single file metadata.
func (c *Client) Stat(path safety.RemotePath) (Entry, error)

// Read reads [offset, offset+length) from path.
// If progressCb is non-nil and length > threshold, progressCb is
// invoked periodically with (bytesRead, totalLength).
//
// The caller is responsible for ensuring length is reasonable; this
// function does not enforce a per-call max (that's the tool layer's
// job, since limits depend on whether output goes to LLM context or
// to a local file).
func (c *Client) Read(path safety.RemotePath, offset, length int64,
    progressCb func(read, total int64)) ([]byte, error)

// Write writes data to path with mode. If atomic is true, writes to a
// temp file in the same directory and renames over.
// If progressCb is non-nil and len(data) > threshold, periodic.
func (c *Client) Write(path safety.RemotePath, data []byte, mode os.FileMode,
    atomic bool, progressCb func(written, total int64)) error

func (c *Client) Mkdir(path safety.RemotePath, mode os.FileMode, recursive bool) error
func (c *Client) Remove(path safety.RemotePath, recursive bool) error
func (c *Client) Rename(from, to safety.RemotePath) error
func (c *Client) Chmod(path safety.RemotePath, mode os.FileMode) error
func (c *Client) Symlink(target, linkPath safety.RemotePath) error
func (c *Client) Realpath(path string) (safety.RemotePath, error)  // expands ~ and resolves

type Entry struct {
    Name     string      `json:"name"`
    Path     string      `json:"path"`
    Size     int64       `json:"size"`
    Mode     string      `json:"mode"`     // e.g. "drwxr-xr-x"
    ModeBits uint32      `json:"mode_bits"`
    ModTime  time.Time   `json:"mod_time"`
    IsDir    bool        `json:"is_dir"`
    IsLink   bool        `json:"is_link"`
    LinkTo   string      `json:"link_to,omitempty"`
}
```

### 5.7 `internal/session`

Persistent shell sessions for multi-step interactions.

```go
package session

type Manager struct { /* opaque */ }

func NewManager(pool *ssh.Pool, idleTimeout time.Duration) *Manager

// Start opens a new persistent shell session.
// Returns a session ID (UUID v4).
func (m *Manager) Start(ctx context.Context, server string) (id string, err error)

// Send writes a command to the session and waits for completion or timeout.
// Completion is determined by a server-injected sentinel pattern,
// NOT by regex on prompt characters.
func (m *Manager) Send(ctx context.Context, id, command string, timeout time.Duration) (*SendResult, error)

func (m *Manager) Close(id string) error
func (m *Manager) List() []SessionInfo
func (m *Manager) CloseAll()

type SendResult struct {
    Stdout   string
    Stderr   string  // best-effort separation
    ExitCode int
    Duration time.Duration
}

type SessionInfo struct {
    ID           string
    Server       string
    StartedAt    time.Time
    LastActivity time.Time
    CommandCount int
}
```

**Sentinel-based completion (corrects original project's broken regex):**

When a session is started, we send a probe command:

```sh
export __MSB_SENTINEL='msb-sentinel-<random_bytes_hex>'
```

Each `Send(cmd)` is wrapped:

```sh
{ <cmd> ; } ; __rc=$? ; printf '\n%s %s\n' "$__MSB_SENTINEL" "$__rc"
```

The reader scans the output stream for a line matching exactly
`<sentinel> <integer>`. That line is consumed (not returned to the user)
and its integer becomes the exit code. This gives us:

- Reliable completion detection (random sentinel can't be forged in
  benign command output)
- Real exit codes (not the original project's "command not found" string
  match)
- Stderr separation: a separate exec channel is used for the wrapper, and
  stderr is captured naturally via the SSH session's stderr stream.

### 5.8 `internal/tunnel`

Local and remote port forwarding.

```go
package tunnel

type Manager struct { /* opaque */ }

func NewManager(pool *ssh.Pool) *Manager

// CreateLocal sets up a local listener that forwards each connection
// to dstHost:dstPort via the named server.
func (m *Manager) CreateLocal(server string, localBind string, localPort int,
    dstHost string, dstPort int) (id string, err error)

// CreateRemote sets up a remote listener on the SSH server forwarding
// to localHost:localPort.
func (m *Manager) CreateRemote(server string, remoteBind string, remotePort int,
    localHost string, localPort int) (id string, err error)

func (m *Manager) Close(id string) error
func (m *Manager) List() []TunnelInfo
func (m *Manager) CloseAll()

type TunnelInfo struct {
    ID            string
    Type          string  // "local" | "remote"
    Server        string
    LocalAddr     string  // for local: bind addr; for remote: forwarded-to
    RemoteAddr    string  // for local: forwarded-to; for remote: bind addr
    StartedAt     time.Time
    BytesIn       int64   // accumulated through all connections
    BytesOut      int64
    ConnCount     int
}
```

Tunnel handlers count bytes for audit purposes. SOCKS support is
**not** in MVP.

### 5.9 `internal/audit`

Append-only JSONL audit log with secret redaction.

```go
package audit

type Logger struct { /* opaque */ }

func New(dir string, retentionDays int) (*Logger, error)

// Record writes a single audit entry. If write fails, returns error and
// the caller MUST refuse to execute the underlying operation.
// (fail-closed contract)
func (l *Logger) Record(e Entry) error

func (l *Logger) Flush() error
func (l *Logger) Close() error

// Query is used by audit_query tool. Returns entries matching filter,
// most recent first, up to limit.
func (l *Logger) Query(f Filter) ([]Entry, error)

type Entry struct {
    Timestamp     time.Time `json:"timestamp"`
    SessionID     string    `json:"session_id"`        // MCP session id
    Tool          string    `json:"tool"`
    Server        string    `json:"server,omitempty"`
    AuthMode      string    `json:"auth_mode,omitempty"` // agent|key|key+passphrase|password_keychain|password_env|plaintext_config|inline_password|inline_key|quick_setup
    ArgsRedacted  string    `json:"args_redacted,omitempty"`  // JSON-encoded, secrets replaced
    ExitCode      int       `json:"exit_code,omitempty"`
    DurationMs    int64     `json:"duration_ms"`
    BytesIn       int64     `json:"bytes_in,omitempty"`
    BytesOut      int64     `json:"bytes_out,omitempty"`
    ErrorCode     string    `json:"error_code,omitempty"`
}

type Filter struct {
    Server     string
    Tool       string
    Since      time.Time
    Until      time.Time
    ExitCodeEq *int        // nil = any
    ErrorOnly  bool
    Limit      int          // default 100, max 1000
}
```

**File layout:** `~/.local/state/mcp-ssh-bridge/audit-2026-05-03.jsonl`,
mode `0600`, parent dir `0700`. One file per UTC date. On startup, files
older than `retention_days` are deleted (synchronous, before MCP ready).

**Redaction:** runs `safety.RedactSecret` on `args_redacted` before
write. Specifically:

- For tool calls with an `inline.password` field: the entire `inline`
  object is replaced with `{"redacted": true}`.
- For tool calls with `query`-like SQL strings: passed through redactor
  to mask any embedded secrets.
- Command bodies (the `command` arg to ssh_exec) are written as-is,
  except for known patterns like `sshpass -p XXX` and
  `mysql -pXXX`, which are redacted.

This is best-effort; a sufficiently obscure command containing secrets
will not be caught. The README will say so explicitly.


---

## 6. Tool Specifications

This section is the LLM-facing contract. Every tool definition includes:

- **Name** (MCP tool name)
- **Description** (what the LLM sees)
- **Input schema** (JSON Schema fragment)
- **Output schema** (`Response.data` shape on success)
- **Error codes** (which `error.code` values are possible)
- **Audit fields** (what gets logged)
- **Implementation notes**

All tools return the standard `Response` envelope from §5.1.

### 6.1 `ssh_exec`

**Description:** Execute a single command on a remote SSH server. Returns
stdout, stderr, and exit code. By default the entire output is buffered;
set `stream: true` for progress notifications during long-running
commands.

**Input schema:**

```json
{
  "type": "object",
  "properties": {
    "server":  { "type": "string", "description": "Configured server name" },
    "inline":  {
      "type": "object",
      "description": "Ad-hoc connection params (alternative to server). Credentials passed inline are NOT persisted. For testing only.",
      "properties": {
        "host":             { "type": "string" },
        "port":             { "type": "integer", "minimum": 1, "maximum": 65535, "default": 22 },
        "user":             { "type": "string" },
        "password":         { "type": "string", "description": "Plaintext password (testing only)" },
        "private_key_pem":  { "type": "string", "description": "PEM-encoded private key" },
        "passphrase":       { "type": "string", "description": "Passphrase for private_key_pem" },
        "accept_new_host":  { "type": "boolean", "default": false, "description": "If true, accept and trust an unknown host key on first contact. Default false: unknown hosts are rejected." }
      },
      "required": ["host", "user"]
    },
    "command":  { "type": "string", "description": "Shell command to execute on the remote host." },
    "cwd":      { "type": "string", "description": "Working directory. Resolved via SFTP realpath; supports ~ expansion. Server's default_dir used if omitted." },
    "stream":   { "type": "boolean", "default": false, "description": "If true, send progress notifications with output chunks." },
    "timeout_ms": { "type": "integer", "minimum": 1000, "maximum": 1800000, "default": 120000 }
  },
  "oneOf": [
    { "required": ["server", "command"] },
    { "required": ["inline", "command"] }
  ]
}
```

**Output (success):**

```json
{
  "stdout": "string",
  "stderr": "string",
  "exit_code": 0,
  "signal": "",
  "duration_ms": 1234,
  "truncated": false,
  "host": "prod-web.example.com",
  "user": "deploy"
}
```

**Possible error codes:** `INVALID_ARGUMENT`, `CONN_FAILED`, `AUTH_FAILED`,
`HOST_KEY_UNKNOWN`, `HOST_KEY_MISMATCH`, `TIMEOUT`, `INLINE_CREDS_DISABLED`,
`PERMISSION_DENIED`, `INTERNAL_ERROR`.

**Audit fields:** server (or `inline:<host>`), `auth_mode`, `args_redacted`
(without inline.password), `exit_code`, `duration_ms`, `bytes_out` (stdout
size), `error_code`.

**Implementation notes:**

1. Validate `oneOf` constraint manually after schema validation (the SDK
   may not enforce `oneOf` strictly).
2. If `inline` is provided, check `Settings.AllowInlineCredentials`.
   Reject with `INLINE_CREDS_DISABLED` if disabled.
3. If `cwd` is provided:
   - Acquire connection.
   - Call `client.SFTP().Realpath(cwd_with_~_expanded)` to get absolute
     path.
   - Build `RemoteCommand` via `safety.NewRemoteCommand(command, abs_cwd)`.
4. If `stream: true`, register an MCP progress callback. Send progress
   notifications with chunks of up to 4 KiB on stdout boundaries (newline-
   aligned where possible).
5. Truncate when total output exceeds `output_max_bytes`. Set `truncated:
   true` and append `...[truncated; N bytes total]` to the returned
   stdout/stderr.
6. Cancel via `ctx.Done()` on timeout: send SSH signal `TERM` to the remote
   process, wait 2s, then send `KILL`, then close the channel.
7. Inline mode: connection is created via `Pool.GetAdHoc()`, used, then
   closed in defer. The `Secret` for inline.password is closed immediately
   after `*ssh.Client` connect.

### 6.2 `session_start`

**Description:** Open a persistent shell session on a remote server.
Subsequent `session_send` calls reuse the same shell, preserving cwd,
environment, etc.

**Input:**
```json
{
  "type": "object",
  "properties": {
    "server": { "type": "string" },
    "inline": { "$ref": "#/definitions/inline" }
  },
  "oneOf": [
    { "required": ["server"] },
    { "required": ["inline"] }
  ]
}
```

**Output:** `{ "session_id": "...", "server": "...", "started_at": "..." }`

**Errors:** all of `ssh_exec`'s connection errors, plus `SESSION_LIMIT`
(default max 16 concurrent sessions).

### 6.3 `session_send`

**Description:** Send a command to an existing session. Waits for
completion using a sentinel-based protocol (not regex prompt detection).

**Input:**
```json
{
  "type": "object",
  "properties": {
    "session_id": { "type": "string" },
    "command":    { "type": "string" },
    "timeout_ms": { "type": "integer", "default": 120000 }
  },
  "required": ["session_id", "command"]
}
```

**Output:** `{ "stdout", "stderr", "exit_code", "duration_ms" }`

**Errors:** `SESSION_DEAD`, `TIMEOUT`, `INVALID_ARGUMENT`.

### 6.4 `session_close`

**Description:** Close a session.

**Input:** `{ "session_id": "string" }`
**Output:** `{ "closed": true }`
**Errors:** `NOT_FOUND` (idempotent — closing an already-closed session
returns OK).

### 6.5 `sftp_list`

**Description:** List directory entries with metadata.

**Input:**
```json
{
  "type": "object",
  "properties": {
    "server":  { "type": "string" },
    "inline":  { "$ref": "#/definitions/inline" },
    "path":    { "type": "string" },
    "recursive": { "type": "boolean", "default": false },
    "max_entries": { "type": "integer", "default": 1000, "maximum": 10000 }
  },
  "required": ["path"]
}
```

**Output:** `{ "entries": [Entry, ...], "truncated": false }`

**Implementation:** recursion is breadth-first with a queue capped at
`max_entries`. When cap hit, set `truncated: true`.

### 6.6 `sftp_read`

**Description:** Read a (range of a) remote file. Supports partial reads
via offset/length, ideal for tailing logs without pulling the whole file.

**Input:**
```json
{
  "type": "object",
  "properties": {
    "server":  { "type": "string" },
    "inline":  { "$ref": "#/definitions/inline" },
    "path":    { "type": "string" },
    "offset":  { "type": "integer", "minimum": -9223372036854775808, "default": 0,
                  "description": "Byte offset. Negative values count from EOF (offset=-4096 = last 4 KiB)." },
    "length":  { "type": "integer", "minimum": 1, "maximum": 16777216, "default": 65536,
                  "description": "Bytes to read. Capped at 16 MiB per call." },
    "encoding": { "type": "string", "enum": ["utf8", "base64"], "default": "utf8",
                  "description": "How to encode the bytes for return. utf8 returns text or fails on invalid UTF-8 (try base64 for binaries)." }
  },
  "required": ["path"]
}
```

**Output:**
```json
{
  "content":   "string (utf8 or base64)",
  "encoding":  "utf8",
  "bytes_read": 4096,
  "file_size":  1234567,
  "is_truncated_view": true
}
```

`is_truncated_view` is true when `bytes_read < file_size` (i.e., we
returned a window).

**Progress:** if `length > sftp_progress_threshold_bytes`, emit MCP
progress notifications.

**Errors:** `NOT_FOUND`, `PERMISSION_DENIED`, `SFTP_ERROR`, `INVALID_ARGUMENT`
(on encoding mismatch).

### 6.7 `sftp_stat`

**Description:** Get metadata for a single path.

**Input:** `{ "server"|"inline", "path": "string" }`
**Output:** single `Entry` (see §5.6).
**Errors:** `NOT_FOUND`, `PERMISSION_DENIED`, `SFTP_ERROR`.

### 6.8 `sftp_op`

**Description:** Perform a write or management operation on the remote
filesystem. Sub-action routed via `action` field.

**Input:**
```json
{
  "type": "object",
  "properties": {
    "server": { "type": "string" },
    "inline": { "$ref": "#/definitions/inline" },
    "action": { "type": "string", "enum": ["write", "mkdir", "remove", "rename", "chmod", "symlink", "realpath"] },
    "path":   { "type": "string", "description": "Primary path (target of action)" },
    "content": { "type": "string", "description": "(write only) UTF-8 or base64 content" },
    "encoding": { "type": "string", "enum": ["utf8", "base64"], "default": "utf8" },
    "atomic":  { "type": "boolean", "default": true, "description": "(write only) Write to temp + rename" },
    "mode":    { "type": "string", "description": "(write/chmod/mkdir) Octal string e.g. '0644'" },
    "recursive": { "type": "boolean", "default": false, "description": "(mkdir/remove)" },
    "to":      { "type": "string", "description": "(rename/symlink) Destination path" },
    "dry_run": { "type": "boolean", "default": false, "description": "(remove only) Report what would be removed without removing" }
  },
  "required": ["action", "path"]
}
```

**Output:** action-specific:

| Action | Output |
|---|---|
| `write` | `{ "bytes_written": N, "path": "..." }` |
| `mkdir` | `{ "created": true }` |
| `remove` | `{ "removed": [paths...], "dry_run": false }` |
| `rename` | `{ "from": "...", "to": "..." }` |
| `chmod` | `{ "mode": "0644" }` |
| `symlink` | `{ "target": "...", "link": "..." }` |
| `realpath` | `{ "resolved": "/abs/path" }` |

**Safety:**
- For `remove`, `dry_run: true` is the **default behavior printed in
  examples**, but the schema default is `false` to match the action
  semantics. The tool's description string explicitly suggests using
  `dry_run: true` first. (We can't override schema defaults to
  `dry_run: true` without breaking workflows.)
- For `write` with `atomic: true`, we write to `<dir>/.<basename>.msb-tmp`
  then `Rename`. If `Rename` fails, the temp file is removed.
- For `chmod`, mode strings are parsed as octal. Reject if the resulting
  mode would set setuid/setgid/sticky bits unless explicitly opted in via
  a `mode` like `"04755"` (we do allow it, just so you know — `safety`
  validation only rejects non-octal strings).

**Errors:** `INVALID_ARGUMENT`, `NOT_FOUND`, `PERMISSION_DENIED`, `SFTP_ERROR`.

### 6.9 `ssh_group_exec`

**Description:** Run the same command across a group of servers
concurrently. Returns one result per server.

**Input:**
```json
{
  "type": "object",
  "properties": {
    "servers": { "type": "array", "items": { "type": "string" }, "minItems": 1, "maxItems": 32 },
    "tag":     { "type": "string", "description": "Alternative to 'servers': run on all servers with this tag" },
    "command": { "type": "string" },
    "cwd":     { "type": "string" },
    "timeout_ms": { "type": "integer", "default": 120000 },
    "stop_on_error": { "type": "boolean", "default": false },
    "max_concurrency": { "type": "integer", "default": 8, "maximum": 16 }
  },
  "required": ["command"],
  "oneOf": [
    { "required": ["servers"] },
    { "required": ["tag"] }
  ]
}
```

**Output:**
```json
{
  "results": [
    { "server": "prod-web-1", "ok": true,  "stdout": "...", "stderr": "...", "exit_code": 0, "duration_ms": 132 },
    { "server": "prod-web-2", "ok": false, "error": { "code": "TIMEOUT", "message": "..." } }
  ],
  "summary": { "total": 2, "succeeded": 1, "failed": 1, "duration_ms": 30200 }
}
```

The top-level `Response.ok` is `true` if all sub-commands succeeded, else
`false` (with `error.code = "PARTIAL_FAILURE"`).

**Note:** ad-hoc inline credentials are NOT supported here — group exec
is for configured servers only.

### 6.10 `tunnel`

**Description:** Manage SSH port forwards.

**Input:**
```json
{
  "type": "object",
  "properties": {
    "action": { "type": "string", "enum": ["create", "list", "close"] },
    "kind":   { "type": "string", "enum": ["local", "remote"], "description": "(create only)" },
    "server": { "type": "string", "description": "(create only)" },
    "local_bind":  { "type": "string", "default": "127.0.0.1", "description": "(create local) Local listener bind address. Defaults to loopback for safety." },
    "local_port":  { "type": "integer" },
    "remote_bind": { "type": "string", "default": "127.0.0.1", "description": "(create remote)" },
    "remote_port": { "type": "integer" },
    "dst_host":    { "type": "string", "description": "(create local) Destination from remote side" },
    "dst_port":    { "type": "integer", "description": "(create local)" },
    "tunnel_id":   { "type": "string", "description": "(close only)" }
  },
  "required": ["action"]
}
```

**Output:**
- `create`: `{ "tunnel_id": "...", "kind": "...", "endpoint": "127.0.0.1:13306" }`
- `list`: `{ "tunnels": [TunnelInfo, ...] }`
- `close`: `{ "closed": true }`

**Safety:** local listener defaults to `127.0.0.1`, never `0.0.0.0`. To
expose to the LAN the operator must explicitly pass `local_bind:
"0.0.0.0"`. README warns about this.

### 6.11 `list_servers`

**Description:** Return all configured servers (without secrets).

**Input:**
```json
{
  "type": "object",
  "properties": {
    "tag": { "type": "string", "description": "Filter by tag" }
  }
}
```

**Output:**
```json
{
  "servers": [
    {
      "name": "prod-web",
      "host": "prod-web.example.com",
      "port": 22,
      "user": "deploy",
      "auth": "agent",
      "default_dir": "/var/www",
      "description": "Production web server",
      "tags": ["prod", "web"],
      "proxy_jump": "bastion"
    }
  ]
}
```

Credential fields are never included in output. The `auth` field reports
the method (agent / key / password) but not the secret.

### 6.12 `audit_query`

**Description:** Query the bridge's own audit log. Use this to recall
prior actions in the current or earlier sessions.

**Input:**
```json
{
  "type": "object",
  "properties": {
    "server":      { "type": "string" },
    "tool":        { "type": "string" },
    "since":       { "type": "string", "format": "date-time" },
    "until":       { "type": "string", "format": "date-time" },
    "exit_code":   { "type": "integer" },
    "errors_only": { "type": "boolean", "default": false },
    "limit":       { "type": "integer", "default": 100, "maximum": 1000 }
  }
}
```

**Output:**
```json
{
  "entries": [
    { "timestamp": "...", "tool": "ssh_exec", "server": "prod-web",
      "auth_mode": "agent", "args_redacted": "{...}",
      "exit_code": 0, "duration_ms": 132 }
  ],
  "count": 42,
  "truncated": false
}
```

**Implementation:** linear scan over JSONL files for the queried date
range, in reverse chronological order. Acceptable for MVP given log
volumes (~10k entries/day max in normal use). v0.2 will add SQLite
mirror for indexed queries.

### 6.13 `ssh_quick_setup`

**Description:** Register an ad-hoc server for the duration of this MCP
session, prompting the user to confirm via the client's elicitation UI.
After confirmation, subsequent `ssh_exec` and other tools can reference
this server by name without re-passing credentials.

**Input:**
```json
{
  "type": "object",
  "properties": {
    "host": { "type": "string" },
    "port": { "type": "integer", "default": 22 },
    "user": { "type": "string" },
    "password":        { "type": "string", "description": "Plaintext password" },
    "private_key_pem": { "type": "string" },
    "passphrase":      { "type": "string" },
    "accept_new_host": { "type": "boolean", "default": false },
    "name_hint":       { "type": "string", "description": "Suggested temporary name; bridge may sanitize/disambiguate" },
    "ttl_minutes":     { "type": "integer", "default": 30, "minimum": 1, "maximum": 240 }
  },
  "required": ["host", "user"]
}
```

**Output:**
```json
{
  "registered_name": "qs-prod-test-1",
  "expires_at": "2026-05-03T15:30:00Z",
  "host": "1.2.3.4",
  "user": "root"
}
```

**Behavior:**

1. Validate `Settings.AllowQuickSetup`. If disabled, return
   `INLINE_CREDS_DISABLED`.
2. Send an MCP `elicitation/create` request to the client with a schema
   like:
   ```
   {
     "type": "object",
     "properties": {
       "confirm": {
         "type": "boolean",
         "description": "Register temp server '1.2.3.4' as user 'root' for 30 minutes?"
       }
     },
     "required": ["confirm"]
   }
   ```
3. Wait for user response. If declined or timed out (60s), return
   `USER_DECLINED`.
4. Sanitize `name_hint` (default `qs-<host>-<n>`) and store in an
   in-memory registry with TTL.
5. Credentials are stored in a `*Secret` with the same lifetime as the
   registry entry. On expiry, `Secret.Close()` is called and the entry
   is removed.

**Audit:** logs `tool: "ssh_quick_setup"`, host, user, `auth_mode:
"quick_setup"`, but **not** the password or key body.

The registered server name resolves through the same `Pool.Get()` path
as configured servers. The pool checks the temp registry first, then
the persistent config.

---

## 7. Configuration Specification

### 7.1 File Format and Location

TOML format. Default path:

| OS | Path |
|---|---|
| macOS | `~/.config/mcp-ssh-bridge/config.toml` |
| Linux | `$XDG_CONFIG_HOME/mcp-ssh-bridge/config.toml` (default `~/.config/...`) |
| Windows | `%APPDATA%\mcp-ssh-bridge\config.toml` |

Override via `MCP_SSH_BRIDGE_CONFIG=/path/to/config.toml` env var or
`--config` CLI flag.

### 7.2 Schema

```toml
# Global settings (all optional; defaults shown)
[settings]
# Plaintext passwords in this file are rejected unless this is true.
# When true, a warning prints to stderr at every startup.
allow_config_plaintext_password = false

# Inline credentials in tool calls (e.g. ssh_exec.inline.password) are
# allowed by default. Set false to force agent/key only.
allow_inline_credentials = true

# ssh_quick_setup tool can register temporary servers. Set false to
# disable that flow entirely.
allow_quick_setup = true

# Command execution
default_timeout_ms              = 120000      # 2 minutes
max_timeout_ms                  = 1800000     # 30 minutes
output_max_bytes                = 65536       # 64 KiB

# SFTP
sftp_progress_threshold_bytes   = 10485760    # 10 MiB

# Lifecycle
session_idle_seconds            = 3600        # 1 hour
conn_idle_seconds               = 600         # 10 minutes

# Audit
audit_retention_days            = 90

# SSH algorithms — by default we use modern only.
# To re-enable a weak algorithm, list its exact name here.
# Example: weak_algorithms_opt_in = ["ssh-rsa"]
weak_algorithms_opt_in = []


# Per-server configuration. Map key is the canonical server name
# (lowercased on load).
[servers.prod-web]
host          = "prod-web.example.com"
port          = 22                                    # default 22
user          = "deploy"
auth          = "agent"                               # "agent" | "key" | "password"
default_dir   = "/var/www"
description   = "Production web frontend"
tags          = ["prod", "web"]
allowed_paths = ["/var/www", "/var/log/nginx", "/tmp"]  # optional SFTP allowlist

[servers.prod-db]
host           = "10.0.1.10"
user           = "postgres"
auth           = "key"
key_path       = "~/.ssh/id_db"
key_passphrase = "keychain:mcp-ssh-bridge:prod-db"

[servers.prod-cache]
host     = "10.0.1.20"
user     = "ops"
auth     = "key"
key_path = "~/.ssh/id_ops"
proxy_jump = "bastion"                                  # tunnel through 'bastion'

[servers.bastion]
host     = "bastion.example.com"
user     = "jump"
auth     = "agent"

# A test server using opt-in plaintext (requires allow_config_plaintext_password = true)
[servers.test-vm]
host     = "192.168.1.100"
user     = "root"
auth     = "password"
password = "plaintext:admin123"
description = "Local Vagrant VM, throwaway"
```

### 7.3 Validation Rules

On load, the validator enforces:

1. `host` is non-empty.
2. `user` is non-empty.
3. `auth` is one of `agent`, `key`, `password`.
4. If `auth = "agent"`: no `key_path`, `password` allowed.
5. If `auth = "key"`: `key_path` required.
6. If `auth = "password"`: `password` required, `key_path` ignored.
7. `password` and `key_passphrase` are valid `CredRef` strings.
8. If any server uses `plaintext:` (or bareword) and
   `allow_config_plaintext_password` is false → error.
9. `proxy_jump` references resolve to a defined server.
10. No cycles in proxy_jump graph.
11. `allowed_paths` entries are absolute and clean (no `..`, no trailing
    slash except root).
12. Tags match `^[a-z0-9_-]+$`.
13. Server name (map key) matches `^[a-z0-9][a-z0-9_-]*$`, length 1–64.
14. Port in [1, 65535].

Validation errors include the specific server name and field. Multiple
errors are collected and reported together.

### 7.4 CredRef Format

A `CredRef` is a string with one of these prefixes:

| Form | Resolution |
|---|---|
| `keychain:<service>:<account>` | OS keychain query. The `<service>` should be `mcp-ssh-bridge` for secrets managed by our CLI; arbitrary values permitted to allow sharing with other tools. |
| `env:<NAME>` | `os.Getenv(NAME)`. Empty value at resolve time → `ErrEmptyEnv`. |
| `plaintext:<value>` | Inline plaintext (rejected without opt-in). |
| `<bareword>` | Implicit `plaintext:`; same opt-in rule. |

### 7.5 Example User Workflows

**First-time setup (recommended):**
```bash
# 1. Install
$ go install github.com/<owner>/mcp-ssh-bridge/cmd/mcp-ssh-bridge@latest

# 2. Init config
$ mcp-ssh-bridge config init
Wrote config to ~/.config/mcp-ssh-bridge/config.toml

# 3. Add a server (interactive)
$ mcp-ssh-bridge server add prod-web
Host: prod-web.example.com
User: deploy
Auth method [agent/key/password]: agent
Default directory: /var/www
Description: Production web

Trust the host's SSH key? (y/n): y
[fetched ed25519 fingerprint SHA256:abc...]
Added to ~/.ssh/known_hosts.

# 4. Test
$ mcp-ssh-bridge server test prod-web
✓ Connected
✓ Auth: ssh-agent (key SHA256:xyz...)
✓ Host key verified

# 5. Wire to Claude Desktop
$ mcp-ssh-bridge install claude-desktop
Wrote MCP server entry to ~/Library/Application Support/Claude/claude_desktop_config.json
Restart Claude Desktop to apply.
```

**Adding a server with passphrase via keychain:**
```bash
$ mcp-ssh-bridge auth set prod-db
Enter secret: ****
Stored as keychain:mcp-ssh-bridge:prod-db

$ mcp-ssh-bridge server add prod-db
Host: 10.0.1.10
User: postgres
Auth method: key
Key path: ~/.ssh/id_db
Key passphrase reference [keychain:mcp-ssh-bridge:prod-db]:  # default suggested
[...]
```

**Migrating from legacy-ssh-tool:**
```bash
$ mcp-ssh-bridge migrate-from-legacy ~/.config/legacy-ssh-tool/.env
Found 5 servers, 3 with plaintext passwords.

Migration plan:
  prod-web  : key auth, no migration needed
  prod-db   : plaintext password → keychain:mcp-ssh-bridge:prod-db
  staging   : plaintext password → keychain:mcp-ssh-bridge:staging
  test-vm   : plaintext password → KEEP (will require allow_config_plaintext_password=true)
  bastion   : agent auth, no migration needed

Proceed? (y/n): y
✓ Stored 2 secrets in keychain
✓ Wrote ~/.config/mcp-ssh-bridge/config.toml
ℹ test-vm uses plaintext; set allow_config_plaintext_password=true to enable, or run 'auth set test-vm' to migrate.
```


---

## 8. Authentication and Credential Handling

### 8.1 Authentication Method Resolution

Given a server (configured or ad-hoc), the bridge resolves authentication
in this order:

```
1. If server.Auth == "agent":
     a. Connect to SSH agent at SSH_AUTH_SOCK.
     b. Use agent.Signers() as ssh.PublicKeys auth method.
     c. If agent unavailable → ErrAuthFailed("agent unavailable").

2. If server.Auth == "key":
     a. Read file at server.KeyPath (~  expanded against $HOME).
     b. Try ssh.ParsePrivateKey first.
     c. If err is *ssh.PassphraseMissingError:
          - Resolve KeyPassphrase CredRef → Secret.
          - ssh.ParsePrivateKeyWithPassphrase(pem, secret.Bytes()).
          - secret.Close().
     d. Use Signer as ssh.PublicKeys auth method.

3. If server.Auth == "password":
     a. Resolve Password CredRef → Secret.
     b. Use ssh.Password(string(secret.Bytes())) as auth method.
     c. secret.Close() immediately after the *ssh.Client.Connect succeeds.

4. For inline (ad-hoc) credentials in tool calls:
     - inline.private_key_pem present → key path (no file read).
     - inline.password present → password path.
     - Both present → INVALID_ARGUMENT.
     - Neither → INVALID_ARGUMENT.
```

### 8.2 Secret Lifecycle

```
┌────────────────────┐
│ CredRef in config  │
│ or inline arg      │
└─────────┬──────────┘
          │ auth.Resolve()
          ▼
┌────────────────────┐
│ *Secret in heap    │
│ (single allocation)│
└─────────┬──────────┘
          │ Bytes() — single use
          ▼
┌────────────────────┐
│ ssh.Password() or  │
│ ssh.ParsePrivate-  │
│ KeyWithPassphrase  │
└─────────┬──────────┘
          │ ssh.Client connected
          ▼
┌────────────────────┐
│ Secret.Close()     │
│ (zero-on-free)     │
└────────────────────┘
```

`Secret.Close()` performs:
1. `for i := range buf { buf[i] = 0 }` — explicit zeroing.
2. `runtime.KeepAlive(buf)` — prevent GC moving the buffer mid-zero.
3. Set internal pointer to nil.

We do not pin secrets in mlocked memory (would require cgo and is
unhelpful given Go's GC model). The mitigation is conservative: zero
ASAP after use.

### 8.3 ssh-agent Forwarding

**Not supported in MVP.** Agent forwarding (`-A`) is a security
sensitivity (forwarded agent can be hijacked by remote root) that we
deliberately exclude. Users who need it can use OpenSSH directly.

### 8.4 Keychain Backend Selection

`zalando/go-keyring` selects backend per OS:

| OS | Backend |
|---|---|
| macOS | `/usr/bin/security` (Keychain) |
| Linux | Secret Service via D-Bus (gnome-keyring, KWallet, etc.) |
| Windows | Credential Manager |

If no backend is available (headless Linux without a session bus, etc.),
`auth.Resolve` returns `ErrKeychainUnavailable`. Users in this case
should use `env:` references with a secrets manager like `pass`,
`age`, `sops`, or HashiCorp Vault providing the env vars.

### 8.5 Inline Credential Lifetime

Inline credentials passed in `ssh_exec.inline.password` etc.:

1. Decoded from MCP request.
2. Wrapped in `*Secret` immediately on entering the tool handler.
3. The MCP `request.Arguments` map is **not** retained beyond the
   immediate decode (MCP SDK responsibility, but we re-zero the relevant
   fields ourselves before returning).
4. The audit log captures the call with `inline` field replaced by
   `{"redacted": true}` (see §9).
5. After the connection is established and the `*ssh.Client` is in hand,
   the secret is closed. The connection itself does not retain the
   password (SSH protocol uses it once during handshake).
6. Ad-hoc connections are NOT pooled — no second use of the secret is
   possible without the caller passing it again.

---

## 9. Audit Log Specification

### 9.1 File Layout

```
~/.local/state/mcp-ssh-bridge/
├── audit-2026-05-01.jsonl     mode 0600
├── audit-2026-05-02.jsonl     mode 0600
└── audit-2026-05-03.jsonl     mode 0600  (current)
```

Parent directory mode `0700`. On Windows: `%LOCALAPPDATA%\mcp-ssh-bridge\state\`.

### 9.2 Entry Schema (JSONL)

One JSON object per line, terminated by `\n`. Keys in alphabetical order
for determinism.

```json
{
  "args_redacted": "{\"server\":\"prod-web\",\"command\":\"df -h\",\"cwd\":\"/var/log\"}",
  "auth_mode":     "agent",
  "bytes_in":      0,
  "bytes_out":     1024,
  "duration_ms":   132,
  "error_code":    "",
  "exit_code":     0,
  "server":        "prod-web",
  "session_id":    "01JZK6XPABCDEFGHJKMNPQRSTV",
  "timestamp":     "2026-05-03T12:34:56.789Z",
  "tool":          "ssh_exec"
}
```

### 9.3 Write Path

```
[tool handler returns]
        │
        ▼
[audit middleware]
        │
        ├─ Build Entry from request + response
        ├─ Redact args (safety.RedactSecret on JSON-encoded args)
        ├─ Append to current day's file (with file lock)
        ├─ Fsync (default true for security; configurable for perf)
        ├─ If write or fsync error:
        │     - Log to stderr
        │     - If this entry was for a write/exec tool:
        │         Refuse the operation (caller already executed —
        │         too late). Mark the next call as needing recovery.
        │   Actually: per fail-closed contract, we audit BEFORE
        │   executing destructive ops. See below.
        ▼
[response sent to client]
```

**Fail-closed sequencing:** for tools that mutate (`ssh_exec` with
non-trivial commands, `sftp_op write/remove/rename/chmod/symlink`),
we use a two-phase audit:

1. **Pre-record** (before executing remote op): write entry with
   `exit_code: -1`, `error_code: "PENDING"`. If this fails, abort with
   `AUDIT_FAILED` error before touching remote.
2. **Update** (after op completes): append a second entry with same
   `session_id` + `request_id` referencing the first, containing actual
   exit code etc. (We don't rewrite the first line — JSONL is
   append-only.)

For read-only tools (`sftp_list/stat/read`, `audit_query`, `list_servers`),
single-phase write after completion is sufficient.

### 9.4 Redaction Patterns

`safety.RedactSecret` runs on the JSON-encoded args before write. It
replaces:

| Pattern | Replacement |
|---|---|
| Object field `inline` (any nesting) | `{"redacted": true}` |
| Object field `password`, `passphrase`, `private_key_pem` (top-level or in `inline`) | `"***REDACTED***"` |
| `(?i)password\s*[:=]\s*\S+` in command strings | `password=***` |
| `sshpass -p \S+` | `sshpass -p ***` |
| `mysql -p\S+` | `mysql -p***` |
| `PGPASSWORD=\S+` | `PGPASSWORD=***` |
| `-----BEGIN [^-]+-----...END[^-]+-----` (PEM) | `-----BEGIN REDACTED-----` |
| URLs with userinfo `://[^/@]+@` | `://***@` |

This is best-effort. README states clearly: **the audit log is for
operational recall and post-incident review, not for cryptographic
guarantees about secret leakage.**

### 9.5 Rotation and Retention

On startup:
1. List `audit-*.jsonl` files in state dir.
2. Parse date from filename.
3. Delete files older than `audit_retention_days`.
4. Open today's file (or create with mode 0600) for append.

At UTC midnight while running: a goroutine rolls the file (closes
yesterday's, opens today's). Check happens lazily on each write — if
`time.Now().UTC().Format("2006-01-02")` differs from current file's
date, rotate.

### 9.6 Querying

`audit_query` tool implements `Logger.Query(filter)`. Algorithm:

```
1. Determine date range from filter.Since/Until (default: last 7 days).
2. For each date in range, descending:
     a. Open audit-<date>.jsonl read-only.
     b. Read line by line (bufio.Scanner with 1 MiB buffer for safety).
     c. For each line:
          i.   json.Unmarshal into Entry.
          ii.  Apply filter predicates (server, tool, exit_code, errors_only).
          iii. If matches, append to results.
          iv.  If len(results) >= filter.Limit, break.
     d. If broke out, set truncated=true.
3. Return results, sort by timestamp descending.
```

Performance is acceptable for MVP volumes. v0.2 adds SQLite with
indexes on `(timestamp, tool, server, exit_code)`.

---

## 10. Error Model

### 10.1 Error Codes

The complete set of `Response.error.code` values:

| Code | HTTP-ish status | Retriable | Meaning |
|---|---|---|---|
| `INVALID_ARGUMENT` | 400 | false | Tool call args fail schema or semantic validation |
| `AUTH_FAILED` | 401 | false | SSH authentication rejected by server |
| `PERMISSION_DENIED` | 403 | false | Authenticated, but operation denied (file mode, sudo, etc.) |
| `NOT_FOUND` | 404 | false | Server name, file, session id, etc. doesn't exist |
| `TIMEOUT` | 408 | true | Command or connection exceeded timeout |
| `CONFLICT` | 409 | false | Operation conflicts with existing state (e.g. tunnel port in use) |
| `RATE_LIMITED` | 429 | true | (reserved; not used in MVP) |
| `INTERNAL_ERROR` | 500 | true | Unexpected internal failure |
| `CONN_FAILED` | 502 | true | TCP / SSH handshake failure (network-level) |
| `SESSION_DEAD` | 503 | true | Session terminated (caller should re-`session_start`) |
| `HOST_KEY_UNKNOWN` | — | false | First connection to host; user must run `trust` |
| `HOST_KEY_MISMATCH` | — | false | Host key changed since last seen — possible MITM |
| `SFTP_ERROR` | — | varies | SFTP protocol-level error (bubbled from pkg/sftp) |
| `INLINE_CREDS_DISABLED` | — | false | Operator has set `allow_inline_credentials = false` |
| `PLAINTEXT_PASSWORD_DISABLED` | — | false | Configured password is plaintext but flag is off |
| `USER_DECLINED` | — | false | Elicitation declined by user (quick_setup) |
| `AUDIT_FAILED` | — | true | Audit log write failed; operation refused |
| `PARTIAL_FAILURE` | — | varies | Group exec had mixed results |
| `SESSION_LIMIT` | — | false | Too many active sessions |

### 10.2 Error Construction Conventions

- `message` is in English, single-sentence where possible, may include
  the remote stderr when relevant.
- `hint` is optional; populated for codes where actionable guidance
  helps the LLM:
  - `HOST_KEY_UNKNOWN` → "Run `mcp-ssh-bridge trust <server>` from a
    terminal, or set `accept_new_host: true` in the inline params."
  - `INLINE_CREDS_DISABLED` → "The operator has disabled inline
    credentials. Use a configured server or have the operator enable
    `allow_inline_credentials`."
  - `PLAINTEXT_PASSWORD_DISABLED` → "The server is configured with a
    plaintext password but `allow_config_plaintext_password` is false.
    Migrate to keychain via `mcp-ssh-bridge auth set <server>`."
- `retriable` reflects whether *the same call with the same args* might
  succeed if retried. `TIMEOUT` is true; `INVALID_ARGUMENT` is false.

### 10.3 Mapping from Underlying Errors

| Source | Mapped to |
|---|---|
| `context.DeadlineExceeded` | `TIMEOUT` |
| `*net.OpError` (dial) | `CONN_FAILED` |
| `*ssh.ExitError` (non-zero exit) | success path; carries `exit_code` |
| `&ssh.ExitMissingError{}` | success path; signal-killed; `signal` populated |
| `keyboardInteractive failures` | `AUTH_FAILED` |
| `knownhosts.KeyError{Want: nil}` | `HOST_KEY_UNKNOWN` |
| `knownhosts.KeyError{Want: not nil}` | `HOST_KEY_MISMATCH` |
| `sftp.StatusErr` | `SFTP_ERROR` (with original error message) |
| `os.IsNotExist` (config file) | `NOT_FOUND` |
| `panic` (recovered in tool middleware) | `INTERNAL_ERROR` with stack trace in stderr only |

---

## 11. CLI Subcommands

The same binary exposes both MCP server mode (default) and a CLI for
configuration. CLI is invoked when `argv[1]` matches a known subcommand;
otherwise stdio MCP server starts.

```
mcp-ssh-bridge                          Run as MCP server (stdio)
mcp-ssh-bridge --config <path>          Same with custom config
mcp-ssh-bridge config init              Write default config.toml
mcp-ssh-bridge config validate          Validate current config, print errors

mcp-ssh-bridge server add <name>        Interactive add
mcp-ssh-bridge server list              List configured servers
mcp-ssh-bridge server remove <name>     Remove from config
mcp-ssh-bridge server test <name>       Connect, exec `echo ok`, report
mcp-ssh-bridge server show <name>       Print server config (no secrets)

mcp-ssh-bridge trust <name>             Fetch and store host key in known_hosts
mcp-ssh-bridge trust --host <h> --port <p>  Same, ad-hoc

mcp-ssh-bridge auth set <name>          Prompt for secret, store in keychain
mcp-ssh-bridge auth get <name>          Print metadata about stored secret (not the value)
mcp-ssh-bridge auth remove <name>       Delete from keychain
mcp-ssh-bridge auth list                List keychain entries for service mcp-ssh-bridge

mcp-ssh-bridge migrate-from-legacy <env-file>     Import legacy-ssh-tool .env
mcp-ssh-bridge migrate-passwords        Walk config, move plaintext to keychain

mcp-ssh-bridge install claude-desktop   Write MCP entry to Claude Desktop config
mcp-ssh-bridge install claude-code      Write MCP entry for Claude Code
mcp-ssh-bridge install codex            Write MCP entry for Codex (TOML)

mcp-ssh-bridge audit query [--server X] [--tool Y] [--since 1h]
                                        Query audit log from CLI

mcp-ssh-bridge version                  Print version + Go version + commit
```

CLI subcommands use `os.Stdin` / `os.Stdout` directly (not stdio JSON-RPC).
The `server test` command prints a multi-line human-readable result, not
an envelope.

---

## 12. Connection and Session Lifecycle

### 12.1 Connection States

```
                   ┌──────────────┐
              ┌────►   Idle       │ ─────────┐
              │    │              │          │ idle > conn_idle_seconds
              │    └──────┬───────┘          ▼
   command    │           │            ┌──────────┐
   completes  │   command │            │ Closing  │
              │           ▼            └──────────┘
              │    ┌──────────────┐          ▲
              └────┤  In use      │          │ explicit Close
                   │              │          │
                   └──────┬───────┘          │
                          │                  │
                          │ keep-alive fail  │
                          ▼                  │
                   ┌──────────────┐          │
                   │   Dead       │ ─────────┘
                   │              │
                   └──────────────┘
                          │
                          │ next Get() reconnects
                          ▼
                   ┌──────────────┐
                   │  Reconnecting│
                   └──────────────┘
```

Keepalive: `*ssh.Client` is configured with
`ServerAliveInterval = 30s`, `ServerAliveCountMax = 3`. If the underlying
TCP connection dies, our `Pool.Get()` detects it on next use (via a
fast `client.Conn.SendRequest("keepalive@msb", true, nil)` probe), drops
the dead client, and dials fresh.

### 12.2 Session States

```
   ┌──────────┐
   │  Ready   │◄──────┐
   └────┬─────┘       │
        │ Send()      │ command completes
        ▼             │
   ┌──────────┐       │
   │  Busy    │───────┘
   └────┬─────┘
        │ Send timeout, or sentinel mismatch
        ▼
   ┌──────────┐
   │  Error   │
   └────┬─────┘
        │ Close()
        ▼
   ┌──────────┐
   │  Closed  │
   └──────────┘
```

A `Busy` session that doesn't return to `Ready` within `timeout_ms`
becomes `Error`. The next `Send` to an `Error` session returns
`SESSION_DEAD`; the client must `session_close` and `session_start`
again.

### 12.3 Idle Reapers

Two goroutines run alongside the MCP server:

- **Connection reaper** (every 60s): walks `Pool`, closes connections
  with `time.Since(lastUsed) > conn_idle_seconds`.
- **Session reaper** (every 60s): walks `session.Manager`, closes
  sessions with `time.Since(lastActivity) > session_idle_seconds`.

Both honor a shutdown context.

### 12.4 ProxyJump Implementation

When `server.ProxyJump` is set:

1. Pool.Get(jumpName) — recursive (with cycle check); jump server
   itself may have its own ProxyJump.
2. On the jump connection, call `Dial("tcp",
   target.Host:target.Port)` to get a `net.Conn`.
3. Pass that `net.Conn` to `ssh.NewClientConn` with the target's
   `ssh.ClientConfig` (separate auth from the jump).

The chain is built lazily on first use and cached. Dropping the jump
connection invalidates downstream connections; reaper handles cleanup.

---

## 13. Security Hard Constraints

This section is the **acceptance criteria** for the project's security
posture. Each item maps to a test in `/internal/safety/safety_test.go`
or a CI check.

| ID | Constraint | Verification |
|---|---|---|
| S-1 | No path arrives at SFTP/shell unvalidated | Static check: every call site of `*sftp.Client` methods uses a `safety.RemotePath`. Enforced by linter rule. |
| S-2 | `cwd` is never string-concatenated into a shell command body | Static check: `internal/ssh/exec.go` constructs commands via `safety.NewRemoteCommand` only. `grep -E '"cd ${' src/**/*.go` returns zero. |
| S-3 | Host key callback is `safety.HostKeyCallback`, never `ssh.InsecureIgnoreHostKey` | Static check: `grep InsecureIgnoreHostKey internal/` returns zero. |
| S-4 | Plaintext passwords in config require explicit opt-in | Unit test: load config with plaintext password and `allow_config_plaintext_password=false` → expect error containing "PLAINTEXT_PASSWORD_DISABLED". |
| S-5 | Audit log writes precede destructive ops | Integration test: inject failing audit writer, attempt `ssh_exec touch /tmp/x`, verify file was NOT touched. |
| S-6 | Inline credentials never appear in audit log | Integration test: call `ssh_exec` with `inline.password="SECRET-MARKER-XYZ"`, grep audit file for marker → expect zero matches. |
| S-7 | Secrets are zeroed after use | Unit test: instrument `Secret.Close` to verify backing array is all zeros. |
| S-8 | `0600` permissions on audit files, `0700` on state dir | Integration test: stat created files. |
| S-9 | Tunnel local listener defaults to 127.0.0.1 | Unit test: `tunnel create` with no `local_bind` → listener bound to `127.0.0.1`. |
| S-10 | No autoApprove example for destructive tools | CI check: grep `examples/` for `autoApprove` → must NOT contain `ssh_exec` or `sftp_op`. |
| S-11 | Weak SSH algorithms are off by default | Unit test: `safety.ModernAlgorithms(nil).Ciphers` does not contain any `*-cbc`. |
| S-12 | Group exec does not accept inline credentials | Unit test: schema validation rejects `inline` in `ssh_group_exec`. |
| S-13 | Remote commands sent via SSH exec channel, not via shell concatenation in our code | Code review checklist item; covered by S-2. |
| S-14 | `ssh_quick_setup` always issues an elicitation | Integration test against a fake MCP client: `ssh_quick_setup` triggers `elicitation/create`. |
| S-15 | Migration command does not log the secrets it migrates | Unit test: redirect stdout, run migration on temp .env with marker password, grep output for marker → expect zero. |

These constraints **cannot be removed without a major-version bump**.

---

## 14. Project Layout and Build

### 14.1 Repository Structure

```
mcp-ssh-bridge/
├── .github/
│   └── workflows/
│       ├── ci.yml                # tests, lint, security checks
│       └── release.yml           # goreleaser binaries
├── cmd/
│   └── mcp-ssh-bridge/
│       ├── main.go               # entrypoint, dispatch CLI vs MCP
│       ├── cli.go                # CLI subcommand routing
│       ├── cli_server.go         # `server add/list/remove/test/show`
│       ├── cli_auth.go           # `auth set/get/remove/list`
│       ├── cli_trust.go          # `trust`
│       ├── cli_migrate.go        # `migrate-from-legacy/migrate-passwords`
│       ├── cli_install.go        # `install claude-desktop/...`
│       └── cli_audit.go          # `audit query`
├── internal/
│   ├── envelope/                 # response envelope (§5.1)
│   ├── config/                   # TOML loader (§5.2)
│   ├── auth/                     # credential resolution (§5.3, §8)
│   ├── safety/                   # validation, escape, host keys (§5.4)
│   ├── ssh/                      # SSH client + pool (§5.5)
│   ├── sftp/                     # SFTP wrapper (§5.6)
│   ├── session/                  # persistent shells (§5.7)
│   ├── tunnel/                   # port forwarding (§5.8)
│   ├── audit/                    # JSONL audit log (§5.9)
│   ├── mcpserver/                # MCP server bootstrap, middleware
│   └── tools/
│       ├── exec.go               # ssh_exec
│       ├── session_start.go
│       ├── session_send.go
│       ├── session_close.go
│       ├── sftp_list.go
│       ├── sftp_read.go
│       ├── sftp_stat.go
│       ├── sftp_op.go
│       ├── group_exec.go
│       ├── tunnel.go
│       ├── list_servers.go
│       ├── audit_query.go
│       └── quick_setup.go
├── docs/
│   ├── threat-model.md           # §3 expanded for end users
│   ├── configuration.md          # config reference
│   ├── tool-reference.md         # per-tool docs (mirrors §6)
│   ├── migration-from-legacy-ssh-tool.md
│   └── security-checklist.md     # §13 with explanations
├── examples/
│   ├── config.toml               # canonical example
│   ├── config-min.toml           # minimal (one server, agent auth)
│   ├── claude-desktop.json       # NO autoApprove
│   ├── claude-code.json          # NO autoApprove
│   └── codex-config.toml
├── scripts/
│   ├── install.sh
│   └── check-no-insecure.sh      # CI: grep for forbidden patterns
├── go.mod
├── go.sum
├── LICENSE                        # Apache 2.0
├── README.md
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
└── SECURITY.md                    # how to report vulns
```

### 14.2 Module Boundaries (Enforced)

A `make check-deps` script (also CI) enforces:

```
cmd/             may import: internal/*
internal/tools/  may import: internal/{envelope, config, auth, safety,
                              ssh, sftp, session, tunnel, audit}
internal/ssh/    may import: internal/{safety, config}
internal/sftp/   may import: internal/{safety}
internal/session/ may import: internal/{ssh, safety}
internal/tunnel/ may import: internal/{ssh, safety}
internal/audit/  may import: internal/{safety}
internal/auth/   may import: internal/{safety, config (types only)}
internal/config/ may import: internal/{}                          (none)
internal/safety/ may import: internal/{}                          (none)
internal/envelope/ may import: internal/{}                        (none)
```

Violations break CI. This avoids the original project's 4,700-line
`index.js`-style entanglement.

### 14.3 Build

```bash
# Development
go build -o bin/mcp-ssh-bridge ./cmd/mcp-ssh-bridge

# Release (multi-platform)
# Done by goreleaser; produces tarballs for:
#   darwin-arm64, darwin-amd64
#   linux-arm64, linux-amd64
#   windows-amd64
goreleaser release --clean
```

Build flags:
```bash
go build -trimpath \
         -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT" \
         -o mcp-ssh-bridge ./cmd/mcp-ssh-bridge
```

`-trimpath` removes local file paths from the binary (important since
the binary may be distributed). `-s -w` strips debug info for size.

### 14.4 Go Version Policy

Track the two most recent minor versions of Go (currently 1.22 and 1.23
as of 2026-05). Drop the older when a new minor releases. This matches
upstream Go support policy.

---

## 15. Testing Strategy

### 15.1 Test Pyramid

| Level | Coverage | Tools | Run on |
|---|---|---|---|
| Unit | individual funcs in safety, config, audit, envelope | `go test` | every commit |
| Integration | tool handlers against mock SSH server | `go test -tags=integration` | every PR |
| End-to-end | real binary against `gliderlabs/ssh` test server | shell scripts | nightly |
| Fuzz | safety.ValidateRemotePath, safety.RedactSecret | `go test -fuzz` | weekly |

### 15.2 Mock SSH Server

Tests use `gliderlabs/ssh` to spin up an in-process SSH server that
accepts a configurable set of public keys / passwords and executes
commands via `os/exec`. This gives us:

- Real SSH protocol round-trips (catches algorithm mismatches)
- Controllable behavior (can simulate slow auth, dropped connections,
  bad host keys)
- No external dependencies

Mock server fixtures live in `internal/testfixtures/sshserver/`.

### 15.3 Critical Test Cases

Each security constraint in §13 has at least one named test:

```go
// internal/safety/safety_test.go
func TestS1_RemotePathValidationRejectsInjection(t *testing.T) { ... }
func TestS2_RemoteCommandConstructorEscapesCwd(t *testing.T) { ... }
func TestS3_HostKeyCallbackRejectsMismatch(t *testing.T) { ... }
func TestS4_PlaintextPasswordRejectedWithoutOptIn(t *testing.T) { ... }
func TestS5_AuditFailureBlocksMutatingOps(t *testing.T) { ... }
func TestS6_InlinePasswordNeverInAuditLog(t *testing.T) { ... }
func TestS7_SecretZeroedAfterClose(t *testing.T) { ... }
func TestS8_AuditFilePermissions(t *testing.T) { ... }
func TestS9_TunnelDefaultBindLocalhost(t *testing.T) { ... }
func TestS10_ExamplesNoAutoApproveDestructive(t *testing.T) { ... }
func TestS11_DefaultCiphersExcludeWeak(t *testing.T) { ... }
// ... etc
```

A `make check-security` target runs only these tests, used as a
quick pre-release gate.

### 15.4 Coverage Targets

- Overall: ≥ 70% line coverage (MVP)
- `internal/safety`: ≥ 95% (it's the security core)
- `internal/auth`: ≥ 90%
- `internal/audit`: ≥ 90%

### 15.5 CI Pipeline

```yaml
# .github/workflows/ci.yml (sketch)
jobs:
  test:
    matrix:
      os: [ubuntu-latest, macos-latest]
      go: ["1.22", "1.23"]
    steps:
      - go test ./... -race -coverprofile=cover.out
      - go vet ./...
      - golangci-lint run
      - ./scripts/check-no-insecure.sh
      - ./scripts/check-module-deps.sh
      - go test -tags=integration ./...
  security:
    steps:
      - gosec ./...
      - govulncheck ./...
      - go test -run 'TestS[0-9]+' ./...
```

`gosec` runs static security analysis. `govulncheck` checks dependencies
against the Go vuln database.

---

## 16. Release and Versioning

### 16.1 SemVer

- v0.x — pre-stable. Breaking changes possible at minor.
- v1.0 — first stable. Breaking tool schemas or config format
  require v2.
- Tool schemas (`Response.data` shape, error codes) are part of the
  stable API.
- Internal packages (`internal/`) have no API stability guarantee.

### 16.2 Release Cadence

- Patch (security/bugfix): as needed, within 7 days of fix.
- Minor (new features): when ready, no fixed cadence.
- Major: only when forced by spec changes or fundamental redesign.

### 16.3 Distribution

| Channel | Method |
|---|---|
| `go install` | source build from tag |
| GitHub Releases | pre-built binaries, signed with cosign |
| Homebrew tap | `brew install <tap>/mcp-ssh-bridge` |
| (later) AUR | community-maintained |
| (later) `npm install -g mcp-ssh-bridge` | wrapper that downloads correct binary |

We do **not** publish to npm as a primary channel because that's the
distribution model of the project we're improving on.

### 16.4 Security Disclosure

`SECURITY.md` documents:
- Email contact (PGP key fingerprint published)
- Expected response time (3 business days)
- 90-day disclosure window
- Hall of fame for reporters

---

## Appendix A: Dependency Pinning

`go.mod` (target versions, frozen at MVP start):

```
module github.com/<owner>/mcp-ssh-bridge

go 1.22

require (
    github.com/modelcontextprotocol/go-sdk          v1.0.0    // or latest stable
    golang.org/x/crypto                              v0.32.0
    github.com/pkg/sftp                              v1.13.7
    github.com/pelletier/go-toml/v2                  v2.2.3
    github.com/zalando/go-keyring                    v0.2.6
    github.com/google/uuid                            v1.6.0
    github.com/oklog/ulid/v2                          v2.1.0     // for session ids
)

// test-only
require (
    github.com/gliderlabs/ssh                         v0.3.7    // mock server
    github.com/stretchr/testify                       v1.10.0
)
```

`go.sum` checksums must match. Renovate/Dependabot is enabled with:
- security updates: auto-PR + auto-merge after CI green
- minor updates: auto-PR, manual review
- major updates: auto-issue, manual review

A SBOM (CycloneDX) is generated per release via `cyclonedx-gomod` and
attached to GitHub release assets.

---

## Appendix B: Migration Guide from legacy-ssh-tool

Operators migrating from `a-legacy-ssh-tool` should follow this
checklist. The migration tool automates most of it.

### B.1 Inventory

```bash
$ mcp-ssh-bridge migrate-from-legacy ~/.config/legacy-ssh-tool/.env --dry-run
```

This prints a report:
- Servers found
- Auth method per server
- Plaintext passwords detected
- Servers using deprecated SSH algorithms (none of our concern; they
  just won't connect by default — opt in via `weak_algorithms_opt_in`)
- Any `proxy_jump` chains

### B.2 Tool Mapping

| `legacy-ssh-tool` tool | `mcp-ssh-bridge` equivalent |
|---|---|
| `ssh_execute` | `ssh_exec` (rename + structured output) |
| `ssh_execute_sudo` | **removed** — use `ssh_exec` with `sudo` in command, configure NOPASSWD on remote |
| `ssh_upload` | `sftp_op` action=`write` |
| `ssh_download` | `sftp_read` |
| `ssh_sync` | **removed** — use `ssh_exec` to invoke remote `rsync` |
| `ssh_tail` | `ssh_exec` with `stream: true` and `tail -f` |
| `ssh_monitor` | `ssh_exec` with composed command (`top -b -n 1; df -h; free -m`) |
| `ssh_history` | `audit_query` (richer, queryable) |
| `ssh_session_*` | `session_*` (rename + sentinel-based protocol) |
| `ssh_execute_group` | `ssh_group_exec` (similar) |
| `ssh_group_manage` | **removed** — use `tags` in config |
| `ssh_tunnel_*` | `tunnel` (action=`create/list/close`) |
| `ssh_deploy` | **removed** — compose via `sftp_op` + `ssh_exec` |
| `ssh_alias` | **removed** — use server name or config tags |
| `ssh_command_alias` | **removed** — LLM can compose commands directly |
| `ssh_hooks` | **removed** |
| `ssh_profile` | **removed** |
| `ssh_connection_status` | `list_servers` (limited) + `audit_query` |
| `ssh_key_manage` | CLI: `mcp-ssh-bridge trust` |
| `ssh_health_check` | `ssh_exec` with composed command |
| `ssh_service_status` | `ssh_exec systemctl status <svc>` |
| `ssh_process_manager` | `ssh_exec ps aux` etc. |
| `ssh_alert_setup` | **removed** — out of scope |
| `ssh_backup_*` | **removed** — out of scope |
| `ssh_db_*` | **removed** — use `ssh_exec` with native CLI clients |

### B.3 Workflow Changes

The most impactful changes for a user:

1. **No more autoApprove for destructive tools.** Each
   `ssh_exec`/`sftp_op` write requires user confirmation in Claude
   Desktop. This is intentional. Add specific commands to your
   client's allowlist if your client supports per-tool/per-arg rules.

2. **First connection requires `trust`.** The pattern
   `ssh-keyscan host >> known_hosts` no longer happens silently.
   Run `mcp-ssh-bridge trust <name>` when adding a server.

3. **Sudo:** configure `NOPASSWD` for the relevant commands on the
   remote system, or use a `session_*` flow where you can interactively
   answer the prompt.

4. **Database tools removed.** Use `ssh_exec` with `mysql -u... -e
   "..."` (set `~/.my.cnf` for credentials so they don't appear in
   command line). For long-running queries, use a session.

---

**END OF SDD**

This document is the source of truth for the v1.0 MVP. Any deviation
during implementation must be reflected back here via a PR that updates
the SDD before the implementation lands.

