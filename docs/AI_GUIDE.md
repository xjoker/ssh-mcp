# AI Assistant Guide for `ssh-mcp`

> Written for the AI assistant (Claude, Codex, GPT, Gemini, …) that has been
> given access to this MCP server. Read this once at session start; it
> changes how you should plan, sequence, and confirm SSH-related tasks.
>
> Humans: paste this file (or its URL) into your AI's context the first
> time you connect the bridge. After that the AI will know the rules.
>
> **Quick install reminder for humans:** the binary lives at
> `~/.local/bin/ssh-mcp` (macOS/Linux) or
> `%LOCALAPPDATA%\Programs\ssh-mcp\ssh-mcp.exe` (Windows).
> Register it once with your client via `claude mcp add ... ssh-bridge`
> or `codex mcp add ssh-bridge ...` — never hand-edit the client config
> if a CLI exists.

---

## 1. Mental model

`ssh-mcp` exposes a small fixed set of SSH/SFTP tools over MCP.
Tools fall into two operational classes:

| Class | Tools | Behavior contract |
|-------|-------|-------------------|
| **Read-only** | `list_servers`, `sftp_list`, `sftp_read`, `sftp_stat`, `audit_query` | Free to call without preface. Cheap, idempotent, no audit pre-record. |
| **Destructive** (have remote effects) | `ssh_exec`, `ssh_group_exec`, `sftp_op`, `sftp_upload`, `tunnel`, `session_*`, `ssh_quick_setup`, `ssh_persistent_setup` | **Always state the intended effect in plain language and wait for the user's MCP-level confirmation** (the host UI handles this — do not auto-approve). Each call is fail-closed audit-pre-recorded, so a mid-flight crash leaves a trail. |
| **Self-management** | `self_update` | Replaces the running binary atomically. After a successful update, inform the user that the MCP server process must be restarted. Use `check_only: true` first to inspect availability. |

You will *not* see an `autoApprove` flag for these tools. The user's setup
intentionally omits it. Treat every destructive call as a confirmation
checkpoint.

---

## 2. Picking the right tool

Decision order (top wins):

1. **Just inspecting?** → `sftp_stat` / `sftp_list` / `sftp_read` /
   `list_servers` / `audit_query`. Never use `ssh_exec` for `cat`, `ls`,
   `stat` — those have first-class tools.
2. **Single command on one host?** → `ssh_exec`. Pass `cwd` if the command
   is path-sensitive.
3. **Same command on many hosts?** → `ssh_group_exec` with either a
   `servers` list or a `tag`. Honor `stop_on_error` when the user said
   "stop on first failure".
4. **Multi-step interactive workflow** (sudo prompt, REPL, `cd && build &&
   test`)? → `session_start` once, `session_send` per step, then
   `session_close`. **Always close the session** even on failure.
5. **File transfer / mkdir / rename / chmod**? → `sftp_op` for **small**
   payloads (mkdir, rename, chmod, tiny configs). Don't shell out for
   these. For **uploading a local file** of any size, prefer `sftp_upload`
   over `sftp_op` — it streams straight from disk to the remote server
   inside the MCP process (no base64/JSON size limit, bytes never enter
   your context). It is disabled by default (`UPLOAD_DISABLED`) until the
   user configures `settings.upload_local_allowed_paths` in `config.toml`
   — this cannot be enabled through any tool call, so if you hit
   `UPLOAD_DISABLED`, tell the user what to add and ask them to restart
   `ssh-mcp`. For **server-to-server** transfers, or downloading a remote
   file to the local machine, ask the user to run one of the CLI commands
   instead: `ssh-mcp download <srv> <remote> <local>`,
   `ssh-mcp cp <src>:<path> <dst>:<path>` (no inter-server SSH trust
   needed), `ssh-mcp fetch <srv> <url> <remote>` (proxy through local
   when the remote can't reach the URL).
6. **Need a port-forward**? → `tunnel` action=create (local|remote). Always
   close it explicitly when the task is done.
7. **No server configured for the host the user wants**? → propose
   `ssh_quick_setup`; the bridge will elicit a UI confirm.

Anti-pattern: do not chain `ssh_exec "cd X && command"` when you can pass
`cwd: X` to a single call — the bridge canonicalises through SFTP
realpath and applies `allowed_paths` to the resolved form.

---

## 2b. PTY sessions — when and how

Use **PTY mode** (`pty: true` in `session_start`) only for programs that
check `isatty(1)` and refuse to render without a real terminal: `btop`,
`htop`, `ncdu`, `vim`, `less`, and similar TUI applications. For regular
commands, build scripts, or REPLs that work fine over a plain pipe, stick
with the default sentinel-based session — it is faster and output
collection is deterministic.

**When to use PTY vs sentinel:**

| Situation | Mode |
|-----------|------|
| TUI program that checks isatty (btop, htop, ncdu) | PTY |
| Multi-step shell workflow (cd, build, test) | Sentinel (default) |
| sudo prompt, interactive REPL | Sentinel (default) |
| Program that emits raw ANSI and you want clean text | PTY + `strip_ansi:true` |

**Opening a PTY session:**

```
session_start {
  server: "prod",
  pty: true,
  command: "btop",
  cols: 220,
  rows: 50,
  init_wait_ms: 3000
}
```

The response includes `mode: "pty"` and `initial_output` containing the
program's startup banner. Store the `session_id` for subsequent calls.

**Reading output in PTY mode:**

```
session_send {
  session_id: "<id>",
  command: "",
  timeout_ms: 2000,
  strip_ansi: true
}
```

`timeout_ms` is how long the bridge waits to collect output — it is **not**
how long the remote command runs. PTY sessions do not use the sentinel
protocol; the bridge collects whatever arrives within the timeout window.

**Terminating a TUI program:**

Send `"\x03"` (Ctrl-C), not `"q"`. The `q` key may not be processed
reliably in all PTY contexts before the program has fully initialised, and
some programs ignore it when a modal is open. After sending `"\x03"`,
always call `session_close` to release the PTY allocation.

```
session_send  {session_id: "<id>", command: "\x03", timeout_ms: 500}
session_close {session_id: "<id>"}
```

---

## 3. Mandatory pre-flight

Before any destructive call:

1. Read back the **server**, **command**, and (for sftp_op) **path** in
   one short sentence. e.g. *"I'll run `systemctl restart nginx` on
   `prod-web1`."*
2. Wait for the host UI confirmation. Do not pre-emptively retry on a
   USER_DECLINED response.
3. After completion, **summarize the result** with exit code and the
   first few lines of stderr if non-zero. Do not paste 5 KB of stdout
   without being asked.

---

## 4. Server discovery

Default first action of any session that touches SSH:

```
list_servers
```

It returns names, hosts, users, tags, descriptions — **no secrets**. Use
this to:

- Confirm the user-supplied server name actually exists.
- Resolve `tag = "prod"` to an explicit list before `ssh_group_exec`.
- Avoid leaking credentials by guessing names that don't exist.

If the user asks about a host that isn't listed:

1. For **permanent** registration (survives restart): call `ssh_persistent_setup` —
   it writes a `[servers.<name>]` block to `config.toml` and makes the entry live
   in the current session without a restart. Plaintext password storage requires
   `settings.allow_config_plaintext_password = true` in config.
2. For **ad-hoc / temporary** use (TTL up to 4 h): propose `ssh_quick_setup`.
3. As a last resort, instruct the human to run
   `ssh-mcp config add-server <name> --host H --user U ...` in a shell.

Never ask the user to paste a password into the chat. Passwords go to the
OS keychain via `ssh-mcp auth set
ssh-password:<name>`. Inline passwords are accepted by `session_start`
and `ssh_quick_setup` only because the bridge promotes them to TTL-bounded
in-memory temp servers and zeroes them on expiry/shutdown — even so, prefer
agent/key.

---

## 5. Errors you will see, and how to react

| `error.code` | Cause | Right next step |
|----|----|----|
| `INVALID_ARGUMENT` | Bad server name, wrong shape, missing field. | Re-read the schema; do **not** retry the same call verbatim. |
| `HOST_KEY_UNKNOWN` | First contact, no `known_hosts` entry. | Tell the user to run `ssh-mcp trust <name>`; do not auto-accept. |
| `HOST_KEY_MISMATCH` | Server's host key changed. | **Stop**. Surface this prominently — possible MITM. Do not retry. |
| `AUTH_FAILED` | Wrong key / password / agent unavailable. | Suggest `auth set` (password) or `ssh-add` (agent). Do not loop. |
| `PERMISSION_DENIED` | Path outside `allowed_paths`, or remote chmod refused. | Show the user the path and the configured prefix. Don't widen scope silently. |
| `TIMEOUT` | Command hit `timeout_ms`. | Retry only with explicit user OK and a higher `timeout_ms`. Note the retriable flag. **The session itself stays alive** — the next `session_send` will drain the prior command's tail output before issuing your new command. No need to start a fresh session. |
| `SESSION_BUSY` | A `session_send` arrived while the prior command's tail output was still draining (5 s budget). | Either wait briefly and retry, or call `session_close` if the prior command is stuck. Do NOT discard the session on this code. |
| `SESSION_DEAD` | The remote shell actually closed (EOF on stdout). | Discard the session_id and start a new session. This is **not** triggered by command timeout alone — only by genuine shell exit. |
| `SESSION_LIMIT` | 16 concurrent sessions reached (default). | Close idle sessions before opening more. |
| `INLINE_CREDS_DISABLED` | Operator turned off inline secrets. | Do not push back — fall back to a configured server. |
| `USER_DECLINED` | User said no in the elicitation. | Accept the decline. Do not rephrase and re-ask. |
| `AUDIT_FAILED` | Audit log unwritable. | Tool has aborted. Inform the user; do not retry until audit storage is fixed. |
| `PARTIAL_FAILURE` (group_exec) | Some hosts succeeded, some failed. | Summarize per host. The `data` field still has individual results. |

**Retriable** is a boolean on the error envelope. Honor it; don't retry
non-retriable codes (e.g. `HOST_KEY_MISMATCH`, `INVALID_ARGUMENT`).

---

## 6. Idiomatic patterns

### One-shot inspection
```
list_servers → sftp_list {server, path:"/var/log", recursive:false}
            → sftp_read  {server, path:"/var/log/syslog", offset:-4096}
```

### Deploy across a tag
```
list_servers {tag:"web"}
ssh_group_exec {tag:"web", command:"systemctl restart nginx",
                stop_on_error:true, max_concurrency:8}
```

### Iterative debugging session
```
session_start {server:"prod"} → session_send {command:"cd /app"}
                              → session_send {command:"npm run build"}
                              → session_send {command:"npm test"}
                              → session_close
```

### Port-forward for a local DB tool
```
tunnel {action:"create", kind:"local", server:"db",
        local_port:15432, dst_host:"127.0.0.1", dst_port:5432}
... user runs psql ...
tunnel {action:"close", tunnel_id:"<from create>"}
```

### Register a server permanently (survives restart)
```
# key-based
ssh_persistent_setup {name:"prod-db", host:"db.example.com", port:22,
                       user:"deploy", auth:"key",
                       key_path:"~/.ssh/id_ed25519"}

# password-based — secret goes to the OS keychain by default
# (password_storage="keychain"), config.toml only stores a reference.
ssh_persistent_setup {name:"prod-db", host:"db.example.com", port:22,
                       user:"deploy", auth:"password",
                       password:"<plaintext>"}
# entry is live immediately — no restart required
ssh_exec {server:"prod-db", command:"hostname"}
```

### Ad-hoc connection (TTL-bounded, in-memory only)
```
list_servers          # confirm server is absent
ssh_quick_setup {host:"new.box", user:"alice", password:"..."}
                      # bridge issues elicitation; on accept use returned name
ssh_exec {server:"<returned name>", command:"hostname"}
```

### Inspect a server with a TUI tool (PTY mode)
```
session_start {server:"prod", pty:true, command:"btop",
               cols:220, rows:50, init_wait_ms:3000}
              → session_send {session_id:"<id>", command:"",
                              timeout_ms:2000, strip_ansi:true}
              → session_send {session_id:"<id>", command:"\x03",
                              timeout_ms:500}   # Ctrl-C to exit btop
              → session_close {session_id:"<id>"}
```

---

## 7. Things to never do

- Suggest setting `autoApprove` for any of these tools.
- Echo a password the user pasted back into a tool call. If they pasted
  one in chat, advise rotating it and using `auth set`.
- Build SSH commands like `ssh user@host "cmd"` and shove them through
  some unrelated tool — every SSH path goes through the bridge.
- Run `rm -rf` style commands without an explicit, specific user request
  AND a confirmation re-read.
- Treat `ssh_quick_setup` as a workaround for "I don't want to confirm".
  It exists for ad-hoc hosts, not to bypass the confirmation gate.
- Use `inline` credentials when a configured server already exists for
  the same host.
- Query the audit log (`audit_query`) for content that you can compute
  from your own conversation history — it is for forensic review, not
  short-term memory. Each entry includes `stdout` + `stderr` of the
  recorded command (after redaction; capped by
  `settings.audit_output_max_bytes`, default 32 KiB), so a one-shot
  query can answer "what did `<server>` say to `<command>` 2 hours
  ago" without re-running anything.

---

## 8. Telling the human "I cannot proceed"

If you reach a real blocker — `HOST_KEY_MISMATCH`, repeated
`AUTH_FAILED`, `AUDIT_FAILED`, an obvious destructive request without
proper context — stop and surface it. Acceptable phrasing:

> I'm pausing here: server `prod-db` returned `HOST_KEY_MISMATCH`. This
> usually means the host key changed (re-imaged box, MITM, or rotated
> infra). Before any further command on this host, please confirm via
> another channel and either re-run `ssh-mcp trust prod-db` or
> investigate.

That paragraph is more useful than three more retries.

---

## 9. Quick reference card (copy/paste-ready)

```
SAFE-FIRST   list_servers, sftp_list, sftp_stat, sftp_read, audit_query
DESTRUCTIVE  ssh_exec, ssh_group_exec, sftp_op, sftp_upload, tunnel, session_*, ssh_quick_setup, ssh_persistent_setup
SELF-MGMT    self_update {check_only:true} to inspect; omit flag to install; restart required after
PREFLIGHT    state intent → wait for confirm → summarize result
DISCOVER     list_servers before guessing names
REGISTER     ssh_persistent_setup for permanent entries; ssh_quick_setup for TTL-bounded ad-hoc
SECRETS      keychain only; never echo passwords
RETRY        only when error.retriable == true
```
