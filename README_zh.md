# ssh-mcp

将 SSH 操作封装为 MCP 工具，供 AI 助手直接调用 —— 执行命令、管理文件、建立隧道、维持持久会话。

**[English README →](README.md)** （权威版本 / authoritative source）

> 本文档为 [English README](README.md) 的翻译版本。当中英描述出现冲突时，以英文版本为准。新功能/新版本通常先在英文版本落地，中文版会在同一 release 内同步翻译。

---

## 让 AI 助手帮你完成安装

> 已经在用 Claude Code 或 Codex？粘贴**第一阶段**提示词完成安装和注册；重启 AI 客户端后，用**第二阶段**提示词通过 MCP 工具添加服务器，无需再执行命令行。

### 第一阶段 — 安装与注册（Claude Code）

```
用命令行在我的机器上安装 ssh-mcp（此时 MCP 尚未启动）：

1. 调用 GitHub releases API 获取最新版本号：
   GET https://api.github.com/repos/xjoker/ssh-mcp/releases
   使用 releases[0].tag_name 作为版本号。

2. 检测我的操作系统和 CPU 架构，下载对应二进制文件：
   URL: https://github.com/xjoker/ssh-mcp/releases/download/{tag}/ssh-mcp_{os}_{arch}
   os 取值：linux | darwin | windows
   arch 取值：amd64 | arm64（Windows 仅支持 amd64）
   Windows 下文件名添加 .exe 后缀。

3. 安装二进制：
   macOS/Linux → ~/.local/bin/ssh-mcp（chmod +x，目录不存在则创建）
   Windows     → %LOCALAPPDATA%\Programs\ssh-mcp\ssh-mcp.exe

4. 运行：ssh-mcp config init

5. 注册到 Claude Code：
   claude mcp add --transport stdio --scope user ssh-bridge -- ~/.local/bin/ssh-mcp
   （Windows 使用第 3 步的完整 .exe 路径）

6. 验证：ssh-mcp version

然后告诉我："完成 —— 请重启 Claude Code 以激活 MCP server。"
```

> 重启 Claude Code 后，`ssh-mcp` MCP 工具即可使用。使用**第二阶段**提示词添加服务器。

### 第二阶段 — 添加服务器（通过 MCP 工具）

重启后，粘贴：

```
开始前，请将以下内容添加到 ~/.claude/settings.json，以避免低风险
ssh-mcp 工具每次调用都弹出确认提示：

  {
    "permissions": {
      "allow": [
        "mcp__ssh-bridge__list_servers",
        "mcp__ssh-bridge__sftp_list",
        "mcp__ssh-bridge__sftp_read",
        "mcp__ssh-bridge__sftp_stat",
        "mcp__ssh-bridge__audit_query"
      ]
    }
  }

然后使用 ssh_quick_setup MCP 工具连接我的 SSH 服务器。
询问我：主机地址、端口、用户名和认证方式（agent / key / password）。
```

> `ssh_quick_setup` 将服务器凭据注册到内存（TTL 最长 4 小时）。常用服务器建议直接写入 `config.toml` 永久保存——AI 之后可以用 `server: "<名称>"` 直接调用，无需任何确认提示。
>
> **更新：** 调用 `self_update` MCP 工具即可，无需命令行。用 `check_only: true` 可先检查版本。

### Codex

第一阶段 — 把第 5 步替换为：
```
codex mcp add ssh-bridge -- ~/.local/bin/ssh-mcp
```
第二阶段 — 同上。

---

## 手动安装

**macOS / Linux：**

```sh
curl -fsSL https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.sh | bash
```

**Windows（PowerShell）：**

```powershell
iwr -useb https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.ps1 | iex
```

无需 Go 环境、无需构建工具、无需管理员权限。二进制文件直接从 [GitHub Releases](https://github.com/xjoker/ssh-mcp/releases) 下载。

| 平台 | 默认安装路径 |
|------|------------|
| macOS / Linux | `~/.local/bin/ssh-mcp` |
| Windows | `%LOCALAPPDATA%\Programs\ssh-mcp\ssh-mcp.exe` |

可通过 `PREFIX=...`（bash）或 `$env:PREFIX=...`（PowerShell）自定义安装目录。

**从源码构建：**

```sh
git clone https://github.com/xjoker/ssh-mcp.git
cd ssh-mcp
make build   # 二进制输出到 bin/ssh-mcp
```

---

## 安装后配置

```sh
ssh-mcp config init
ssh-mcp config add-server prod --host example.com --user alice --auth agent
ssh-mcp trust prod

# 注册到你的 AI 客户端：
claude mcp add --transport stdio --scope user ssh-bridge -- ~/.local/bin/ssh-mcp
codex  mcp add ssh-bridge -- ~/.local/bin/ssh-mcp
```

密码认证：

```sh
ssh-mcp config add-server prod --host example.com --user alice --auth password
ssh-mcp auth set ssh-password:prod
# 提示输入密码，不回显；密码不会写入 config.toml
```

### 预授权工具（避免每次弹出确认提示）

Claude Code 默认对每次 MCP 工具调用弹出确认提示。你可以将特定工具加入 `~/.claude/settings.json`（用户全局）或 `.claude/settings.json`（仅当前项目）的 `permissions.allow` 列表来预授权它们。

> `permissions.allow` 只预批准指定工具，有别于 MCP 配置中的 `autoApprove`（全局跳过所有确认）。ssh-mcp 示例配置中刻意不使用 `autoApprove`。

**不要使用通配符 `"mcp__ssh-bridge__*"`。** 通配符会预授权所有工具，包括破坏性和安全边界类工具，从而移除了限制 prompt injection 或模型误操作影响范围的人工确认环节。

建议按以下分级处理：

#### Tier 1 — 可以放心预授权（只读，无副作用）

```json
{
  "permissions": {
    "allow": [
      "mcp__ssh-bridge__list_servers",
      "mcp__ssh-bridge__sftp_list",
      "mcp__ssh-bridge__sftp_read",
      "mcp__ssh-bridge__sftp_stat",
      "mcp__ssh-bridge__audit_query"
    ]
  }
}
```

#### Tier 2 — 仅在理解影响的前提下预授权

这些工具会在远程服务器上执行命令或写入文件。预授权它们将移除逐次确认，从而无法拦截意外操作。

```json
{
  "permissions": {
    "allow": [
      "mcp__ssh-bridge__ssh_exec",
      "mcp__ssh-bridge__sftp_op",
      "mcp__ssh-bridge__session_start",
      "mcp__ssh-bridge__session_send",
      "mcp__ssh-bridge__session_close",
      "mcp__ssh-bridge__ssh_group_exec",
      "mcp__ssh-bridge__ssh_quick_setup"
    ]
  }
}
```

#### Tier 3 — 永远不要 wildcard 预授权；每次必须人工确认

这些工具具有持久或不可逆影响：`tunnel` 建立长期端口转发，`ssh_persistent_setup` 写入永久服务器凭据，`self_update` 替换当前运行的二进制（即安全边界本身）。请始终逐次人工确认。

- `mcp__ssh-bridge__tunnel`
- `mcp__ssh-bridge__ssh_persistent_setup`
- `mcp__ssh-bridge__self_update`

#### 为什么每次调用 `ssh_quick_setup` 都会弹确认？

你看到的"信任 host_key / 注册临时服务器"对话框来自 **Claude Code 自身的工具权限 UI**，不是 ssh-mcp 发出的。bridge 端没有任何 MCP elicitation 调用 —— 服务端代码里没有逐次确认逻辑。两个推论：

1. 把工具加入上方 `permissions.allow` 即可一劳永逸消除提示。
2. 如果是固定经常使用的服务器，**用 `ssh_persistent_setup` 注册一次**胜过反复调用 `ssh_quick_setup`。永久注册后用 `name` 直接 `ssh_exec` / `sftp_*`，不会再走 setup 工具。

对同一 `host+port+user` 重复调用 `ssh_quick_setup` 已经在内部做了去重 —— 复用既有内存注册，不分配新 name —— 但仍然会触发 Claude Code 自己的逐次工具权限检查。

---

## 功能详解

### 命令执行

| 工具 | 说明 |
|------|------|
| `ssh_exec` | 在单台服务器上执行命令。支持 PTY 模式运行 TUI 程序（htop、btop、ncdu），可过滤 ANSI 控制序列。 |
| `ssh_group_exec` | 并发在多台服务器上执行同一命令，支持按名称列表或标签选择目标。 |

### 文件操作（SFTP）

| 工具 | 说明 |
|------|------|
| `sftp_op` | 上传、下载、创建目录、删除、移动、复制、创建软链接、stat、realpath。仅适合小文件（base64 / JSON 包大小限制 —— 大文件请用下方 CLI 命令）。`realpath` 操作同样受 `allowed_paths` 约束 —— 无法用于探测允许列表以外的路径。 |
| `sftp_list` | 列出远程目录内容（含元数据）。 |
| `sftp_read` | 读取远程文件，支持字节偏移（tail / seek）。 |
| `sftp_stat` | 查询单个远程路径的元数据。 |

**大文件**和**服务器间互传**请用 CLI（直接 SFTP 流式传输，无大小限制）：

| 命令 | 用途 |
|------|------|
| `ssh-mcp upload <服务器> <本地> <远程>` | 本地 → 服务器。 |
| `ssh-mcp download <服务器> <远程> <本地>` | 服务器 → 本地。 |
| `ssh-mcp cp <源:路径> <目标:路径>` | 服务器 ↔ 服务器（本地中转，不需要服务器间 SSH 互信）。 |
| `ssh-mcp fetch <服务器> <url> <远程>` | 本地代下载推送到服务器。远端被 GFW 挡或无出网时使用。 |

### 持久 Shell 会话

| 工具 | 说明 |
|------|------|
| `session_start` | 打开持久 shell —— **哨兵模式**（等待命令退出）或 **PTY 模式**（基于时间的输出收集，适合交互式程序）。 |
| `session_send` | 向活跃会话发送输入并收集输出。 |
| `session_close` | 关闭会话并释放资源。 |

会话有状态：`cd`、设置环境变量、激活 virtualenv —— 状态在多次 `session_send` 间持续保留。

### 端口隧道

| 工具 | 说明 |
|------|------|
| `tunnel` ⚠️ | 建立本地或远程端口转发。本地：`localhost:{port} → 服务器:{remotePort}`；远程：`服务器:{port} → localhost:{localPort}`。Tier 3 — 永远不要 wildcard 预授权。 |

### 服务器管理

| 工具 | 说明 |
|------|------|
| `list_servers` | 列出已配置的服务器，支持标签过滤。默认 `refresh=true` 重读 `config.toml` —— 手动编辑后无需重启即可看到；新条目同时注入 SSH pool，`ssh_exec` / `session_start` 立即可用。 |
| `ssh_quick_setup` | 使用内联凭据注册临时服务器 —— 存储在内存中，有 TTL（最长 4 小时），不写入磁盘。同 `host+port+user` 重复调用复用既有注册。 |
| `ssh_persistent_setup` ⚠️ | 把 `[servers.<name>]` 块追加到 `config.toml`，重启后仍存在且无 TTL。密码默认存 OS keychain（`password_storage="keychain"`）—— config.toml 里只留引用；设为 `"plaintext"`（并开 `settings.allow_config_plaintext_password = true`）才直接写明文。Tier 3 — 永远不要 wildcard 预授权。 |

### 审计

| 工具 | 说明 |
|------|------|
| `audit_query` | 搜索仅追加的 JSONL 审计日志，支持按服务器、工具、时间范围、退出码、错误状态过滤。 |

### 自更新

| 工具 | 说明 |
|------|------|
| `self_update` ⚠️ | 检查是否有新版本并原子替换二进制。`check_only: true` 仅检查不下载。更新后需重启 MCP server 以应用新版本。Tier 3 — 永远不要 wildcard 预授权。 |

---

## 代理链（Proxy Chain）

对于复杂网络拓扑，`proxy_chain` 允许将某台服务器的 TCP 拨号路径经过一个或多个代理路由——HTTP CONNECT、HTTPS CONNECT、SOCKS5 或另一台 SSH 主机——按外到内的顺序串联成链。

### 支持的代理类型

| `type` | 协议 | 说明 |
|--------|------|------|
| `http` | HTTP CONNECT（明文）| 可选 Basic auth，通过 `user` + `password`（CredRef）配置 |
| `https` | HTTP CONNECT over TLS | `insecure_skip_verify = true` 仅供开发用 |
| `socks5` | SOCKS5 | 支持可选的 `user` + `password` 认证 |
| `ssh` | SSH 隧道 | 两种模式：`server = "<name>"`（推荐）或直连 `host`/`port`/`user`/`auth` |

SSH 代理建议优先使用 `server = "<name>"` 形式——可完整复用该 server 的认证配置、主机密钥固定以及嵌套的 `proxy_chain`。

### 配置示例

```toml
[proxies.corp-http]
type     = "http"
host     = "proxy.corp"
port     = 8080
user     = "alice"
password = "keychain:ssh-mcp:proxy-pass:corp"

[proxies.tor]
type = "socks5"
host = "127.0.0.1"
port = 9050

[proxies.bastion-via-server]
type   = "ssh"
server = "bastion"   # 复用 [servers.bastion] 的认证和主机密钥

[proxies.bastion-direct]
type = "ssh"
host = "jump.example.com"
port = 22
user = "deploy"
auth = "agent"

[servers.internal-db]
host        = "10.0.0.50"
user        = "dba"
auth        = "key"
key_path    = "~/.ssh/id_ed25519"
proxy_chain = ["corp-http", "tor", "bastion-via-server"]   # 外→内顺序
```

`proxy_chain` 元素按从左到右、由外到内解析：先拨 `corp-http`，再通过它隧穿 `tor`，然后 `bastion-via-server`，最终经最后一跳到达 `internal-db`。

### 规则与限制

- `proxy_chain` 与 `proxy_jump` **互斥**。存在 `proxy_chain` 时优先使用它；`proxy_jump` 保留以维持向后兼容。
- 链最大长度：**8 跳**。
- 同一链中不允许出现重复的代理名称，配置加载时即报错。
- SSH 代理的 `server` 引用会做环检测（扩展原有 `proxy_jump` 环检测逻辑）。
- 端口转发（tunnel）透明地走服务器的 `proxy_chain`，无需额外配置。
- 代理的 `password` 字段是 CredRef 字符串，与服务器凭据同等安全级别——默认走密钥链（keychain）。v0.0.6 中 `ssh` 直连模式不支持加密私钥；请用 `ssh-agent` 或通过 `server = "…"` 引用已配置的 server（servers 那侧支持 `key_passphrase`）。

---

## 核心亮点

**多跳 SSH 跳板链**
通过 `proxy_jump` 透明地经过跳板机路由。任意深度的链路均可工作——在 `config.toml` 里配置 `proxy_jump` 即可，A → B → C 无需额外设置。混合 HTTP/SOCKS5/SSH 的多协议链路请参阅上方[代理链（Proxy Chain）](#代理链proxy-chain)章节。

**PTY 支持**
`ssh_exec` 和 `session_start` 均支持完整伪终端分配。可运行 `htop`、`btop`、`ncdu`、`vim` 等 TUI 程序；使用 `strip_ansi` 获取纯文本输出。

**OS 密钥链集成**
密码存储在 macOS 钥匙串、Linux libsecret 或 Windows 凭据管理器中，永远不写入 `config.toml`。`ssh-mcp auth set` 负责录入。

**标签批量操作**
给服务器打标签（`tags = ["prod", "eu"]`），用一次 `ssh_group_exec` 调用操作整个服务器组。

**TTL 限定的内联凭据**
`ssh_quick_setup` 接受内联的密码或私钥用于临时会话。凭据存于内存，TTL 到期或关闭时自动清零。

**仅追加审计日志**
每次工具调用在执行前预先写入 JSONL 审计日志。`audit_query` 提供结构化查询；凭据字段仅显示 `{"redacted":true}`。

**自动更新**
`ssh-mcp update` 获取最新版本二进制，验证 SHA-256 后原子替换当前运行的二进制。启动时若有新版本可用，也会在 AI 客户端界面显示更新提示。

---

## 安全

- **不使用 `autoApprove`** —— 示例客户端配置刻意省略了该选项。SSH 操作影响范围不可预知，必须保持人工确认。
- **主机密钥验证** —— `HOST_KEY_MISMATCH` 是硬性中止；网桥永不自动接受变更的主机密钥。
- **首次连接信任仅通过 CLI** —— `accept_new_host` 字段已从所有 MCP 工具 schema 中移除（`ssh_quick_setup`、`ssh_exec`、`session_start`、`ssh_persistent_setup`）。新主机必须通过 CLI 建立信任：`ssh-mcp trust <name>` 或 `ssh-mcp trust --host <h> --port <p>`。CLI 会显示 SHA256 指纹并要求人工确认后才写入 known_hosts。这可防止被 prompt injection 的模型通过工具参数静默建立 TOFU 信任。
- **`allowed_paths` 执行** —— SFTP 路径在策略应用前通过 SFTP `realpath` 规范化，消除软链接 TOCTOU 漏洞。`realpath` 操作本身同样受此约束，不能用于探测允许列表以外的路径。
- **`self_update` 预审计** —— 更新操作在替换二进制前会先写入一条 pending 审计记录。若审计写入失败，更新将中止。这确保替换安全边界本身的操作始终可追溯。
- **明文密码防护** —— 除非设置 `allow_config_plaintext_password = true`，否则拒绝明文密码；推荐使用密钥链。
- 完整威胁模型见 [`SECURITY.md`](SECURITY.md)。

---

## 配置

默认位置（无需管理员权限）：

| 操作系统 | 配置文件 | 审计日志 |
|---------|---------|---------|
| macOS / Linux | `~/.config/ssh-mcp/config.toml` | `~/.local/state/ssh-mcp/` |
| Windows | `%APPDATA%\ssh-mcp\config.toml` | `%LOCALAPPDATA%\ssh-mcp\audit\` |

通过 `MCP_SSH_BRIDGE_CONFIG=/path/to/config.toml` 覆盖配置路径。

最简配置：

```toml
[servers.prod]
host = "example.com"
user = "alice"
auth = "agent"
```

跳板机链路：

```toml
[servers.bastion]
host = "bastion.example.com"
user = "ops"
auth = "key"
key_path = "~/.ssh/id_ed25519"

[servers.internal]
host = "10.0.1.50"
user = "ops"
auth = "key"
key_path = "~/.ssh/id_ed25519"
proxy_jump = "bastion"
```

完整示例：[`examples/config.toml`](examples/config.toml)

---

## CLI 速查

```sh
# 配置与服务器管理
ssh-mcp config init
ssh-mcp config validate
ssh-mcp config add-server <名称> --host H --user U --auth agent|key|password
ssh-mcp trust <名称>
ssh-mcp auth set ssh-password:<名称>
ssh-mcp server list
ssh-mcp server test <名称>

# 文件传输（SFTP 流式，无大小限制）
ssh-mcp upload   <服务器> <本地路径> <远程路径>
ssh-mcp download <服务器> <远程路径> <本地路径>
ssh-mcp cp       <源服务器>:<源路径> <目标服务器>:<目标路径>
ssh-mcp fetch    <服务器> <url> <远程路径>

# 审计与更新（默认连同 stdout/stderr 一起记录到 audit log，可通过 audit_record_output=false 关闭）
ssh-mcp audit query --tool ssh_exec --since 24h            # 元数据表
ssh-mcp audit query --tool ssh_exec --since 1h --output    # 展开模式：stdout/stderr 内联
ssh-mcp audit query --since 24h --json | jq                # JSONL 输出，方便工具消费
ssh-mcp update
ssh-mcp install claude-code     # 输出 claude mcp add 命令
ssh-mcp install codex           # 输出 codex mcp add 命令
ssh-mcp install claude-desktop  # 输出 JSON 片段
```

---

## 常见问题

| 现象 | 解决方法 |
|------|---------|
| `HOST_KEY_UNKNOWN` | `ssh-mcp trust <名称>` |
| `unable to authenticate`（密码认证）| `ssh-mcp auth set ssh-password:<名称>` |
| `SESSION_LIMIT` | 关闭空闲会话，或在配置中提高 `settings.max_sessions` |
| AI 客户端中看不到工具 | `mcp add` 后重启 AI 客户端 |
| `config: no such file` | `ssh-mcp config init` |

---

## 文档

- [`docs/AI_GUIDE.md`](docs/AI_GUIDE.md) —— 连接网桥后粘贴给 AI 助手；教导工具选择策略、错误处理方式和禁止 autoApprove 的原则
- [`examples/`](examples/) —— 配置文件和客户端片段示例
- [`SECURITY.md`](SECURITY.md) —— 威胁模型和漏洞披露政策
- [`SDD.md`](SDD.md) —— 系统设计文档

---

## 许可证

Apache 2.0，详见 [LICENSE](LICENSE)。
