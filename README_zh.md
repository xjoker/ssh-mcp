# ssh-mcp

将 SSH 操作封装为 MCP 工具，供 AI 助手直接调用 —— 执行命令、管理文件、建立隧道、维持持久会话。

**[English →](README.md)**

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
请使用 ssh_quick_setup MCP 工具连接我的 SSH 服务器。
询问我：主机地址、端口、用户名和认证方式（agent / key / password）。
```

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

Claude Code 默认对每次 MCP 工具调用弹出确认提示。将以下内容加入 `~/.claude/settings.json`（用户全局）或 `.claude/settings.json`（仅当前项目），可预授权所有 ssh-mcp 工具：

```json
{
  "permissions": {
    "allow": ["mcp__ssh-bridge__*"]
  }
}
```

或按需授权单个工具以获得更精细的控制：

```json
{
  "permissions": {
    "allow": [
      "mcp__ssh-bridge__ssh_exec",
      "mcp__ssh-bridge__sftp_list",
      "mcp__ssh-bridge__sftp_read",
      "mcp__ssh-bridge__list_servers",
      "mcp__ssh-bridge__session_start",
      "mcp__ssh-bridge__session_send",
      "mcp__ssh-bridge__session_close",
      "mcp__ssh-bridge__audit_query",
      "mcp__ssh-bridge__self_update"
    ]
  }
}
```

> `permissions.allow` 只预批准指定工具，有别于 MCP 配置中的 `autoApprove`（全局跳过所有确认）。ssh-mcp 示例配置中刻意不使用 `autoApprove`。

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
| `sftp_op` | 上传、下载、创建目录、删除、移动、复制、创建软链接、stat、realpath。 |
| `sftp_list` | 列出远程目录内容（含元数据）。 |
| `sftp_read` | 读取远程文件，支持字节偏移（tail / seek）。 |
| `sftp_stat` | 查询单个远程路径的元数据。 |

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
| `tunnel` | 建立本地或远程端口转发。本地：`localhost:{port} → 服务器:{remotePort}`；远程：`服务器:{port} → localhost:{localPort}`。 |

### 服务器管理

| 工具 | 说明 |
|------|------|
| `list_servers` | 列出已配置的服务器，支持标签过滤。 |
| `ssh_quick_setup` | 使用内联凭据注册临时服务器 —— 存储在内存中，有 TTL（最长 4 小时），不写入磁盘。 |

### 审计

| 工具 | 说明 |
|------|------|
| `audit_query` | 搜索仅追加的 JSONL 审计日志，支持按服务器、工具、时间范围、退出码、错误状态过滤。 |

### 自更新

| 工具 | 说明 |
|------|------|
| `self_update` | 检查是否有新版本并原子替换二进制。`check_only: true` 仅检查不下载。更新后需重启 MCP server 以应用新版本。 |

---

## 核心亮点

**多跳 SSH 跳板链**
通过 `proxy_jump` 透明地经过跳板机路由。任意深度的链路均可工作——在 `config.toml` 里配置 `proxy_jump` 即可，A → B → C 无需额外设置。

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
- **`allowed_paths` 执行** —— SFTP 路径在策略应用前通过 SFTP `realpath` 规范化，消除软链接 TOCTOU 漏洞。
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
ssh-mcp config init
ssh-mcp config validate
ssh-mcp config add-server <名称> --host H --user U --auth agent|key|password
ssh-mcp trust <名称>
ssh-mcp auth set ssh-password:<名称>
ssh-mcp server list
ssh-mcp server test <名称>
ssh-mcp audit query --tool ssh_exec --since 24h
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
