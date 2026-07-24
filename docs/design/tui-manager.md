# 架构方案：SQLite 混合存储 + 轻量实时可观测 + 管理型 TUI

状态：**待批准**（2026-07-13）。地基决策已锁定（见 §1）；本文档是 W1（存储+可观测+TUI）的总体架构方案，W2（版本/CI/升级）另见 §11。实现采用适合本项目的 Go TUI 分层与单屏运维交互。

关联记忆：[[ssh-mcp 2026-07-13 方向重塑]]、[[command-policy]]、[[数据安全第一优先]]。

---

## 1. 已锁定的地基决策（2026-07-13 用户拍板）

| 决策 | 选择 |
|---|---|
| TUI 框架 | **Bubble Tea + Bubbles + Lip Gloss** |
| 存储 | **SQLite 混合**：操作数据（审计/日志/实时态/记录）进 SQLite；安全敏感 config 项留 TOML；密钥留 keychain |
| SQLite 驱动 | **modernc.org/sqlite（纯 Go，无 cgo）** |
| 实时可观测 | **轻量路径**：MCP 进程心跳上报 live 状态到 SQLite，TUI 轮询近实时；**无 daemon** |
| 探测方式 | **被动上报，不主动探测** |
| 版本方案 | **`YYYYMMDD.V`**（W2） |

## 2. 问题与动机

ssh-mcp 面向 AI 客户端（stdio MCP），但持久数据对**人类**的管理与可观测入口分散、且完全没有「此刻在发生什么」的视角：

- 命令策略无 CLI 写入路径，只能手编 TOML（[[command-policy]]）。
- 审计只能一次性 `audit query`，无交互浏览。
- **活跃 session/tunnel/连接完全不可见**：它们活在 AI 客户端临时拉起的 MCP 进程内存里，另一个进程（CLI/TUI）无从观测。

## 3. 目标 / 非目标

**目标**
- SQLite 作为**操作数据统一存储**（审计 + 运行日志 + 记录 + 实时态），WAL 多进程安全。
- **轻量实时可观测**：TUI 近实时看到「此刻有哪些活跃 session/tunnel/连接、在哪台机器」。
- `ssh-mcp tui` Bubble Tea 管理台：服务器/凭据/trust/命令策略读写全功能 + 审计浏览 + 实时可观测视图。
- 所有写复用与 CLI 同一套 core；危险操作二次确认；密钥/密码/token 界面永不显原文。

**非目标**
- **不引入常驻 daemon**、不做 C/S 化、不监听网络端口（轻量路径的前提）。
- **不主动探测**远端健康（可观测只来自正在发生的 MCP 活动的被动上报）。
- 不远程/多租户（纯本地 same-user）。
- 密钥**永不入 SQLite**（仍 keychain）。

## 4. 存储架构（本方案的新核心）

### 4.1 三层数据归属

| 数据 | 归属 | 理由 |
|---|---|---|
| 服务器定义、settings、命令策略、proxy | **config.toml**（不变） | 保住「人工改文件 = 人类意图」信任边界；`upload_local_allowed_paths` 等敏感项 SECURITY.md 明确不可经任何工具写。TUI 通过 Phase 0 的 config 写 core 编辑 TOML |
| 密钥/密码/passphrase | **keychain**（不变） | 永不入库；`auth.SetKeychain/DeleteKeychain` 已可复用 |
| 审计、运行日志、记录、**live 状态** | **SQLite** | 统一查询、TUI 浏览、实时可观测的载体 |

> 采「config 全留 TOML、SQLite 只装操作数据」这一最简混合（§11-D1 可再议）：完整保住现有 config 信任模型与迁移工具，同时拿到统一操作存储与实时可观测，改动面最小。

### 4.2 SQLite 概览

- 位置：`~/.local/state/ssh-mcp/ssh-mcp.db`（遵循 XDG，与现审计目录同级），**WAL 模式**（多个 MCP 进程 + TUI + CLI 并发读写安全），`0600`。
- 驱动：`modernc.org/sqlite`（纯 Go，不破坏 5 平台交叉编译）。
- 新包 `internal/store`：封装打开/迁移(schema version)/读写；被 mcpserver 运行时、CLI、TUI 并列复用，保持存储核心与界面层解耦。
- 表（概览）：
  - `audit`：迁移自现 JSONL（字段对齐 `audit.Entry`）。保留 fail-closed 语义——破坏性工具执行前先写 `status=pending` 行（事务提交失败即拒绝执行）。
  - `logs`：结构化运行日志（可选，替代/补充 stderr）。
  - `live_sessions` / `live_tunnels` / `live_connections`：实时态，见 §5。
  - `records`：预留（用户提到的「记录」，具体语义待定，§11-D3）。
- **fail-closed 与 durability**：审计写入用同步事务（`PRAGMA synchronous=NORMAL` + WAL，或关键写用 `FULL`）。SECURITY.md 的「本地可写攻击者可改审计」仍属非目标，但迁 SQLite 后需复核 append-only 语义（不暴露 UPDATE/DELETE audit 的 core API）。

### 4.3 迁移

- 现有 JSONL 审计一次性导入 SQLite（`ssh-mcp migrate-audit` 或首次启动自动导入，幂等）。
- config.toml 不迁移（留 TOML）。

## 5. 轻量实时可观测

**机制（被动上报，无 daemon）**：
- MCP 运行时（`internal/session`、`internal/tunnel`、`internal/ssh` 连接池）在建立/存活/关闭 live 资源时写 SQLite `live_*` 表：`{id, server, kind, pid, mcp_client, started_at, last_heartbeat}`。
- 存活期定时（如每 2–5s）更新 `last_heartbeat`；干净关闭时删行。
- TUI 轮询 `live_*`，只显示 `last_heartbeat` 在 TTL 内（如 < 3×心跳间隔）的行为「活跃」；进程崩溃遗留的陈旧行按 TTL 判死（读时过滤 + 惰性 reaper 清理）。
- 近实时（心跳/轮询粒度，秒级），非推送。

**边界**：v1 **只读观测**。「从 TUI 杀掉某活跃 session」需属主 MCP 进程配合——后续可加「写请求行→属主进程轮询消费」的命令通道（§11-D4），非 v1。

## 6. 框架决策（已定）：Bubble Tea

Go 侧采用 Bubble Tea 的原生职责映射（`App`→`Model`、`poll_*`→`Update` 消息、`render`→`View`、`keymap`→`bubbles/key`+`help`、多字段表单→`bubbles/textinput` 组合而非手写 inline editor）。tview 因状态分散、观感更远被否决。

## 7. TUI 屏幕

| 屏幕 | 数据源 | 操作 |
|---|---|---|
| 服务器列表（主表格） | config.Servers | 搜索/排序/多选、`enter` 详情、`a` 增 `d` 删 |
| 服务器详情 | ServerConfig | host/port/user/auth(脱敏)/policy/**关联的 live 连接** + 最近审计 |
| 新增/编辑服务器（多字段表单） | 同上 | `bubbles/textinput`，提交校验→config 写 core |
| 命令策略编辑器 | Mode/Allow/Deny | 保存前 `config.Load(tmp)` 复验正则 |
| **实时可观测视图** | SQLite `live_*` | 近实时列出活跃 session/tunnel/连接（server/pid/时长/客户端）；只读 |
| 审计浏览器 | SQLite `audit` | 按 server/tool/status/时间筛选翻页；只读 |
| 凭据管理 | keychain | Set/Delete，仅显 account 名 |
| Trust 管理 | known_hosts | 列/新 trust(指纹二确认)/吊销 |

导航：list→modal；`keymap` 单一事实来源驱动状态栏 + `?` help；host key 首连确认/连通测试用挂起 TUI 跑外部交互。

## 8. 写安全

- 全部写走 core（config 写 core / `auth.*Keychain` / trust core），与 CLI 同一份校验/原子写/keychain，不重实现。
- 删除服务器/吊销 trust/删凭据 → `y` 二次确认；删服务器先备份 config.toml（可恢复，[[数据安全第一优先]]）。
- 敏感字段界面只显示状态而不显示原文，并用断言测试守护；审计已有 `RedactSecret`，展示层再兜一层。

## 9. 分层与 core 复用

```
config.toml ─ internal/config (加 Save + 服务器/策略写 core)  ┐
keychain    ─ internal/auth   (已有)                          ├─ 被 cmd/ssh-mcp/cli_*.go 与 internal/tui 并列复用
SQLite      ─ internal/store  (新: audit/logs/live/records)   │
known_hosts ─ internal/knownhosts (抽 trustHostKey)           ┘
                         ▲
              internal/tui (Bubble Tea) 只是这些 core 的前端，不重实现
```
`scripts/check-deps.sh` 需给 `internal/tui`、`internal/store` 加 allowlist 条目（否则 CI check-deps 失败，见 [[ssh-mcp anti-pattern check-deps allowlist]]）。

## 10. 实施拆分（W1，每阶段独立可部署、测试先行）

1. **Phase 0 — config 写 core 下沉**（无 SQLite/TUI）：`config.Save` + 服务器/策略增删改 core，trust 抽 `internal/knownhosts`，CLI 改薄壳，`config add-server` 补 `--mode/--allow/--deny`。**独立发布即补上命令策略 CLI 写入缺口**。
2. **Phase 1 — SQLite 操作存储**：`internal/store`（modernc + WAL + schema 迁移）；审计 JSONL→SQLite 迁移 + `audit.Record/Query` 改走 store（保 fail-closed）；check-deps 加 `internal/store`。安全复核 append-only。
3. **Phase 2 — live-state 心跳上报**：`internal/session`/`internal/tunnel`/`internal/ssh` 池写 `live_*` + 心跳 + 关闭删行 + TTL reaper。这是实时可观测的后端。
4. **Phase 3 — Bubble Tea TUI**：`ssh-mcp tui` + 服务器 CRUD（Phase 0 core）+ 审计浏览 + **实时可观测视图**（Phase 2 数据）+ 策略/凭据/trust 编辑；check-deps 加 `internal/tui`。

## 11. 待决策点 & W2

**待决策（写进后续阶段设计，非阻塞开工）**
- **D1**：混合粒度——server 定义是否也进 SQLite？（倾向：全留 TOML，最简、保全信任模型。若要 TUI 事务化管理服务器+策略，可再议）
- **D2**：审计迁 SQLite 是 Phase 1 强制，还是先并存双写观察？（倾向：迁移 + 保留导出）
- **D3**：`records` 表语义待定（用户提到「记录」——是命令历史？会话回放？收藏？）
- **D4**：TUI 控制 live session（杀/接管）是否后续做（需命令通道）。

**W2 — 版本 `YYYYMMDD.V` + CI 自动构建 + 自动升级**（相对独立，可先行/并行）
- 版本：改 ldflags 注入 + `release.yml` tag 匹配（现 `v[0-9]+.[0-9]+.[0-9]+` → 新格式）；`internal/updater` 版本比较改成能比 `YYYYMMDD.V`（现 SemVer 感知）；CHANGELOG/SECURITY supported-versions 更新。
- CI/升级：现有 `ci.yml`/`release.yml`/`release-dev.yml` + `ssh-mcp update` 适配新版本方案；「自动升级」的自动程度（自动检查提示 vs 自动应用）待定。
