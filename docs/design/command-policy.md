# 设计方案：per-server 命令级安全策略（command policy）

状态：**已批准**（2026-07-13，D1=内置保守 allowlist，D2=一律拒绝）

---

## 1. 问题

当前 ssh-mcp 对命令内容**零过滤**：

- `ssh_exec` / `ssh_group_exec` / `session_send` 把 `command` 原样交给远端 shell（`internal/safety/contract.go:NewRemoteCommand` 仅拼 `cd '<dir>' && <cmd>`）。
- 现有约束只有路径维度（`allowed_paths` 管 SFTP/cwd 前缀），与命令执行无关。
- 唯一的闸门是 MCP 客户端的工具级审批（如 Claude Code `permissions.allow`），它是 all-or-nothing：一旦放行 `ssh_exec`，`rm -rf /` 与 `ls` 无区别。
- 审计 `Entry` 只有 `error_code` 表达失败，没有「策略拒绝」判定，无法回答"AI 曾试图执行什么被拒了"。

核心场景：用户把 MCP 交给 AI 操作一批服务器，其中混着生产机。希望能对**个别服务器**上锁（只许观测、或只许一小组运维命令），而不改变其余服务器的现有体验。

## 2. 目标与非目标

**目标**
- per-server 可选（opt-in）的命令策略；未配置的 server 行为与现在逐字节一致，零开销。
- fail-closed：策略配置存在但为空/无效 ⇒ 拒绝，而不是放行。
- 策略拒绝进入审计，可追溯。

**非目标（文档必须诚实声明）**
- 这不是沙箱（无 seccomp/namespace）。命令一旦放行，以 SSH 用户的完整权限运行。
- 正则过滤可被构造绕过（编码载荷、shell 变量间接等）。定位是**防事故 + 防常见形态的 prompt injection** 的 defense-in-depth，严格场景应配合远端低权限账号。

## 3. 方案

### 3.1 单一引擎：allow/deny 正则（restricted 模式）

`[servers.X]` 新增字段：

```toml
[servers.prod]
# ... 现有字段 ...
mode = "restricted"                # 缺省不写 = "unrestricted"，行为不变
allow_patterns = ["^docker (ps|logs|inspect) ", "^systemctl status "]
deny_patterns  = ["--force"]
```

规则（与 fail-closed 哲学一致）：
- 命令必须**匹配至少一条 allow** 且**不匹配任何 deny**；**DENY 恒胜 ALLOW**。
- `mode = "restricted"` 且 `allow_patterns` 为空 ⇒ 一切命令拒绝（fail-closed）。
- 正则用 Go `regexp`（RE2，无灾难回溯）。无效正则 = `config.Load` 报错**启动失败**（快速失败，不学"跳过并告警"）；热重载（`list_servers refresh`）遇无效配置保留旧快照。

> **restricted 无内置元字符护栏（2026-07-13 拍板，仅文档声明）**：`readonly` 的内置 allowlist 是系统提供的，故额外硬拒 shell 元字符（§3.2）以防前缀匹配被 `;`/`|`/`` ` `` 等旁路。`restricted` 的 `allow_patterns` 是**用户自写正则**，引擎不替用户加元字符检查——一条未锚定的 `^docker ps` 会被 `docker ps; rm -rf /` 骑绕。**用户须自行锚定** allow 正则（如收尾用 `( |$)`、必要时把 `;&|<>` 写进 `deny_patterns`）。这与"defense-in-depth 而非 sandbox"的定位一致：不为不会被本模式覆盖的场景加防御性检查（避免误伤用户显式允许的 `a && b` 类多命令）。

### 3.2 readonly 模式 = 内置保守 allow 预置集（待拍板，见 §5-D1）

`mode = "readonly"` 不引入第二套引擎，而是同一引擎 + 内置预置：

- 内置**allowlist**（而非 denylist）：`ls / cat / head / tail / grep / df / du / ps / free / uname / whoami / id / date / uptime / env(只读) / docker ps|logs|inspect / kubectl get|logs|describe / systemctl status / journalctl / ss / ip addr|route` 等保守只读命令前缀集。
- 额外硬规则：命令含 shell 元字符（`;` `&` `|` `>` `<` `` ` `` `$(`）即拒绝——否则 `cat > /etc/x`、`ls; rm -rf /` 让前缀匹配失效。代价：`journalctl | grep x` 被拒，AI 需分步（journalctl 自身有 `-g` 过滤，可接受）。
- 用户可用 `allow_patterns` 在 readonly 基础上**追加**放行（如 `^php artisan `），`deny_patterns` 继续恒胜。

选 allowlist 而非同类项目常见的内置 denylist（拦 rm/mv/dd/...）的理由：denylist 是清单式安全（永远数不全危险命令），allowlist 匹配不上即拒，与本项目 `upload_local_allowed_paths` 等既有 fail-closed 设计同构。

### 3.3 工具面 gating（策略对每个工具的作用）

复用本次刚落地的 `tools.Annotations` 分类作为策略输入（同仓可信来源，非外部 hints）：

| 工具 | mode=readonly / restricted 下 |
|---|---|
| sftp_list / sftp_read / sftp_stat | **放行**（ReadOnlyHint=true，观测正是 readonly 的目的） |
| ssh_exec / ssh_group_exec / session_send | 命令过正则闸；group_exec 在 handler 内**逐目标 server**评估（同一命令可在 A 放行、在 B 拒绝） |
| session_start | 放行（只开 shell；send 逐条过闸；session 归属 server 取 `session.Server` 字段） |
| session_send 多行命令 | **逐行**独立评估，任一行拒 ⇒ 整体拒 |
| sftp_op / sftp_upload / tunnel | **一律拒绝**（写通道/转发通道无命令语义可闸；用户真需要就不要给该 server 上 mode） |
| list_servers / audit_query / self_update / *_setup | 不涉 per-server 策略（本地或创建新 server），不变 |

### 3.4 施策点

- 单 server 工具：`internal/mcpserver/dispatch.go` middleware 已有 `extractServerName` + `rawArgs`，在 audit pre-record 之前插入 `safety.EvaluatePolicy(server, tool, command)`（引擎放 `internal/safety/policy.go`；mcpserver、tools 的 check-deps 白名单均已含 safety，**无新 import 边**）。
- `ssh_group_exec` / `session_send`：middleware 拿不到目标 server（前者是数组/tag，后者只有 session_id），在 handler 内调用同一引擎函数。
- quick_setup 临时 server（qs-*）：不暴露 mode 参数（AI 给自己选 unrestricted 无意义），恒为 unrestricted，维持现状。

### 3.5 审计

- 新增 `error_code = "POLICY_DENIED"`（`internal/envelope/codes.go`），拒绝时写一条 `status="denied"` 审计记录，`error` 字段带命中原因（哪条 deny / 无 allow 命中）。复用现有 Entry 结构，**不加新字段**。
- 放行的调用走现有 pending/completed 记录，不重复记。

## 4. 实施拆分（各自独立可回滚）

1. **引擎 + 配置**：`internal/safety/policy.go`（纯函数：mode + patterns + command → verdict）+ config 字段与校验 + 表驱动单测（含元字符绕过 battery：`$()`、反引号、`;`、重定向、换行、别名前缀等注入载荷全拒）。
2. **接线**：dispatch middleware + group_exec/session_send handler 内评估 + POLICY_DENIED 审计 + 集成测试。
3. **文档**：README/SECURITY.md 增补 mode 说明与局限性声明。

测试先行：步骤 1 的 verdict 表和步骤 2 的「readonly server 上 ssh_exec rm 被拒且留审计」先写红灯测试。

## 5. 已拍板决策点（2026-07-13）

- **D1 readonly 语义**：采用 §3.2「内置保守 allowlist + 元字符拒绝」。否决备选「内置 denylist（拦 rm/mv/...，其余放行）」——可用性更高但清单数不全、可绕过面大。
- **D2 sftp_op/sftp_upload/tunnel 在有 mode 的 server 上一律拒绝**（§3.3）。否决「readonly 拒、restricted 放行」——命令锁死而文件随便写等于策略形同虚设。
