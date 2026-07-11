# 设计方案：MCP 原生大文件上传工具 `sftp_upload`

状态：**提案，待用户拍板**（2026-07-11）
背景记忆：Yuki 912bfd7a（CLI upload 不识别 quick_setup 临时 server，被检索 49 次的高频痛点）

---

## 1. 问题与核心可行性论证

### 现状的两条路都有结构性缺陷

| 路径 | 机制 | 缺陷 |
|---|---|---|
| MCP `sftp_op` (action=write) | 内容 base64 编码后作为 JSON 参数传入 | 字节**穿过 AI 上下文**（+33% base64 膨胀、烧 token）；16 MiB 硬上限（`sftp_op.go:18`）；超大参数疑似被 MCP 客户端截断（2026-07-11 取证：损坏报告未复现，客户端截断是最可能解释） |
| CLI `ssh-mcp upload` | 流式 `io.Copy`，无大小限制（`cli_transfer.go:187-268`） | **独立进程**，只读 config.toml，永远看不到运行中 MCP 进程内存里的 quick_setup 临时 server —— 这是架构性的，无法通过"CLI 增强"低成本修复 |

### 「MCP 工具真的能传大文件吗？」——能，且这是唯一正确的架构

关键认知：**MCP 工具调用的 JSON 里只需要传元数据（路径），不需要传字节**。
ssh-mcp 进程就运行在文件所在的本机，新工具入参为
`(server, local_path, remote_path)`，由 MCP 进程自己 `os.Open` 读盘、流式写入
SFTP —— 字节全程不进 AI 上下文，与 CLI upload 的数据通道完全一致，因此**没有
大小上限**。这与用户已在用的 2term 堡垒机 MCP 的设计原则相同：「AI 只编排，
绝不搬字节」。

同时因为工具运行在 MCP 进程内，`deps.Pool.Get(name)` 天然优先解析
quick_setup 临时 server（`pool.go:277-279`），**49 次检索的高频痛点直接消失**，
不需要任何 IPC。

---

## 2. 方案对比

### 方案 A（推荐）：独立新工具 `sftp_upload`

新增 `internal/tools/sftp_upload.go`，入参：

```jsonc
{
  "server": "qs-abc123",          // 静态或 quick_setup 临时 server，透明
  "local_path": "/abs/path/file", // 本机绝对路径
  "remote_path": "/opt/app/file", // 远端目标（受 server 的 allowed_paths 约束）
  "mode": "0644",                 // 可选，默认 0644
  "atomic": true                  // 可选，默认 true（临时文件 + rename）
}
```

返回：`{bytes_written, sha256, remote_path}`（sha256 为本地内容流式计算值，
AI 可在需要时用 `ssh_exec sha256sum` 远端复验）。

**为什么独立工具而不是给 sftp_op 加 action=upload（方案 B）**：
「读取本机磁盘任意文件」是一个**全新的能力等级**。Claude Code 等客户端的
`permissions.allow` 以工具为粒度——用户机器上 `mcp__ssh-bridge__sftp_op`
已在白名单里，如果把 upload 塞进 sftp_op 的 action，等于**静默给已放行的
工具追加本地磁盘读取能力**，绕过了用户的一次显式授权决策。独立工具名强制
用户重新 allow 一次，权限边界干净。这条理由优先于「少一个工具名」的简洁性。

### 方案 B：sftp_op 加 action=upload

复用现有 schema/audit 接线，改动最小；但有上述权限静默扩权问题。**不推荐**。

### 方案 C：让 CLI 识别 quick_setup 会话

需要 MCP 进程把临时 server（含内存中的密码/凭据）通过某种 IPC 导出给 CLI
进程——凭据出进程是安全降级，且引入 socket/文件握手复杂度。**拒绝**。

### 方案 D：sftp_op 分块 append

字节仍穿 AI 上下文，只是分摊到多次调用，token 成本不降反升。**拒绝**。

---

## 3. 安全设计（本方案的核心难点）

威胁模型：被注入/失控的 AI 把本机敏感文件（`~/.ssh/id_rsa`、浏览器 cookie、
keychain 导出）上传到它可寻址的远端服务器 = **本机数据渗出通道**。这是
ssh-mcp 现有工具面没有的新风险（sftp_op 只能写 AI 上下文里已有的内容）。

分层缓解，全部 fail-closed：

1. **本地路径白名单（新 settings 字段，默认禁用）**
   `settings.upload_local_allowed_paths = []`（绝对路径前缀数组，复用
   `allowed_paths` 的 Rule 11 校验：绝对、无 `..`、clean）。
   **默认空 = 工具注册但调用即返回 `UPLOAD_DISABLED`**，错误 hint 指引用户
   手动编辑 config.toml 开启。AI 无法通过 MCP 面自行开启（persistent_setup
   只写 `[servers.*]` 块）。文档明确建议：白名单给具体工作目录，不要给 `$HOME`。
2. **本地 realpath 硬化**：prefix 检查前先 `filepath.EvalSymlinks`，防止
   白名单目录内放符号链接指向 `~/.ssh` 的绕过（与远端
   `resolveAndCheckRemotePath` 的 realpath 处理对称）；且要求是 regular file。
3. **远端路径复用现有约束**：`resolveAndCheckRemotePath`（远端 realpath +
   server 的 `allowed_paths`），与 sftp_op write 完全同一条检查路径。
4. **审计**：加入 `destructiveTools` 集合（`dispatch.go:27-42`）→ 自动获得
   fail-closed pre-record + post-record；audit 条目含 local_path、size、
   sha256（`io.TeeReader` 挂 hasher，流式计算零额外成本）。
5. **完整性**：atomic 写完成后 `Stat` 远端 size 比对本地 size（廉价，抓截断）；
   sha256 返回给 AI 供按需远端复验。不默认做远端读回全量哈希（大文件双倍流量，
   YAGNI）。
6. **不做的**：per-upload Elicit 确认——取证确认 Elicit 注入在 dispatch.go
   只有注释、基础设施未落地（`dispatch.go:102`），白名单 + 审计已覆盖威胁；
   将来 Elicit 落地后可作为白名单之外的第二道可选闸门。上传字节数上限——
   流式实现内存恒定，体积上限对渗出威胁无实质缓解，不加。

---

## 4. 实施拆解（预估 ~400 行含测试，单 PR 可审）

1. `internal/sftp/ops.go`：新增 `WriteFrom(p, r io.Reader, size int64, mode, atomic, progressCb) error`——把 `writeAtomic`/`writeDirect` 的字节循环从 `[]byte` 切片改成 `io.CopyBuffer`；现有 `Write([]byte)` 改为 `WriteFrom(bytes.NewReader(...))` 的薄壳（顺带简化）
2. `internal/config`：`UploadLocalAllowedPaths` 三点联动（contract.go struct / rawSettings 指针 / Load 默认值）+ Rule 11 风格校验
3. `internal/tools/sftp_upload.go`：工具注册（registry 样板）+ handler（本地校验 → 打开 → TeeReader 哈希 → WriteFrom + Progress 阈值复用 `SftpProgressThresholdBytes` → size 比对 → envelope 响应）
4. `internal/mcpserver/dispatch.go`：`destructiveTools` 加 `sftp_upload`
5. 文档：docs/AI_GUIDE.md、SECURITY.md、README 配置参考
6. **测试先行**（红→绿）：默认禁用返回 UPLOAD_DISABLED；白名单外拒绝；symlink 逃逸拒绝；非 regular file 拒绝；100 KiB 字节精确 + sha256 正确；远端 size 不匹配报错；config 校验用例

**不在本期**：对称的 `sftp_download` 工具（下载大文件到本机）——需要时同骨架照搬，本期不做以控制审查面。
