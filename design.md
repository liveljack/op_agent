# OpAgent 设计方案

轻量化 Linux 运维 Agent —— 基于 `@earendil-works/pi-coding-agent` 构建。

## 一、目标与约束

- **轻量**：单 Bun 进程 + 内嵌 SQLite，无 Redis/Mongo/Milvus；目标常驻内存 < 100MB，可在 1c1g 服务器运行；`bun build --compile` 产出单文件二进制。
- **安全第一**：所有写/删操作默认阻断，强制确认 + 审计；绝不出现无授权的文件删除或数据库记录删除。
- **交互**：复用 pi 的 `InteractiveMode`（hermes/pi 风格 CLI 对话框），流式输出 + markdown + slash 命令。
- **能力**：检查、监控、执行、报警、编写脚本、漏洞扫描与自动处理。
- **模型**：默认 DeepSeek（pi 原生支持），可切 OpenAI / Anthropic 兼容。
- **范围**：第一版单机；后续主从集群（基于 pi RPC）。

## 二、核心定位

pi 已提供完整 coding agent harness（agent loop、工具、会话、skill 系统、扩展、provider、TUI/RPC）。**OpAgent 不重造内核，而是 pi 之上的一层运维扩展包**，只负责 pi 不提供但运维必需的部分：

1. 安全策略层（扩展）
2. 审计链（扩展 + SQLite）
3. 运维专用工具（`defineTool`）
4. 运维技能库（`SKILL.md`，Agent Skills 标准）
5. 运维系统提示词
6. 监控守护进程（headless 调度）
7. 集群 RPC 编排（v2）

### pi 提供开箱即用

- 对话框交互：`InteractiveMode`，流式 / markdown / `/skill:name` / `/model` / `/resume` / 会话树 fork
- 编程与执行：`bash` 工具（带 `spawnHook` 拦截/改写命令、cwd、env）、`edit`/`write`（带 diff）
- DeepSeek 默认：原生 provider，`DEEPSEEK_API_KEY` 即可用
- skill 系统：Agent Skills 标准，`SKILL.md` + frontmatter，progressive disclosure
- 会话持久化与分支：`SessionManager`（jsonl 树、fork、compaction）
- 扩展机制：`tool_call`（阻断/改写）、`tool_result`（改结果）、`before_agent_start`（注入系统提示）、`bash spawnHook`、`user_bash`、`project_trust`
- RPC 模式：`runRpcMode` / `pi --mode rpc` —— 集群通信通道

## 三、整体架构

```
┌──────────────────────────────────────────────────────────┐
│  opagent CLI (= pi InteractiveMode + OpAgent 扩展包)      │
│  hermes/pi 风格对话框 · 流式 · markdown · 确认门           │
└───────────────────────────┬──────────────────────────────┘
                            │  createAgentSession({ extensions, customTools, skills })
┌───────────────────────────▼──────────────────────────────┐
│  pi AgentSession (loop / tools / sessions / provider)     │
│  provider: DeepSeek (默认) / OpenAI / Anthropic           │
│  tools: read bash edit write grep find ls + ops 自定义     │
└──────┬────────────┬───────────────┬────────────────┬─────┘
       │            │               │                │
┌──────▼───┐  ┌─────▼─────┐  ┌──────▼──────┐  ┌──────▼──────┐
│ opagent-  │  │ opagent-  │  │ ops 工具     │  │ ops 技能     │
│ safety    │  │ audit     │  │ inspect/     │  │ SKILL.md     │
│ (扩展)    │  │ (扩展)    │  │ monitor/     │  │ (Agent Skills)│
│           │  │           │  │ security     │  │              │
│ tool_call │  │ tool_call │  │ (defineTool) │  │ progressive  │
│ spawnHook │  │ tool_result│ │              │  │ disclosure   │
│ 路径/黑名单│  │ 哈希链     │  │              │  │              │
└──────┬───┘  └─────┬─────┘  └──────┬──────┘  └──────┬──────┘
       └────────────┴───────┬───────┴────────────────┘
                            │
              ┌─────────────▼─────────────┐
              │  bun:sqlite (audit / FTS)  │
              └───────────────────────────┘
```

## 四、安全策略层（核心）

pi 明确无内置沙箱（`docs/security.md`），安全边界交由扩展/OS。OpAgent 用 `opagent-safety` 扩展把运维红线钉死在 pi 内核层（拦截发生在工具执行前，无法被模型绕过）。

| 安全需求 | pi 钩子 | OpAgent 实现 |
|---|---|---|
| 拦截危险命令（`rm -rf`/`mkfs`/`dd of=/dev/`/fork 炸弹等） | `tool_call`（`bash`） | tokenize + 黑名单正则，命中 `{block:true, reason}` |
| 拦截危险 SQL（`DROP`/`TRUNCATE`/无 `WHERE` 的 `DELETE`/`ALTER DROP`） | `tool_call`（`bash`） | 检测命令中的 SQL 子串 |
| 路径白名单 + 禁区（`/boot` `/etc/shadow` `/proc` `/sys` `~/.ssh`） | `tool_call`（`write`/`edit`/`bash`） | 解析目标路径，越界即 block |
| 写操作强制确认 + dry-run 预览 | `tool_call` + `ctx.ui.confirm` | `write`/`edit`/写类 bash 先展示 diff/影响，y/N |
| 命令改写（注入 `set -o pipefail`、`timeout`、`ulimit`） | `bash spawnHook` | 统一包装，防资源耗尽 |
| 破坏性操作默认不存在 | 工具注册 | 删除类工具默认不注册；`--allow-destructive` 时注册 `controlled_delete`，仍走二次确认 + 审计 |
| 注入安全系统提示 | `before_agent_start` | 追加运维安全红线 |
| 用户 `!` 命令受控 | `user_bash` | 同样过 PolicyGuard |
| 可选 OS 级隔离 | 容器/bwrap | 整个 opagent 进程于容器运行（pi 官方推荐） |

### 严格策略落点

- 默认工具集：`read, grep, find, ls, bash`；`bash` 受 safety 扩展约束。**`edit`/`write` 默认关闭**，需 `--allow-write` 开启且仍逐次确认。
- `controlled_delete` / `db_mutate` 等破坏性工具：**默认完全不注册**，`--allow-destructive` 才注册，且每次需 `ctx.ui.confirm` + 输入动作名 + 写明理由。
- `PolicyGuard` 为纯函数模块，便于单测。

### LLM 语义审计（第二层，`--llm_audit`）

模式层快但只能匹配已知模式；LLM 层慢但能理解语义，抓变量间接构造（`a=rm;$a`）、编码混淆（`base64|sh`）、数据外泄（`nc`/`curl` 上传敏感文件）、提权（`sudo`）等绕过。

- 触发条件：仅写/破坏性命令与脚本（`run_script`）触发；只读跳过（省延迟/成本）。
- 与模式层关系：模式层先判 → LLM 层后审 → `mergeDecisions` 取严合并（LLM 只能升级，不能降级模式层判定）。
- 安全等级绑定：LLM 审计 prompt 注入当前 `allowWrite`/`allowDestructive` 等级，强制 `allowDestructive=false` 时破坏性操作判 block。
- fail-safe：审计请求异常/解析失败 → 升级为需人工确认（不静默放行）。
- 审计留痕：每次 LLM 审计单独写入审计链（`tool=llm_audit`）。
- 配置：默认走 DeepSeek OpenAI 兼容端点；`OPAGENT_AUDIT_BASE_URL` / `OPAGENT_AUDIT_MODEL` / `OPAGENT_AUDIT_API_KEY` 可独立配置（推荐用更便宜模型审计）。

### 脚本安全（`run_script` 工具）

生成脚本走专用工具，流程：`bash -n`/`py_compile` 语法检查 → `dry_run` 预览 → 模式层校验 → LLM 审计 → 确认 → 执行（临时文件 0600 + 超时）。系统提示词要求模型生成脚本必须优先用 `run_script` 且先 `dry_run`。

### 工具风险分级

- `read`：只读，自动执行（`inspect_*`/`read_logs`/`security_scan` dry-run）
- `write`：需交互确认 y/N（`write_file`/`restart_service`/`run_script`/`install_pkg`）
- `destructive`：默认硬阻断，需 `--allow-destructive` + 二次输入动作名 + 理由（`controlled_delete`/`db_mutate`）

## 五、审计链（`opagent-audit` 扩展）

- 监听 `tool_call`（记录意图）+ `tool_execution_end`/`tool_result`（记录结果）
- 写入 `bun:sqlite` append-only `audit` 表：`ts | tool | input | result | risk | blocked | approver | reason | prev_hash | hash`
- 哈希链（`prev_hash = sha256(prev_row)`）保证不可篡改
- slash 命令 `/audit` 查询；可导出/告警

## 六、运维专用工具（`defineTool`）

| 工具 | 风险 | 说明 |
|---|---|---|
| `inspect_disk`/`inspect_mem`/`inspect_cpu`/`inspect_net`/`inspect_service`/`inspect_proc` | read | 只读，自动执行，结构化返回 |
| `read_logs` | read | 带过滤、tail、时间窗口 |
| `security_scan` | read | 调 lynis/clamav/trivy（若存在），dry-run 报告 |
| `check_thresholds` | read | 监控阈值检查 |
| `run_script` | write | 受控执行生成脚本，先 lint + dry-run + 确认 |
| `restart_service` | write | 确认后执行 |
| `controlled_delete` | destructive | 默认不注册，`--allow-destructive` |
| `db_query` | read | 只读 SQL |
| `db_mutate` | destructive | 默认不注册；强制 `WHERE` + 影响行数预估 + 确认 |

工具内部统一调用 `PolicyGuard.check()`。

## 七、运维技能库（pi Agent Skills 标准）

采用 pi 的 `SKILL.md` 格式（frontmatter + markdown 正文），progressive disclosure：描述常驻系统提示，正文按需 `read`。

```
skills/
├── inspect-disk-usage/SKILL.md
├── analyze-logs/SKILL.md
├── check-service-health/SKILL.md
├── vuln-scan/SKILL.md
├── safe-cleanup-tmp/SKILL.md
├── restart-webservice/SKILL.md
└── incident-triage/SKILL.md
```

frontmatter 在 pi 标准（`name`/`description`）之上用 `metadata` 扩展 `category`/`risk`/`tags`：

```markdown
---
name: inspect-disk-usage
description: 检查磁盘使用率并定位大目录。用于磁盘告警排查。
metadata:
  category: inspect
  risk: read
  tags: [disk, fs]
---
```

检索增强（可选）：技能多时加 `opagent skill search` 命令，SQLite FTS5 索引 `skills/**/SKILL.md`。

## 八、运维系统提示词

通过 `DefaultResourceLoader.systemPromptOverride` 或 `.pi/SYSTEM.md` 注入：

> 你是 Linux 服务器运维助手。只读优先；任何写/删操作必须先 dry-run 并经用户确认。绝不主动删除文件、绝不删除或修改数据库记录，除非用户显式要求且通过 `controlled_delete`/`db_mutate` 工具并输入理由。遇到不确定优先报告而非行动。

## 九、监控守护进程

- `opagent monitor`：独立轻量进程，定时（cron 式）跑只读检查技能
- 实现：headless 调 `createAgentSession` + `runPrintMode`，加载同一 safety 扩展 + ops 工具 + inspect 技能
- 阈值 breach → 告警（webhook/Telegram/邮件）
- 低内存：无 TUI，单次 prompt 即退，可由 systemd timer 触发

## 十、集群演进（v2，基于 pi RPC）

pi 自带 `runRpcMode` + `RpcClient` JSON-RPC，集群通信不自研：

```
主 agent (opagent)  ──RpcClient──►  子 agent (pi --mode rpc + OpAgent 扩展) @ server B
                  ──RpcClient──►  子 agent @ server C
```

- 主 agent：接收任务，`RpcClient` 派发到子 agent，聚合结果
- 子 agent：`pi --mode rpc` 进程，加载同一 `opagent-safety` 扩展 —— 安全策略在子节点本地强制执行，主节点无法绕过
- 通信：SSH 隧道 / mTLS 上 JSON-RPC；鉴权共享 token + 信任证书
- v1 的工具/技能/安全扩展在子节点原样复用

## 十一、项目结构

```
op_agent/
├── package.json                 # 依赖 @earendil-works/pi-coding-agent
├── design.md
├── src/
│   ├── index.ts                 # opagent CLI 入口（组装 pi + 扩展包）
│   ├── config.ts                # DeepSeek 默认 + 环境配置
│   ├── prompt.ts                # 运维系统提示词
│   ├── safety/
│   │   ├── policy.ts            # PolicyGuard 纯函数
│   │   ├── patterns.ts          # 危险模式规则表
│   │   └── extension.ts         # opagent-safety 扩展
│   ├── audit/
│   │   ├── extension.ts         # opagent-audit 扩展
│   │   ├── store.ts             # sqlite 哈希链
│   │   └── db.ts
│   ├── tools/                   # defineTool 运维工具
│   │   ├── inspect.ts
│   │   ├── monitor.ts
│   │   ├── security.ts
│   │   ├── script.ts
│   │   └── destructive.ts       # controlled_delete / db_mutate（默认不注册）
│   ├── skills/                  # 技能 FTS 索引 + 管理命令
│   │   └── index.ts
│   ├── monitor/daemon.ts        # headless 监控守护
│   └── cluster/                 # v2: RpcClient 主从编排
├── skills/                      # 内置 SKILL.md 技能库
└── test/                        # bun test（PolicyGuard 单测为重点）
```

## 十二、落地路线图

| 阶段 | 内容 | 产出 |
|---|---|---|
| P0 | 脚手架 + 依赖 pi + DeepSeek 默认 + `createAgentSession` 跑通 + ops 系统提示 | 能对话 |
| P1 | `opagent-safety` 扩展（tool_call 守卫 + spawnHook + 路径/黑名单 + 确认门）+ PolicyGuard 单测 | 安全执行只读命令 |
| P2 | `opagent-audit` 哈希链 + ops inspect 工具 + 首批技能 + FTS 检索 | 可用运维 agent |
| P3 | script 生成执行 + security 扫描 + monitor 守护 + alert | 功能完整 v1 |
| P4 | `--allow-write`/`--allow-destructive` 受控通道 + 容器化 + `bun build --compile` | 可发布 |
| P5 | cluster：RpcClient 主从 + 子节点本地安全兜底 | 集群版 |

**MVP = P0–P1**：验证"pi + safety 扩展"能安全执行运维命令这条主链路。
