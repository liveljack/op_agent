# OpAgent

基于 [pi coding agent SDK](https://pi.dev) 构建的轻量化 Linux 运维 Agent。复用 pi 的 agent loop、工具、会话、技能、TUI 与 provider，在此之上增加安全优先的运维层：三层安全策略、防篡改审计链、运维工具/技能，以及可插拔的监控与报警系统。

- **轻量化**：单 Bun 进程 + 内嵌 SQLite，无 Redis/Mongo/Milvus，可在 1c1g 服务器运行。
- **安全第一**：破坏性操作默认阻断；写操作需确认；全程审计。
- **交互式**：pi 风格 TUI 对话框；监控可对话式定义，无需手写 YAML。
- **可插拔**：自定义 collector/notifier 为 TypeScript 文件，热加载。

> 详细设计文档：[design.md](design.md) · [monitor_design.md](monitor_design.md) · [coding_desc.md](coding_desc.md)

---

## 项目说明

OpAgent 专为**轻量化 Linux 运维**设计：单 Bun 进程 + 内嵌 SQLite，可在 1c1g 服务器轻松运行，辅助日常运维——检查、监控、执行、报警、脚本生成、安全审查。核心约束是**安全**：agent 绝不主动删除文件或数据库记录，且每个动作都可审计。

### 安全优先设计

所有模型提议的动作在执行前都要经过**三层防御**。拦截发生在 pi 的 `tool_call` 钩子（执行前），模型无法绕过。

| 层级                          | 作用                                                                                                                                                                                                                                   | 代码                                                                                            |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| 1. 模式层（`PolicyGuard`）    | 快速确定地阻断破坏性命令（`rm -rf`、`mkfs`、`find -delete`、`\| sh`、`eval`、`base64\|sh`、解释器删除）、危险 SQL（`DROP`/`TRUNCATE`/无 `WHERE` 的 `DELETE`）、硬保护路径（`/etc/shadow`、`~/.ssh`、`/proc`、`/sys`、`/dev`、`/boot`） | [src/safety/policy.ts](src/safety/policy.ts) · [src/safety/patterns.ts](src/safety/patterns.ts) |
| 2. LLM 语义层（`LlmAuditor`） | 审计写/脚本的变量间接、混淆、外泄、提权。取严合并——LLM 只能升级，不能降级。fail-safe：异常时升级为人工确认。                                                                                                                           | [src/audit/llm.ts](src/audit/llm.ts)                                                            |
| 3. 确认门 + 审计              | 写/破坏性操作需交互 `y/N`；无 UI（print 模式）则 fail-closed 阻断。每条决策与结果入哈希链审计日志。                                                                                                                                    | [src/safety/extension.ts](src/safety/extension.ts) · [src/audit/store.ts](src/audit/store.ts)   |

### 安全演示

| 默认阻塞 (Blocked) | 开启 `--allow-write` (需确认) |
| :---: | :---: |
| ![默认阻塞](docs/images/blocked_write.png) | ![写确认](docs/images/allowed_write_confirm.png) |

**保证：**

- 删除类工具（`controlled_delete`、`db_mutate`）**默认不注册**——仅 `--allow-destructive` 时注册，且仍需确认 + 理由（[src/tools/destructive.ts](src/tools/destructive.ts)）。
- `write`/`edit` 工具默认关闭——需 `--allow-write` + 逐次确认。
- 运行命令/SQL 的 collector 也过 `PolicyGuard`（防御纵深）——[src/monitor/builtin/collectors/file_sql_cmd.ts](src/monitor/builtin/collectors/file_sql_cmd.ts)。
- 生成脚本走 `run_script`：`bash -n` 语法检查 → `dry_run` 预览 → 模式+LLM 审计 → 确认 → 执行（[src/tools/script.ts](src/tools/script.ts)）。

### 审计链

每次工具调用决策、LLM 审计结论、执行结果都追加到**哈希链** SQLite 表（`hash = sha256(prev_hash || 字段)`）。任何事后篡改都会断链，可检出。

- 写入/校验/查询：[src/audit/store.ts](src/audit/store.ts)
- slash 命令：`/audit list [n]`、`/audit verify`（[src/audit/extension.ts](src/audit/extension.ts)）
- DB：`~/.op_agent/audit.db`

### 日常运维能力

| 运维需求                                      | 实现                                                                        | 代码                                                                                            |
| --------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **检查**（磁盘/内存/CPU/网络/服务/进程/日志） | 只读 `inspect_*` 工具，自动执行无需确认                                     | [src/tools/inspect.ts](src/tools/inspect.ts)                                                    |
| **监控**（OS 指标/日志/数据库/命令）          | 定时守护进程 + 可插拔 collector                                             | [src/monitor/](src/monitor/)                                                                    |
| **报警**（飞书/钉钉/webhook/邮件…）           | 可插拔 notifier，自带加签                                                   | [src/monitor/builtin/notifiers/](src/monitor/builtin/notifiers/)                                |
| **执行**（命令/脚本）                         | `bash`（受控 + 注入 `pipefail`/`timeout`）与 `run_script`（lint + dry-run） | [src/safety/extension.ts](src/safety/extension.ts) · [src/tools/script.ts](src/tools/script.ts) |
| **脚本**（生成 bash/python）                  | `run_script` 语法检查 + dry-run 预览                                        | [src/tools/script.ts](src/tools/script.ts)                                                      |
| **安全审查**                                  | 只读检查 + `--llm_audit` 对写操作语义复核                                   | [src/safety/](src/safety/) · [src/audit/llm.ts](src/audit/llm.ts)                               |
| **恢复**                                      | 技能驱动的非破坏性 playbook；破坏性仅走确认的 `controlled_delete`           | [skills/](skills/) · [src/tools/destructive.ts](src/tools/destructive.ts)                       |

### 轻量化设计

- 单 Bun 进程 + 内嵌 `bun:sqlite`——无 Redis/Mongo/Milvus。
- 只读检查跳过 LLM 审计层（仅在写/脚本上付出延迟与成本）。
- 监控守护进程 headless 运行，例行检查不消耗 LLM。
- `bun build --compile` → 单文件二进制，便于目标机部署。

---

## 环境要求

- [Bun](https://bun.sh) 运行时（会自动加载 `.env`）
- DeepSeek API key（默认模型）或任意 pi 支持的 provider key

## 安装

### 方式一：从 npm 安装（推荐用户使用）

```bash
# 使用 npm 全局安装
npm install -g @xianzongwendao/op-agent

# 或使用 bun
bun add -g @xianzongwendao/op-agent

# 或不安装直接运行
npx @xianzongwendao/op-agent
```

### 方式二：从源码构建（开发者）

```bash
git clone https://github.com/liveljack/op_agent.git
cd op_agent
bun install
```

## 快速开始

```bash
# 1. 配置 API key（见下方"LLM 配置"）
mkdir -p ~/.op_agent
echo 'DEEPSEEK_API_KEY=sk-xxxxxxxx' > ~/.op_agent/.env
chmod 600 ~/.op_agent/.env

# 2. 自检（离线，不调用 LLM）
opagent --self-test

# 3. 启动交互式 TUI
opagent
```

---

## LLM 配置

### 配置来源优先级（高 → 低）

1. **CLI 参数** —— `--model`、`--allow-write`、`--llm_audit` …
2. **`process.env`** —— 真实环境变量 + Bun 自动加载的 `<cwd>/.env`
3. **`~/.op_agent/.env`** —— 全局配置文件；仅填充前两层未设置的键

`~/.op_agent/.env` 是存放密钥的推荐位置（全局、0600 权限、不进 git）：

```bash
DEEPSEEK_API_KEY=sk-xxxxxxxx
# 可选开关
# OPAGENT_ALLOW_WRITE=1
# OPAGENT_LLM_AUDIT=1
```

### API key

| 变量               | 用途                          |
| ------------------ | ----------------------------- |
| `DEEPSEEK_API_KEY` | DeepSeek API 密钥（默认模型） |
| `OPAGENT_API_KEY`  | 通用兜底密钥                  |

### URL

- **主模型**：pi 内置 DeepSeek provider 端点固定，**无需配置 URL**，只需 key。
- **自定义 / 兼容端点**（代理、自部署、OpenAI 兼容服务）：在 `~/.op_agent/models.json` 定义自定义 provider（pi 机制），再设 `OPAGENT_MODEL=<provider>/<model>`。示例 `models.json`：
  ```json
  {
    "my-openai": {
      "baseUrl": "https://your-endpoint/v1",
      "apiKey": "$YOUR_API_KEY",
      "api": "openai-completions",
      "models": [
        {
          "id": "gpt-4o",
          "name": "GPT-4o",
          "reasoning": false,
          "input": ["text"],
          "contextWindow": 128000,
          "maxTokens": 4096,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
  ```
  然后：`OPAGENT_MODEL=my-openai/gpt-4o opagent`
- **LLM 审计端点**（仅 `--llm_audit` 时）：`OPAGENT_AUDIT_BASE_URL`（默认 `https://api.deepseek.com`）、`OPAGENT_AUDIT_MODEL`（默认 `deepseek-chat`）、`OPAGENT_AUDIT_API_KEY`（默认同 `DEEPSEEK_API_KEY`）。

### 切换模型

```bash
# 单次覆盖
opagent --model deepseek/deepseek-v4-flash
opagent --model anthropic/claude-sonnet-4-5   # 需 ANTHROPIC_API_KEY
opagent --model openai/gpt-4o                 # 需 OPENAI_API_KEY

# 或写入 ~/.op_agent/.env 持久化
OPAGENT_MODEL=deepseek/deepseek-v4-pro
```

查看某 provider 可用模型：设置好 key 后运行 `pi --list-models`（或在 TUI 内用 `/model`）。

> **不要**把密钥放进 `.vscode/settings.json` —— 它是编辑器配置，不是应用配置，常被共享/提交。请用 `~/.op_agent/.env`。（VSCode 的 `terminal.integrated.env.osx` 终端注入可用，但不便携。）

---

## 用法

```bash
opagent                              # 交互式 TUI（默认）
opagent --allow-write                # 开启写操作（仍逐次确认）
opagent --allow-destructive          # 开启破坏性通道（仍需确认 + 理由）
opagent --llm_audit                  # 对写/脚本启用 LLM 语义审计
opagent -p "检查磁盘使用"             # headless 单次执行
opagent --self-test                  # 离线自检
opagent monitor                      # 启动监控守护进程
opagent monitor new-collector <name> # 生成自定义 collector 模板
opagent monitor new-notifier <name>  # 生成自定义 notifier 模板
```

### 参数与环境变量

| 参数                  | 环境变量                      | 默认                         | 说明                            |
| --------------------- | ----------------------------- | ---------------------------- | ------------------------------- |
| `--model`             | `OPAGENT_MODEL`               | `deepseek/deepseek-v4-flash` | 模型 `provider/model`           |
| `--allow-write`       | `OPAGENT_ALLOW_WRITE=1`       | 关                           | 开启写操作（需确认）            |
| `--allow-destructive` | `OPAGENT_ALLOW_DESTRUCTIVE=1` | 关                           | 开启破坏性操作（需确认 + 理由） |
| `--llm_audit`         | `OPAGENT_LLM_AUDIT=1`         | 关                           | LLM 语义审计                    |
| `--cwd`               | —                             | `process.cwd()`              | 工作目录                        |
| `-p, --print`         | —                             | —                            | headless 单次                   |
| —                     | `OPAGENT_DIR`                 | `~/.op_agent`                | 配置目录                        |
| —                     | `OPAGENT_WRITE_PATHS`         | `<cwd>/workspace`            | 写白名单（冒号分隔）            |
| —                     | `OPAGENT_AUDIT_DB`            | `~/.op_agent/audit.db`       | 审计 DB 路径                    |

---

## 安全模型（三层）

1. **模式层**（`PolicyGuard`）：快、确定。阻断 `rm -rf`、`mkfs`、`find -delete`、`| sh`、`eval`、`base64|sh`、解释器删除（`python os.remove`、`perl unlink`…）、危险 SQL（`DROP`/`TRUNCATE`/无 `WHERE` 的 `DELETE`），以及硬保护路径（`/etc/shadow`、`~/.ssh`、`/proc`、`/sys`、`/dev`、`/boot`）。
2. **LLM 层**（`LlmAuditor`，`--llm_audit`）：对写/脚本做语义审计——抓变量间接、混淆、外泄、提权。取严合并（LLM 只能升级，不能降级）。fail-safe：异常时升级为人工确认。
3. **确认门 + 审计**：写/破坏性操作需交互 `y/N`；每条决策与执行结果写入哈希链审计日志。

安全等级与参数绑定：`--allow-write` / `--allow-destructive` 决定 LLM 审计可放行的范围。`/audit list`、`/audit verify` slash 命令查询与校验审计链。

删除类工具（`controlled_delete`、`db_mutate`）**默认不注册**——仅 `--allow-destructive` 时注册，且仍需确认 + 理由。

---

## 监控与报警

两套可插拔扩展 + 守护进程 + 对话式设置。

### 内置 Collector

`system.cpu` · `system.mem` · `system.disk` · `system.net` · `file.tail` · `sql` · `command.read`
（prometheus/grafana/http/journald 规划中）

### 内置 Notifier

`log` · `webhook` · `feishu` · `dingtalk`（email/slack/telegram 规划中）

### 守护进程

```bash
opagent monitor          # 定时采集 → 条件评估 → 告警 → 通知
                         # SIGHUP 热加载配置与插件
```

配置文件（由 TUI 工具自动生成，也可手写）：

- `~/.op_agent/monitors.yaml`
- `~/.op_agent/notifiers.yaml`

示例：

```yaml
# notifiers.yaml
notifiers:
  - id: feishu-ops
    type: feishu
    params: { webhook_url: 'https://open.feishu.cn/...', secret: '${FEISHU_SECRET}' }

# monitors.yaml
monitors:
  - id: disk-root
    collector: system.disk
    params: { mount: '/' }
    when: { field: usage_percent, op: '>', value: 85 }
    for: 2m
    severity: warn
    interval: 60s
    notifiers: [feishu-ops]
    cooldown: 5m
```

### 对话式设置

在 TUI 里直接说要监控什么——agent 读取插件的 `paramsSchema`，提问参数、试采集一次、发测试通知、落配置：

> "监控磁盘，超 85% 飞书通知我"

agent 通过 `monitor_*` 工具操作（`monitor_list_collectors`、`notifier_add`、`monitor_add`、`monitor_test`…）。配置写入需 `--allow-write`。

### 自定义插件

```bash
opagent monitor new-collector my-monitor      # → ~/.op_agent/monitor/my-monitor.ts
opagent monitor new-notifier my-channel       # → ~/.op_agent/notification/my-channel.ts
```

编辑生成的模板，`kill -HUP <守护进程pid>`（或重启）加载。声明 `paramsSchema` 后对话式设置自动识别；敏感字段标 `{ secret: true }` 自动脱敏。

---

## 项目结构

```
src/
├── index.ts              # CLI 入口（TUI / print / monitor 子命令）
├── config.ts             # 环境配置（三级优先级 + ~/.op_agent/.env 加载）
├── prompt.ts             # 运维系统提示词
├── safety/               # PolicyGuard + safety 扩展 + 模式规则
├── audit/                # 哈希链审计 + LLM 审计器
├── tools/                # inspect / run_script / destructive 工具
├── skills/               # 内置技能加载
└── monitor/              # 监控守护进程 + collectors/notifiers/工具
skills/                   # 内置 SKILL.md
test/                     # bun 测试
design.md · monitor_design.md · coding_desc.md
```

## 开发

```bash
bun test          # 运行测试
bun run typecheck # tsc --noEmit
bun run dev       # 热重载开发
```

## License

[Apache License 2.0](LICENSE)
