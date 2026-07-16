---
name: monitor-setup
description: 交互式定义监控与通知。用户说"监控 X""日志 Y 告警飞书"时使用，引导选采集器、填参数、配通知、试采集试通知、落配置。
metadata:
  category: monitor
  risk: write
  tags: [monitor, alert, setup]
---

# 交互式监控设置

## 流程

1. **理解意图**：明确监控对象（OS 指标/文件/数据库/命令）与告警条件。
2. **选采集器**：调 `monitor_list_collectors` 列出可用类型，按 `fields` 与 params 选合适的 collector。
3. **收集参数**：按 collector 的 params schema 逐项向用户提问，给默认值，校验必填。
4. **定条件**：确定 `when`（field/op/value）、`for`（持续时长）、`severity`、`interval`、`cooldown`。
5. **配通知**：调 `monitor_list_notifiers`；若无合适渠道，引导用户配置（飞书/钉钉/邮件/webhook），
   调 `notifier_add { test: true }` 发测试消息让用户确认收到。
6. **试采集**：调 `monitor_add { test: true }` 试采集一次，向用户展示当前值与是否命中。
7. **落配置**：确认后保存。提示守护进程需 `SIGHUP` 或重启（`opagent monitor`）加载。

## 注意

- 修改配置需 `--allow-write`；未开启时告知用户。
- secret 字段（webhook 密钥/token）建议用 `${ENV_VAR}` 引用，避免明文落盘。
- 命令/SQL 类采集会被 PolicyGuard 校验，破坏性/写操作拒绝。
- 鼓励用户先 `dry-run`（test）再正式启用。
