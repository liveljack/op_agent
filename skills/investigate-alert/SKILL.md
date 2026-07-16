---
name: investigate-alert
description: 收到告警后排查根因。用只读 inspect 工具结合告警上下文定位问题，给出建议（不自动破坏性修复）。
metadata:
  category: monitor
  risk: read
  tags: [monitor, alert, investigate]
---

# 告警根因排查

## 流程

1. **取告警**：调 `monitor_status` 查看最近告警，或读用户提供的告警内容。
2. **理解上下文**：告警的 monitorId、severity、命中字段、host、sample。
3. **只读排查**：按告警类型用对应 inspect 工具：
   - 磁盘/内存/CPU 告警 → `inspect_disk`/`inspect_mem`/`inspect_cpu`
   - 服务/进程告警 → `inspect_service`/`inspect_proc`
   - 日志告警 → `read_logs` 取相关片段
   - 数据库告警 → `db_query` 只读查询
4. **归纳根因**：现状、可能原因、影响范围。
5. **给建议**：非破坏性恢复建议（重启服务需确认、清理需用户授权）。

## 注意

- 只读优先，不自动执行破坏性修复。
- 任何修复动作需用户确认（`--allow-write`/`--allow-destructive`）。
- 用中文结构化输出。
