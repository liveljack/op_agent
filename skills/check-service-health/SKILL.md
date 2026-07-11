---
name: check-service-health
description: 检查 systemd 服务健康状态（active/failed/资源占用）。用于服务异常排查。
metadata:
  category: inspect
  risk: read
  tags: [service, systemd]
---

# 检查服务健康

## 步骤

1. 询问或从上下文确认目标服务名（如 nginx、redis）。
2. 调用 `inspect_service { service }` 查看状态。
3. 结合 `inspect_proc` 看资源占用，`read_logs` 看最近日志。
4. 汇总：服务状态、失败原因（若有）、恢复建议。

## 注意

- 只读。重启服务需用户确认（--allow-write 下通过 `run_script` 或 bash）。
