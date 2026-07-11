---
name: analyze-logs
description: 分析 /var/log 日志定位错误与异常。用于故障排查、告警根因分析。
metadata:
  category: inspect
  risk: read
  tags: [log, debug]
---

# 分析日志

## 步骤

1. 确认目标日志文件（如 syslog、nginx/error.log）与时间窗口/关键字。
2. 调用 `read_logs { file, lines, grep }` 取相关片段。
3. 识别 ERROR/WARN/异常堆栈，归纳根因假设。
4. 汇总：异常清单、可能根因、下一步排查/修复建议。

## 注意

- 只读。不修改日志文件。
