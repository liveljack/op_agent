---
name: inspect-disk-usage
description: 检查磁盘使用率并定位大目录。用于磁盘空间告警排查、清理前评估。
metadata:
  category: inspect
  risk: read
  tags: [disk, fs]
---

# 检查磁盘使用率

## 步骤

1. 调用 `inspect_disk`（不带 detail）查看各挂载点使用率。
2. 对超过 80% 的挂载点，再次 `inspect_disk { detail: true }` 定位大目录。
3. 汇总：现状（哪些满）、风险、可清理项建议（不自动删除）。

## 注意

- 只读检查，不执行任何写/删操作。
- 清理建议需用户确认后，通过 `controlled_delete`（需 --allow-destructive）执行。
