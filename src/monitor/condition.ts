/**
 * 声明式条件评估（无 eval，杜绝注入）
 *
 * 支持 {field, op, value} 与 {all:[]}/{any:[]} 组合。
 * 字段缺失视为不匹配（保守：不触发告警）。
 */

import type { Condition } from "./types.ts";

export function evalCondition(cond: Condition, fields: Record<string, number | string>): boolean {
  if ("all" in cond) return cond.all.every((c) => evalCondition(c, fields));
  if ("any" in cond) return cond.any.some((c) => evalCondition(c, fields));

  const raw = fields[cond.field];
  if (raw === undefined) return false;
  const a = typeof raw === "number" ? raw : String(raw);
  const b = cond.value;
  switch (cond.op) {
    case ">":
      return a > (b as any);
    case ">=":
      return a >= (b as any);
    case "<":
      return a < (b as any);
    case "<=":
      return a <= (b as any);
    case "==":
      return a === (typeof b === "number" ? b : String(b));
    case "!=":
      return a !== (typeof b === "number" ? b : String(b));
    default:
      return false;
  }
}
