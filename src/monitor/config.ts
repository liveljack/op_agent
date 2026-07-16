/**
 * 监控配置解析
 *
 * 读取 ~/.op_agent/monitors.yaml 与 notifiers.yaml，展开 ${VAR}（env 三级优先级），
 * secret 字段脱敏工具，时间字符串（"60s"/"5m"/"2h"）→ 毫秒。
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import type { MonitorConfig, NotifierConfig, Rule } from "./types.ts";
import { isSecret } from "./types.ts";

/** "60s"/"5m"/"2h"/"1d" → 毫秒；纯数字视为毫秒 */
export function parseDuration(s: string | number | undefined): number {
  if (s === undefined || s === null) return 0;
  if (typeof s === "number") return s;
  const m = String(s).trim().match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$/);
  if (!m || !m[1]) return 0;
  const n = parseFloat(m[1]);
  const unit = m[2] ?? "ms";
  const mult = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[unit] ?? 1;
  return Math.round(n * mult);
}

/** 展开 ${VAR}；未定义的变量保留原样（不替换为空，便于发现配置错误） */
export function expandVars(str: string): string {
  if (typeof str !== "string") return str;
  return str.replace(/\$\{([A-Z0-9_]+)\}/g, (m, name) =>
    process.env[name] !== undefined ? (process.env[name] as string) : m,
  );
}

function expandDeep(v: unknown): unknown {
  if (typeof v === "string") return expandVars(v);
  if (Array.isArray(v)) return v.map(expandDeep);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) o[k] = expandDeep(val);
    return o;
  }
  return v;
}

/** 按 paramsSchema 把 secret 字段的值替换为 "***"（用于审计/日志/TUI 显示） */
export function redactParams(
  schema: { properties?: Record<string, any> } | undefined,
  params: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...params };
  if (!schema?.properties) return out;
  for (const [k, sch] of Object.entries(schema.properties)) {
    if (isSecret(sch) && k in out) out[k] = "***";
  }
  return out;
}

function readYaml(path: string): any {
  if (!existsSync(path)) return null;
  return parse(readFileSync(path, "utf-8"));
}

/** 加载并校验配置；缺文件返回空配置 */
export function loadMonitorConfig(agentDir: string): MonitorConfig {
  const notifiersRaw = readYaml(join(agentDir, "notifiers.yaml")) ?? { notifiers: [] };
  const monitorsRaw = readYaml(join(agentDir, "monitors.yaml")) ?? { monitors: [] };

  const notifiers: NotifierConfig[] = (notifiersRaw.notifiers ?? []).map((n: any) => ({
    id: String(n.id),
    type: String(n.type),
    params: expandDeep(n.params ?? {}) as Record<string, unknown>,
  }));

  const monitors: Rule[] = (monitorsRaw.monitors ?? []).map((m: any) => ({
    id: String(m.id),
    collector: String(m.collector),
    params: expandDeep(m.params ?? {}) as Record<string, unknown>,
    when: m.when,
    forMs: parseDuration(m.for),
    severity: m.severity === "critical" ? "critical" : "warn",
    intervalMs: parseDuration(m.interval) || 60_000,
    notifiers: Array.isArray(m.notifiers) ? m.notifiers.map(String) : [],
    cooldownMs: parseDuration(m.cooldown),
    labels: m.labels,
  }));

  return { notifiers, monitors };
}
