/**
 * 监控/通知插件接口与核心类型
 *
 * Collector / Notifier 是两套正交的可插拔扩展：
 * - Collector 产出 Sample（不知道阈值）
 * - Notifier 消费 Alert（不知道数据源）
 * Rule 配置把它们绑在一起。
 *
 * 每个插件声明 paramsSchema（typebox），agent 读取它驱动交互式设置。
 */

import { Type, type TSchema, type TObject } from "typebox";

/** 标记 schema 字段为敏感（存储/审计/日志脱敏） */
export const SECRET = Symbol.for("opagent.secret");
export function Secret<T extends TSchema>(schema: T): T {
  (schema as any)[SECRET] = true;
  return schema;
}
export function isSecret(schema: any): boolean {
  return Boolean(schema?.[SECRET]) || schema?.secret === true || schema?.["x-secret"] === true;
}
export function SecretString(opts?: Record<string, unknown>) {
  return Secret(Type.String(opts as any));
}

export interface Sample {
  ts: number;
  fields: Record<string, number | string>;
  labels?: Record<string, string>;
}

export interface Alert {
  id: string;
  monitorId: string;
  severity: "warn" | "critical";
  message: string;
  sample: Sample;
  host: string;
  ts: number;
  status: "firing" | "resolved";
}

export interface CollectCtx {
  host: string;
  /** 取该 monitor 最近 windowMs 内的 samples（供 window/rate 计算） */
  history: (monitorId: string, windowMs: number) => Sample[];
  /** 命令/SQL 类采集必经的安全守卫 */
  guard: any;
}

export interface Collector {
  type: string;
  paramsSchema: TObject;
  /** 产出字段名，供 rule 条件引用 */
  fields: string[];
  collect(params: Record<string, unknown>, ctx: CollectCtx): Promise<Sample>;
}

export interface Notifier {
  type: string;
  paramsSchema: TObject;
  notify(alert: Alert, params: Record<string, unknown>): Promise<void>;
  /** 发一条测试通知 */
  test(params: Record<string, unknown>): Promise<void>;
}

export type Severity = "warn" | "critical";

/** 声明式条件（无 eval） */
export type Condition =
  | {
      field: string;
      op: ">" | ">=" | "<" | "<=" | "==" | "!=";
      value: number | string;
    }
  | { all: Condition[] }
  | { any: Condition[] };

export interface Rule {
  id: string;
  collector: string;
  params: Record<string, unknown>;
  when: Condition;
  /** 持续多久才告警（毫秒），默认 0 */
  forMs?: number;
  severity: Severity;
  /** 采集间隔（毫秒） */
  intervalMs: number;
  notifiers: string[];
  /** 同 key 冷却（毫秒），默认 0 */
  cooldownMs?: number;
  labels?: Record<string, string>;
}

export interface NotifierConfig {
  id: string;
  type: string;
  params: Record<string, unknown>;
}

export interface MonitorConfig {
  notifiers: NotifierConfig[];
  monitors: Rule[];
}

export type PluginKind = "collector" | "notifier";
