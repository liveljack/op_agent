/**
 * monitor_* 工具（defineTool）
 *
 * 供 agent 在 TUI 中交互式管理监控/通知：列类型、加 notifier、加 monitor、
 * 试采集/试通知、查状态、删、静默、生成自定义插件模板。
 *
 * 配置写入需 --allow-write（由 safety 扩展对 write 工具拦截；这些自定义工具
 * 自身也校验 allowWrite）。命令/SQL 采集过 PolicyGuard。
 */

import { Type } from "typebox";
import { defineTool } from "@earendil-works/pi-coding-agent";
import type { Registry } from "./registry.ts";
import { evalCondition } from "./condition.ts";
import { upsertNotifier, upsertMonitor, removeMonitor, readMonitors, readNotifiers } from "./configio.ts";
import { redactParams } from "./config.ts";
import { createStore } from "./store.ts";
import { generateCollectorScaffold, generateNotifierScaffold } from "./scaffold.ts";
import { homedir } from "node:os";
import { join } from "node:path";

export interface MonitorToolsDeps {
  registry: Registry;
  agentDir: string;
  dbPath: string;
  guard: any;
  allowWrite: boolean;
  host: string;
}

function text(s: string, isError = false) {
  return { content: [{ type: "text" as const, text: s }], details: {}, isError };
}
function schemaSummary(schema: any): any {
  if (!schema?.properties) return schema;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(schema.properties)) {
    const anyv = v as any;
    out[k] = `${anyv.type ?? "any"}${anyv.description ? ` — ${anyv.description}` : ""}`;
  }
  return out;
}

export function createMonitorTools(deps: MonitorToolsDeps) {
  const { registry, agentDir, guard } = deps;

  return [
    defineTool({
      name: "monitor_list_collectors",
      label: "列出采集器类型",
      description: "列出所有可用 collector 类型（内置 + 用户自定义）及其参数 schema 与产出字段，供定义监控时选择。",
      parameters: Type.Object({}),
      execute: async () => {
        const list = registry.listCollectors().map((c) => ({
          type: c.type,
          fields: c.fields,
          params: schemaSummary(c.paramsSchema),
        }));
        return text(JSON.stringify(list, null, 2));
      },
    }),

    defineTool({
      name: "monitor_list_notifiers",
      label: "列出通知器类型",
      description: "列出所有可用 notifier 类型及其参数 schema，供定义通知渠道时选择。",
      parameters: Type.Object({}),
      execute: async () => {
        const list = registry.listNotifiers().map((n) => ({
          type: n.type,
          params: schemaSummary(n.paramsSchema),
        }));
        return text(JSON.stringify(list, null, 2));
      },
    }),

    defineTool({
      name: "monitor_list",
      label: "列出已定义监控",
      description: "列出已配置的监控规则与通知渠道。",
      parameters: Type.Object({}),
      execute: async () => {
        const monitors = readMonitors(agentDir);
        const notifiers = readNotifiers(agentDir).map((n: any) => ({
          id: n.id,
          type: n.type,
          params: redactParams(registry.getNotifier(n.type)?.paramsSchema as any, n.params ?? {}),
        }));
        return text(JSON.stringify({ monitors, notifiers }, null, 2));
      },
    }),

    defineTool({
      name: "monitor_status",
      label: "查看告警状态",
      description: "查看最近的告警记录。",
      parameters: Type.Object({
        limit: Type.Optional(Type.Number({ description: "返回条数，默认 20" })),
      }),
      execute: async (_id, params) => {
        const store = createStore(deps.dbPath);
        const n = Math.min(Math.max(Number(params.limit ?? 20), 1), 200);
        const alerts = store.listAlerts(n).map((a) => ({
          id: a.id,
          monitor: a.monitorId,
          severity: a.severity,
          status: a.status,
          ts: new Date(a.ts).toISOString(),
          message: a.message,
        }));
        return text(JSON.stringify(alerts, null, 2) || "（无告警）");
      },
    }),

    defineTool({
      name: "notifier_add",
      label: "添加通知渠道",
      description:
        "添加/更新一个通知渠道（写 notifiers.yaml，需 --allow-write）。可选 test=true 立即发一条测试通知。",
      parameters: Type.Object({
        id: Type.String({ description: "通知渠道 ID，如 feishu-ops" }),
        type: Type.String({ description: "notifier 类型，如 feishu/dingtalk/email/webhook/log" }),
        params: Type.Record(Type.String(), Type.Unknown()),
        test: Type.Optional(Type.Boolean({ description: "是否立即发测试通知" })),
      }),
      execute: async (_id, p) => {
        if (!deps.allowWrite) return text("需 --allow-write 才能修改配置", true);
        const plugin = registry.getNotifier(String(p.type));
        if (!plugin) return text(`未知 notifier 类型: ${p.type}`, true);
        upsertNotifier(agentDir, { id: String(p.id), type: String(p.type), params: p.params as Record<string, unknown> });
        let msg = `已保存通知渠道 ${p.id} (${p.type})`;
        if (p.test) {
          try {
            await plugin.test(p.params);
            msg += "\n测试通知已发送。";
          } catch (e: any) {
            msg += `\n测试通知失败: ${e?.message ?? e}`;
          }
        }
        return text(msg);
      },
    }),

    defineTool({
      name: "monitor_add",
      label: "添加监控规则",
      description:
        "添加/更新一条监控规则（写 monitors.yaml，需 --allow-write）。可选 test=true 立即试采集一次。",
      parameters: Type.Object({
        rule: Type.Any(),
        test: Type.Optional(Type.Boolean()),
      }),
      execute: async (_id, p) => {
        if (!deps.allowWrite) return text("需 --allow-write 才能修改配置", true);
        const r = (p as any).rule as any;
        const plugin = registry.getCollector(String(r.collector));
        if (!plugin) return text(`未知 collector 类型: ${r.collector}`, true);
        upsertMonitor(agentDir, r);
        let msg = `已保存监控规则 ${r.id}`;
        if (p.test) {
          try {
            const sample = await plugin.collect(r.params ?? {}, {
              host: deps.host,
              history: () => [],
              guard,
            });
            const breached = evalCondition(r.when as any, sample.fields);
            msg += `\n试采集: ${JSON.stringify(sample.fields)} | 当前${breached ? "命中阈值" : "未命中"}`;
          } catch (e: any) {
            msg += `\n试采集失败: ${e?.message ?? e}`;
          }
        }
        msg += "\n提示：运行中的守护进程需 SIGHUP 或重启以加载（opagent monitor）。";
        return text(msg);
      },
    }),

    defineTool({
      name: "monitor_remove",
      label: "删除监控",
      description: "删除一条监控规则（需 --allow-write）。",
      parameters: Type.Object({ id: Type.String() }),
      execute: async (_id, p) => {
        if (!deps.allowWrite) return text("需 --allow-write", true);
        removeMonitor(agentDir, String(p.id));
        return text(`已删除监控 ${p.id}`);
      },
    }),

    defineTool({
      name: "monitor_new_plugin",
      label: "生成自定义插件模板",
      description:
        "生成自定义 collector 或 notifier 模板到 ~/.op_agent/monitor 或 notification 目录（需 --allow-write）。",
      parameters: Type.Object({
        kind: Type.Union([Type.Literal("collector"), Type.Literal("notifier")]),
        name: Type.String({ description: "插件名（kebab-case）" }),
      }),
      execute: async (_id, p) => {
        if (!deps.allowWrite) return text("需 --allow-write", true);
        const kind = String(p.kind) as "collector" | "notifier";
        const name = String(p.name);
        const path =
          kind === "collector"
            ? generateCollectorScaffold(agentDir, name)
            : generateNotifierScaffold(agentDir, name);
        return text(`已生成模板: ${path}\n编辑实现后，守护进程 SIGHUP 或重启自动加载。`);
      },
    }),
  ];
}
