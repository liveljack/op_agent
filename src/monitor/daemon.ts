/**
 * Monitor Daemon —— 调度 + 告警状态机 + 去重 + 热加载
 *
 * 每 rule 按 intervalMs 采集 → 评估条件 → 状态机推进 → 通知。
 * 状态：ok → pending(条件命中) → firing(持续 for) → resolved(恢复)
 * 去重：alertKey = monitorId+labels；cooldown 内不重复通知。
 * 热加载：SIGHUP 重新加载配置与插件。
 */

import { hostname } from "node:os";
import type { Registry } from "./registry.ts";
import { loadMonitorConfig, redactParams } from "./config.ts";
import { evalCondition } from "./condition.ts";
import { createStore, type MonitorStore } from "./store.ts";
import type { Alert, Rule, Sample } from "./types.ts";

type MonState = "ok" | "pending" | "firing";

interface Runtime {
  state: MonState;
  pendingSince: number;
  lastNotifyTs: number;
  activeAlertId: string | null;
  timer: ReturnType<typeof setInterval> | null;
}

export interface DaemonDeps {
  registry: Registry;
  agentDir: string;
  dbPath: string;
  guard: any;
  onAlert?: (a: Alert) => void; // 推送到 TUI 等
}

export class MonitorDaemon {
  private store: MonitorStore;
  private host = hostname();
  private runtimes = new Map<string, Runtime>();
  private rules: Rule[] = [];
  private notifierConfigs: Map<string, { type: string; params: Record<string, unknown> }> = new Map();
  private reloading = false;

  constructor(private deps: DaemonDeps) {
    this.store = createStore(deps.dbPath);
  }

  /** 加载配置 + 启动所有调度 */
  async start() {
    await this.reload();
    process.on("SIGHUP", () => {
      console.log("[opagent:monitor] 收到 SIGHUP，重新加载...");
      this.reload().catch((e) => console.error("[opagent:monitor] 重载失败:", e));
    });
    console.log(`[opagent:monitor] 已启动，监控 ${this.rules.length} 条`);
  }

  async reload() {
    if (this.reloading) return;
    this.reloading = true;
    try {
      // 停旧调度
      for (const rt of this.runtimes.values()) if (rt.timer) clearInterval(rt.timer);
      this.runtimes.clear();

      const cfg = loadMonitorConfig(this.deps.agentDir);
      this.rules = cfg.monitors;
      this.notifierConfigs.clear();
      for (const n of cfg.notifiers) this.notifierConfigs.set(n.id, { type: n.type, params: n.params });

      // 启新调度
      for (const rule of this.rules) {
        const rt: Runtime = { state: "ok", pendingSince: 0, lastNotifyTs: 0, activeAlertId: null, timer: null };
        this.runtimes.set(rule.id, rt);
        rt.timer = setInterval(() => this.tick(rule).catch((e) => console.error(`[opagent:monitor] ${rule.id} tick:`, e)), rule.intervalMs);
        // 立即跑一次
        this.tick(rule).catch((e) => console.error(`[opagent:monitor] ${rule.id} tick:`, e));
      }
    } finally {
      this.reloading = false;
    }
  }

  stop() {
    for (const rt of this.runtimes.values()) if (rt.timer) clearInterval(rt.timer);
    this.runtimes.clear();
  }

  private async tick(rule: Rule) {
    const collector = this.deps.registry.getCollector(rule.collector);
    const rt = this.runtimes.get(rule.id);
    if (!collector || !rt) return;

    let sample: Sample;
    try {
      sample = await collector.collect(rule.params, {
        host: this.host,
        history: (mid, w) => this.store.history(mid, w),
        guard: this.deps.guard,
      });
    } catch (e: any) {
      console.error(`[opagent:monitor] ${rule.id} 采集失败: ${e?.message ?? e}`);
      return;
    }
    sample.ts = sample.ts || Date.now();
    this.store.appendSample(rule.id, sample);
    if (Math.random() < 0.1) this.store.prune(Date.now()); // 偶尔清理

    const breached = evalCondition(rule.when, sample.fields);
    const now = Date.now();
    const alertKey = `${rule.id}:${JSON.stringify(sample.labels ?? {})}`;

    if (breached) {
      if (rt.state === "ok") {
        rt.state = "pending";
        rt.pendingSince = now;
        return;
      }
      if (rt.state === "pending") {
        const forMs = rule.forMs ?? 0;
        if (now - rt.pendingSince >= forMs) {
          rt.state = "firing";
          await this.fire(rule, sample, alertKey, rt, now);
        }
        return;
      }
      // firing：cooldown 到了再重复通知
      if (rt.state === "firing" && now - rt.lastNotifyTs >= (rule.cooldownMs ?? 0)) {
        await this.fire(rule, sample, alertKey, rt, now);
      }
    } else {
      // 恢复
      if (rt.state === "firing" && rt.activeAlertId) {
        this.store.resolveAlert(rt.activeAlertId, now);
        await this.notifyResolve(rule, sample, now);
        rt.state = "ok";
        rt.activeAlertId = null;
      } else if (rt.state === "pending") {
        rt.state = "ok";
      }
    }
  }

  private async fire(rule: Rule, sample: Sample, alertKey: string, rt: Runtime, now: number) {
    const alert: Alert = {
      id: `${alertKey}:${now}`,
      monitorId: rule.id,
      severity: rule.severity,
      message: this.buildMessage(rule, sample),
      sample,
      host: this.host,
      ts: now,
      status: "firing",
    };
    this.store.insertAlert(alert);
    rt.activeAlertId = alert.id;
    rt.lastNotifyTs = now;
    await this.dispatch(rule, alert);
    this.deps.onAlert?.(alert);
  }

  private async notifyResolve(rule: Rule, sample: Sample, now: number) {
    const alert: Alert = {
      id: `${rule.id}:resolve:${now}`,
      monitorId: rule.id,
      severity: rule.severity,
      message: `[恢复] ${rule.id} 已恢复正常`,
      sample,
      host: this.host,
      ts: now,
      status: "resolved",
    };
    await this.dispatch(rule, alert);
  }

  private async dispatch(rule: Rule, alert: Alert) {
    for (const notifierId of rule.notifiers) {
      const cfg = this.notifierConfigs.get(notifierId);
      if (!cfg) {
        console.warn(`[opagent:monitor] 未找到 notifier: ${notifierId}`);
        continue;
      }
      const plugin = this.deps.registry.getNotifier(cfg.type);
      if (!plugin) {
        console.warn(`[opagent:monitor] 未找到 notifier 插件类型: ${cfg.type}`);
        continue;
      }
      try {
        await plugin.notify(alert, cfg.params);
      } catch (e: any) {
        console.error(`[opagent:monitor] 通知失败 ${notifierId}: ${e?.message ?? e}`);
      }
    }
  }

  private buildMessage(rule: Rule, sample: Sample): string {
    const field = "field" in rule.when ? rule.when.field : "";
    const val = field ? sample.fields[field] : "";
    return `[${rule.severity}] ${rule.id}: ${field}=${val} 命中阈值 (${this.host})`;
  }
}
