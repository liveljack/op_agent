/**
 * 内置 Collector：系统指标（cpu/mem/disk/net）
 *
 * Linux /proc + df；解析逻辑独立为纯函数（便于单测，macOS 也能测解析）。
 * 采集本身只读。
 */

import { Type } from "typebox";
import { readFileSync } from "node:fs";
import { $ } from "bun";
import type { Collector, Sample } from "../../types.ts";

/** 解析 `df -P` 输出，返回各挂载点使用情况 */
export function parseDf(output: string): Array<{ mount: string; usage: number; sizeGb: number; availGb: number }> {
  const lines = output.trim().split("\n").slice(1);
  const out: Array<{ mount: string; usage: number; sizeGb: number; availGb: number }> = [];
  for (const line of lines) {
    const p = line.trim().split(/\s+/);
    if (p.length < 6 || !p[1] || !p[3] || !p[4] || !p[5]) continue;
    const size = Number(p[1]);
    const avail = Number(p[3]);
    const usage = Number(p[4].replace("%", ""));
    const mount = p[5];
    out.push({ mount, usage, sizeGb: size / 1024 / 1024, availGb: avail / 1024 / 1024 });
  }
  return out;
}

export const systemDisk: Collector = {
  type: "system.disk",
  paramsSchema: Type.Object({
    mount: Type.String({ description: "挂载点，如 / 或 /data", default: "/" }),
  }),
  fields: ["usage_percent", "size_gb", "avail_gb"],
  async collect(params) {
    const out = await $`df -P`.quiet().nothrow();
    const rows = parseDf(out.stdout.toString());
    const mount = String(params.mount ?? "/");
    const row = rows.find((r) => r.mount === mount) ?? rows[0];
    if (!row) throw new Error(`未找到挂载点: ${mount}`);
    return {
      ts: Date.now(),
      fields: {
        usage_percent: row.usage,
        size_gb: Number(row.sizeGb.toFixed(2)),
        avail_gb: Number(row.availGb.toFixed(2)),
      },
      labels: { mount: row.mount },
    };
  },
};

/** 解析 /proc/meminfo */
export function parseMeminfo(text: string): {
  totalKb: number;
  freeKb: number;
  availKb: number;
  cachedKb: number;
  swapTotalKb: number;
  swapFreeKb: number;
} {
  const get = (k: string) => {
    const m = text.match(new RegExp(`^${k}:\\s+(\\d+)`, "m"));
    return m ? Number(m[1]) : 0;
  };
  return {
    totalKb: get("MemTotal"),
    freeKb: get("MemFree"),
    availKb: get("MemAvailable"),
    cachedKb: get("Cached"),
    swapTotalKb: get("SwapTotal"),
    swapFreeKb: get("SwapFree"),
  };
}

export const systemMem: Collector = {
  type: "system.mem",
  paramsSchema: Type.Object({}),
  fields: ["used_percent", "used_gb", "swap_percent"],
  async collect() {
    const text = readFileSync("/proc/meminfo", "utf-8");
    const m = parseMeminfo(text);
    const usedKb = m.totalKb - m.availKb;
    const usedPercent = m.totalKb ? (usedKb / m.totalKb) * 100 : 0;
    const swapPercent = m.swapTotalKb ? ((m.swapTotalKb - m.swapFreeKb) / m.swapTotalKb) * 100 : 0;
    return {
      ts: Date.now(),
      fields: {
        used_percent: Number(usedPercent.toFixed(1)),
        used_gb: Number((usedKb / 1024 / 1024).toFixed(2)),
        swap_percent: Number(swapPercent.toFixed(1)),
      },
    };
  },
};

/** 解析 /proc/loadavg */
export function parseLoadavg(text: string): { load1: number; load5: number; load15: number } {
  const p = text.trim().split(/\s+/);
  return { load1: Number(p[0]), load5: Number(p[1]), load15: Number(p[2]) };
}

export const systemCpu: Collector = {
  type: "system.cpu",
  paramsSchema: Type.Object({}),
  fields: ["usage_percent", "load1", "load5"],
  async collect() {
    // 采样两次 /proc/stat 间隔 100ms 估算 CPU 使用率
    const read = () => {
      const line = readFileSync("/proc/stat", "utf-8").split("\n")[0] ?? "";
      const p = line.split(/\s+/).slice(1).map(Number);
      return { idle: p[3] ?? 0, total: p.reduce((a, b) => a + b, 0) };
    };
    const a = read();
    await Bun.sleep(100);
    const b = read();
    const dt = b.total - a.total;
    const usage = dt > 0 ? (1 - (b.idle - a.idle) / dt) * 100 : 0;
    const la = parseLoadavg(readFileSync("/proc/loadavg", "utf-8"));
    return {
      ts: Date.now(),
      fields: {
        usage_percent: Number(usage.toFixed(1)),
        load1: la.load1,
        load5: la.load5,
      },
    };
  },
};

/** 解析 /proc/net/dev */
export function parseNetdev(text: string, iface: string): { rx: number; tx: number; errIn: number; errOut: number } {
  for (const line of text.split("\n").slice(2)) {
    const m = line.match(/^\s*(\S+):\s*(.*)$/);
    if (!m || m[1] !== iface || !m[2]) continue;
    const p = m[2].trim().split(/\s+/).map(Number);
    return { rx: p[0] ?? 0, tx: p[8] ?? 0, errIn: p[2] ?? 0, errOut: p[10] ?? 0 };
  }
  throw new Error(`未找到网卡: ${iface}`);
}

export const systemNet: Collector = {
  type: "system.net",
  paramsSchema: Type.Object({
    iface: Type.String({ description: "网卡名，如 eth0", default: "eth0" }),
  }),
  fields: ["rx_bytes", "tx_bytes", "err_in", "err_out"],
  async collect(params) {
    const iface = String(params.iface ?? "eth0");
    const text = readFileSync("/proc/net/dev", "utf-8");
    const r = parseNetdev(text, iface);
    return {
      ts: Date.now(),
      fields: { rx_bytes: r.rx, tx_bytes: r.tx, err_in: r.errIn, err_out: r.errOut },
      labels: { iface },
    };
  },
};
