/**
 * 插件注册表
 *
 * 加载内置插件 + 用户自定义插件：
 * - 内置：src/monitor/builtin/{collectors,notifiers}/*.ts
 * - 用户：~/.op_agent/monitor/*.ts（Collector）、~/.op_agent/notification/*.ts（Notifier）
 *         单文件或 <name>/index.ts
 *
 * 用 Bun 原生动态 import 加载 .ts（无需 jiti 编译）。用户插件自包含，不依赖 opagent 内部模块。
 * 同 type 后加载者警告并忽略；内置优先级最低（用户可覆盖）。
 */

import { existsSync, readdirSync, statSync } from "node:fs";
import { join, basename, extname } from "node:path";
import { pathToFileURL } from "node:url";
import { homedir } from "node:os";
import type { Collector, Notifier, PluginKind } from "./types.ts";
import { builtinCollectors } from "./builtin/collectors/index.ts";
import { builtinNotifiers } from "./builtin/notifiers/index.ts";

export interface Registry {
  getCollector(type: string): Collector | undefined;
  getNotifier(type: string): Notifier | undefined;
  listCollectors(): Collector[];
  listNotifiers(): Notifier[];
}

async function loadPluginFile(filePath: string): Promise<any | null> {
  try {
    const mod = await import(pathToFileURL(filePath).href);
    return mod.default ?? null;
  } catch (e: any) {
    console.warn(`[opagent:monitor] 加载插件失败 ${filePath}: ${e?.message ?? e}`);
    return null;
  }
}

/** 扫描目录，返回插件文件路径列表（单文件 .ts 或 <name>/index.ts） */
function scanDir(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (!statSync(full).isDirectory()) {
      if (extname(entry) === ".ts") files.push(full);
    } else {
      const idx = join(full, "index.ts");
      if (existsSync(idx)) files.push(idx);
    }
  }
  return files;
}

export async function createRegistry(agentDir?: string): Promise<Registry> {
  const collectors = new Map<string, Collector>();
  const notifiers = new Map<string, Notifier>();

  const registerCollector = (c: Collector) => {
    if (collectors.has(c.type)) {
      console.warn(`[opagent:monitor] collector 类型冲突，忽略: ${c.type}`);
      return;
    }
    collectors.set(c.type, c);
  };
  const registerNotifier = (n: Notifier) => {
    if (notifiers.has(n.type)) {
      console.warn(`[opagent:monitor] notifier 类型冲突，忽略: ${n.type}`);
      return;
    }
    notifiers.set(n.type, n);
  };

  // 1. 内置（优先级最低，先注册 → 用户可覆盖）
  //    为允许用户覆盖，内置先放，用户后放但跳过冲突——这里改为：用户先注册，内置不覆盖已存在
  const userCollectorDir = join(agentDir ?? join(homedir(), ".op_agent"), "monitor");
  const userNotifierDir = join(agentDir ?? join(homedir(), ".op_agent"), "notification");

  for (const f of scanDir(userCollectorDir)) {
    const c = await loadPluginFile(f);
    if (c?.type) registerCollector(c as Collector);
  }
  for (const f of scanDir(userNotifierDir)) {
    const n = await loadPluginFile(f);
    if (n?.type) registerNotifier(n as Notifier);
  }
  for (const c of builtinCollectors) if (!collectors.has(c.type)) registerCollector(c);
  for (const n of builtinNotifiers) if (!notifiers.has(n.type)) registerNotifier(n);

  return {
    getCollector: (t) => collectors.get(t),
    getNotifier: (t) => notifiers.get(t),
    listCollectors: () => [...collectors.values()],
    listNotifiers: () => [...notifiers.values()],
  };
}
