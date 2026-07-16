/**
 * 配置文件读写（原始 yaml，不展开 ${VAR}，保留用户写法）
 *
 * 供 monitor_* 工具做 read-modify-write。
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { parse, stringify } from "yaml";

function readYaml(path: string): any {
  if (!existsSync(path)) return null;
  return parse(readFileSync(path, "utf-8"));
}
function writeYaml(path: string, data: any) {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, stringify(data), { mode: 0o600 });
}

export function readNotifiers(agentDir: string): any[] {
  const raw = readYaml(join(agentDir, "notifiers.yaml"));
  return raw?.notifiers ?? [];
}
export function readMonitors(agentDir: string): any[] {
  const raw = readYaml(join(agentDir, "monitors.yaml"));
  return raw?.monitors ?? [];
}

export function writeNotifiers(agentDir: string, notifiers: any[]) {
  writeYaml(join(agentDir, "notifiers.yaml"), { notifiers });
}
export function writeMonitors(agentDir: string, monitors: any[]) {
  writeYaml(join(agentDir, "monitors.yaml"), { monitors });
}

export function upsertNotifier(agentDir: string, n: { id: string; type: string; params: any }): any[] {
  const all = readNotifiers(agentDir).filter((x) => x.id !== n.id);
  all.push(n);
  writeNotifiers(agentDir, all);
  return all;
}

export function upsertMonitor(agentDir: string, m: any): any[] {
  const all = readMonitors(agentDir).filter((x) => x.id !== m.id);
  all.push(m);
  writeMonitors(agentDir, all);
  return all;
}

export function removeMonitor(agentDir: string, id: string): any[] {
  const all = readMonitors(agentDir).filter((x) => x.id !== id);
  writeMonitors(agentDir, all);
  return all;
}
