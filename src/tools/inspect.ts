/**
 * 运维只读检查工具
 *
 * 全部 risk=read，自动执行（无需确认）。
 * 内部命令虽为固定只读，仍过 PolicyGuard 作为防御纵深——非 read 一律拒绝执行。
 */

import { Type } from "typebox";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { $ } from "bun";
import type { PolicyGuard } from "../safety/policy.ts";

/** 受控执行：仅允许 read 级命令，过 PolicyGuard */
async function guardedRun(guard: PolicyGuard, command: string): Promise<string> {
  const decision = guard.checkBash(command);
  if (!decision.allow || decision.risk !== "read") {
    throw new Error(`inspect 工具拒绝执行非只读命令：${decision.reason ?? command}`);
  }
  const wrapped = `set -o pipefail; ${command}`;
  try {
    const out = await Promise.race([
      $`bash -c ${wrapped}`.quiet(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("inspect 命令超时（30s）")), 30_000),
      ),
    ]);
    return out.stdout.toString().trim();
  } catch (e: any) {
    // 命令非零退出也返回 stderr 供模型诊断
    const stderr = e?.stderr?.toString?.()?.trim() ?? "";
    const stdout = e?.stdout?.toString?.()?.trim() ?? "";
    throw new Error(`${stdout ? stdout + "\n" : ""}${stderr || e.message}`);
  }
}

function textOut(s: string) {
  return { content: [{ type: "text" as const, text: s }], details: {} };
}

export function createInspectTools(guard: PolicyGuard) {
  return [
    defineTool({
      name: "inspect_disk",
      label: "检查磁盘",
      description: "检查磁盘使用率（df -h）。用于磁盘空间排查。",
      parameters: Type.Object({
        detail: Type.Optional(Type.Boolean({ description: "是否对挂载点 du 定位大目录（耗时）" })),
      }),
      execute: async (_id, params) => {
        let out = await guardedRun(guard, "df -h");
        if (params.detail) {
          out += "\n\n# 大目录（/var 下 du）\n";
          out += await guardedRun(guard, "du -sh /var/* 2>/dev/null | sort -rh | head -10");
        }
        return textOut(out);
      },
    }),

    defineTool({
      name: "inspect_mem",
      label: "检查内存",
      description: "检查内存与 swap 使用（free -h）。",
      parameters: Type.Object({}),
      execute: async () => textOut(await guardedRun(guard, "free -h")),
    }),

    defineTool({
      name: "inspect_cpu",
      label: "检查CPU",
      description: "检查负载、CPU 核数与占前进程。",
      parameters: Type.Object({}),
      execute: async () => {
        const load = await guardedRun(guard, "cat /proc/loadavg; echo; nproc");
        const top = await guardedRun(guard, "ps -eo pid,pcpu,pmem,comm --sort=-pcpu | head -11");
        return textOut(`# 负载/核数\n${load}\n\n# 占CPU前10\n${top}`);
      },
    }),

    defineTool({
      name: "inspect_net",
      label: "检查网络",
      description: "检查监听端口与网卡（ss / ip）。",
      parameters: Type.Object({}),
      execute: async () => {
        const ports = await guardedRun(guard, "ss -tulpn 2>/dev/null | head -40");
        const iface = await guardedRun(guard, "ip -br a 2>/dev/null");
        return textOut(`# 监听端口\n${ports}\n\n# 网卡\n${iface}`);
      },
    }),

    defineTool({
      name: "inspect_service",
      label: "检查服务",
      description: "查看 systemd 服务状态（只读）。参数：服务名。",
      parameters: Type.Object({
        service: Type.String({ description: "systemd 服务名，如 nginx" }),
      }),
      execute: async (_id, params) => {
        const svc = String(params.service).replace(/[^a-zA-Z0-9_.@-]/g, "");
        if (!svc) throw new Error("无效服务名");
        return textOut(await guardedRun(guard, `systemctl status ${svc} --no-pager 2>&1 | head -40`));
      },
    }),

    defineTool({
      name: "inspect_proc",
      label: "检查进程",
      description: "列出占内存前 N 进程。",
      parameters: Type.Object({
        limit: Type.Optional(Type.Number({ description: "返回行数，默认 15" })),
      }),
      execute: async (_id, params) => {
        const n = Math.min(Math.max(Number(params.limit ?? 15), 1), 50);
        return textOut(await guardedRun(guard, `ps -eo pid,pcpu,pmem,rss,comm --sort=-rss | head -${n + 1}`));
      },
    }),

    defineTool({
      name: "read_logs",
      label: "读取日志",
      description: "读取 /var/log 下日志尾部。参数：相对 /var/log 的文件名、行数、关键字过滤。",
      parameters: Type.Object({
        file: Type.String({ description: "日志文件，如 syslog 或 nginx/error.log" }),
        lines: Type.Optional(Type.Number({ description: "尾部行数，默认 100" })),
        grep: Type.Optional(Type.String({ description: "关键字过滤" })),
      }),
      execute: async (_id, params) => {
        const file = String(params.file).replace(/[^a-zA-Z0-9_./-]/g, "");
        if (file.includes("..")) throw new Error("禁止路径穿越");
        const n = Math.min(Math.max(Number(params.lines ?? 100), 1), 1000);
        const grep = params.grep ? String(params.grep).replace(/[;|&$`]/g, "") : null;
        const cmd = grep
          ? `journalctl -n ${n} --no-pager 2>/dev/null | grep -i ${JSON.stringify(grep)} || tail -n ${n} /var/log/${file}`
          : `tail -n ${n} /var/log/${file}`;
        return textOut(await guardedRun(guard, cmd));
      },
    }),
  ];
}
