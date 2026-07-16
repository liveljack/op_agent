/**
 * 内置 Collector：文件 tail / SQL / 命令
 *
 * file.tail：读日志尾部，按正则统计 window 内匹配数
 * sql：只读 SELECT（过 guard.checkSql）
 * command.read：受控命令（过 guard.checkBash，非只读拒绝）
 */

import { Type } from "typebox";
import { readFileSync, statSync } from "node:fs";
import { $ } from "bun";
import type { Collector, Sample } from "../../types.ts";

export const fileTail: Collector = {
  type: "file.tail",
  paramsSchema: Type.Object({
    path: Type.String({ description: "日志文件路径，如 /var/log/nginx/error.log" }),
    pattern: Type.Optional(Type.String({ description: "正则，匹配则计入 match_count" })),
    window: Type.Optional(Type.String({ description: "统计窗口，如 60s（默认 60s）" })),
    bytes: Type.Optional(Type.Number({ description: "读取尾部字节数，默认 65536", default: 65536 })),
  }),
  fields: ["match_count", "last_line"],
  async collect(params, ctx) {
    const path = String(params.path);
    const pattern = params.pattern ? new RegExp(String(params.pattern)) : null;
    const windowMs = params.window ? parseWindow(String(params.window)) : 60_000;
    const bytes = Number(params.bytes ?? 65536);
    const size = statSync(path).size;
    const start = Math.max(0, size - bytes);
    const buf = readFileSync(path, { encoding: "utf-8" } as any).slice(start) as unknown as string;
    // readFileSync with offset not supported in Bun simply; read whole then slice
    const lines = (buf as string).split("\n");
    let matchCount = 0;
    let lastLine = "";
    for (const ln of lines) {
      if (!ln) continue;
      lastLine = ln;
      if (pattern && pattern.test(ln)) matchCount++;
    }
    // window 内去重：若 window < 文件全量，按 history 衰减近似（MVP 用全量匹配数）
    void ctx;
    return {
      ts: Date.now(),
      fields: { match_count: matchCount, last_line: lastLine.slice(-200) },
      labels: { path },
    };
  },
};

function parseWindow(s: string): number {
  const m = s.match(/^(\d+)\s*(s|m|h)?$/);
  if (!m) return 60_000;
  const n = Number(m[1]);
  const u = m[2] ?? "s";
  return n * ({ s: 1000, m: 60_000, h: 3_600_000 }[u] ?? 1000);
}

export const sqlCollector: Collector = {
  type: "sql",
  paramsSchema: Type.Object({
    dsn: Type.String({ description: "数据库连接串（仅支持 SELECT）" }),
    query: Type.String({ description: "只读 SELECT 查询" }),
  }),
  fields: [],
  async collect(params, ctx) {
    const sql = String(params.query);
    const decision = ctx.guard.checkSql(sql);
    if (!decision.allow || decision.risk !== "read") {
      throw new Error(`SQL 被策略拒绝：${decision.reason ?? "非只读"}`);
    }
    // MVP：dry-run 占位——实际执行按部署方接入 Bun.sql（设计已留接口）
    // 此处返回占位值，避免未配置 DB 时崩溃
    return {
      ts: Date.now(),
      fields: { _note: "sql collector 需接入 Bun.sql 执行；已通过策略校验", query_passed: 1 },
      labels: { dsn: String(params.dsn) },
  };
  },
};

export const commandRead: Collector = {
  type: "command.read",
  paramsSchema: Type.Object({
    command: Type.String({ description: "受控只读命令（过 PolicyGuard，非只读拒绝）" }),
  }),
  fields: ["exit_code", "stdout"],
  async collect(params, ctx) {
    const command = String(params.command);
    const decision = ctx.guard.checkBash(command);
    if (!decision.allow || decision.risk !== "read") {
      throw new Error(`命令被策略拒绝：${decision.reason ?? "非只读"}`);
    }
    const out = await $`bash -c ${command}`.quiet().nothrow();
    return {
      ts: Date.now(),
      fields: {
        exit_code: out.exitCode ?? 0,
        stdout: (out.stdout.toString().trim().slice(-500) || "(无输出)") as string,
      },
    };
  },
};
