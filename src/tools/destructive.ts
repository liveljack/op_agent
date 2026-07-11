/**
 * 受控破坏性工具
 *
 * 默认完全不注册（见 index.ts：仅当 --allow-destructive 时才加入 customTools）。
 * 即使注册，safety 扩展仍会在 tool_call 做破坏性确认 + 审计。
 * 工具内部再次校验路径白名单，作为防御纵深。
 */

import { Type } from "typebox";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { $ } from "bun";
import type { PolicyGuard } from "../safety/policy.ts";

function textOut(s: string) {
  return { content: [{ type: "text" as const, text: s }], details: {} };
}

export function createDestructiveTools(guard: PolicyGuard) {
  return [
    defineTool({
      name: "controlled_delete",
      label: "受控删除",
      description:
        "删除白名单目录内的单个文件。仅当 --allow-destructive 启用时可用；仍需用户二次确认并填写理由。严禁删除目录、系统文件、数据库。",
      parameters: Type.Object({
        path: Type.String({ description: "待删除文件的绝对路径（必须在写白名单内）" }),
        reason: Type.String({ description: "删除理由（必填，写入审计）" }),
      }),
      execute: async (_id, params) => {
        const path = String(params.path);
        const reason = String(params.reason ?? "");
        if (!reason.trim()) throw new Error("必须填写删除理由");
        const decision = guard.checkDeletePath(path);
        if (!decision.allow) {
          throw new Error(`删除被策略拒绝：${decision.reason}`);
        }
        // 仅允许删除普通文件，禁目录
        const file = Bun.file(path);
        const exists = await file.exists();
        if (!exists) return textOut(`文件不存在：${path}`);
        try {
          await $`rm -- ${path}`.quiet();
          return textOut(`已删除：${path}\n理由：${reason}`);
        } catch (e: any) {
          throw new Error(`删除失败：${e.message}`);
        }
      },
    }),

    defineTool({
      name: "db_query",
      label: "数据库只读查询",
      description: "对数据库执行只读 SELECT 查询。破坏性 SQL 会被策略层阻断。",
      parameters: Type.Object({
        dsn: Type.String({ description: "数据库连接串" }),
        sql: Type.String({ description: "SELECT 查询语句" }),
      }),
      execute: async (_id, params) => {
        const sql = String(params.sql);
        const decision = guard.checkSql(sql);
        if (!decision.allow || decision.risk !== "read") {
          throw new Error(`查询被策略拒绝：${decision.reason ?? "非只读 SQL"}`);
        }
        // 仅做策略校验与占位；实际执行由部署方按需接入 Bun.sql。
        return textOut(
          `[dry-run] 只读查询通过策略校验，未执行（需配置数据库连接）：\n${sql}`,
        );
      },
    }),
  ];
}
