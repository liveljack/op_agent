/**
 * opagent-audit 扩展
 *
 * 安全决策由 safety 扩展写入审计链；本扩展只提供查询能力：
 * - /audit list [n]   最近 n 条审计记录
 * - /audit verify     校验哈希链完整性
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { AuditStore } from "./store.ts";

export function createAuditExtension(audit: AuditStore) {
  return function auditExtension(pi: ExtensionAPI): void {
    pi.registerCommand("audit", {
      description: "查询审计链：/audit list [n] | /audit verify",
      handler: async (args, ctx) => {
        const parts = (args ?? "").trim().split(/\s+/);
        const sub = parts[0] ?? "list";

        if (sub === "verify") {
          const res = audit.verify();
          if (res.ok) {
            ctx.ui.notify("审计链校验通过：完整无篡改", "info");
          } else {
            ctx.ui.notify(`审计链损坏！首个异常记录 seq=${res.brokenAt}`, "error");
          }
          return;
        }

        const limit = Number(parts[1] ?? "20");
        const rows = audit.list(Number.isFinite(limit) ? limit : 20);
        const lines = rows.map((r) => {
          const flag = r.blocked ? "BLOCKED" : "OK";
          const m = r.matches ?? [];
          const matchStr = m.length ? ` [${m.join(",")}]` : "";
          return `#${r.seq} ${new Date(r.ts).toISOString()} ${r.tool} ${r.risk} ${flag}${matchStr}${r.reason ? " — " + r.reason : ""}`;
        });
        ctx.ui.notify(lines.join("\n") || "（无审计记录）", "info");
      },
    });
  };
}
