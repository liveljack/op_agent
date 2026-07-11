import { test, expect, describe } from "bun:test";
import { mergeDecisions, LlmAuditor, type LlmAuditResult } from "../../src/audit/llm.ts";

const pat = (allow: boolean, risk: any, requireConfirm = false, reason = "pattern") => ({
  allow,
  risk,
  requireConfirm,
  reason,
  matches: ["x"],
});

describe("mergeDecisions —— 模式层与 LLM 取严合并", () => {
  test("模式层阻断 → 维持阻断（LLM 不能放行）", () => {
    const m = mergeDecisions(pat(false, "destructive"), {
      allow: true,
      risk: "read",
      requireConfirm: false,
      reason: "llm ok",
    });
    expect(m.allow).toBe(false);
    expect(m.risk).toBe("destructive");
  });

  test("LLM 阻断 → 阻断（LLM 升级）", () => {
    const m = mergeDecisions(pat(true, "write", false), {
      allow: false,
      risk: "destructive",
      requireConfirm: false,
      reason: "发现外泄",
    });
    expect(m.allow).toBe(false);
    expect(m.risk).toBe("destructive");
    expect(m.reason).toContain("LLM 审计阻断");
  });

  test("LLM 要求确认 → 升级为确认", () => {
    const m = mergeDecisions(pat(true, "write", false), {
      allow: true,
      risk: "write",
      requireConfirm: true,
      reason: "可疑但可控",
    });
    expect(m.allow).toBe(true);
    expect(m.requireConfirm).toBe(true);
  });

  test("两者都放行 → 放行", () => {
    const m = mergeDecisions(pat(true, "write", true), {
      allow: true,
      risk: "write",
      requireConfirm: false,
      reason: "llm ok",
    });
    expect(m.allow).toBe(true);
    expect(m.requireConfirm).toBe(true); // 模式层仍要求确认
  });

  test("LLM 判定更高风险 → 取更高风险", () => {
    const m = mergeDecisions(pat(true, "write", false), {
      allow: true,
      risk: "destructive",
      requireConfirm: true,
      reason: "实际是破坏性",
    });
    expect(m.risk).toBe("destructive");
    expect(m.requireConfirm).toBe(true);
  });
});

describe("LlmAuditor —— 端到端（mock OpenAI 兼容端点）", () => {
  test("正常返回审计判定并解析 JSON", async () => {
    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = (await req.json()) as any;
        // 简单 echo 判定：命令含 rm 则阻断
        const cmd = body.messages?.[1]?.content ?? "";
        const danger = /rm |delete|drop/i.test(cmd);
        return Response.json({
          choices: [
            {
              message: {
                content: JSON.stringify(
                  danger
                    ? { allow: false, risk: "destructive", requireConfirm: false, reason: "含删除" }
                    : { allow: true, risk: "read", requireConfirm: false, reason: "只读安全" },
                ),
              },
            },
          ],
        });
      },
    });
    const baseUrl = `http://localhost:${server.port}`;
    const auditor = new LlmAuditor({ baseUrl, model: "test", apiKey: "k" });

    const ok = await auditor.audit({ tool: "bash", command: "df -h" }, { allowWrite: true, allowDestructive: false });
    expect(ok.allow).toBe(true);
    expect(ok.risk).toBe("read");

    const bad = await auditor.audit({ tool: "bash", command: "rm -rf /x" }, { allowWrite: true, allowDestructive: false });
    expect(bad.allow).toBe(false);
    expect(bad.risk).toBe("destructive");

    server.stop(true);
  });

  test("端点异常 → fail-safe 升级为需确认", async () => {
    const server = Bun.serve({
      port: 0,
      fetch() {
        return new Response("internal error", { status: 500 });
      },
    });
    const auditor = new LlmAuditor({
      baseUrl: `http://localhost:${server.port}`,
      model: "test",
      apiKey: "k",
    });
    const r = await auditor.audit({ tool: "bash", command: "echo x" }, { allowWrite: true, allowDestructive: false });
    expect(r.allow).toBe(true);
    expect(r.requireConfirm).toBe(true); // fail-safe：升级人工确认
    server.stop(true);
  });

  test("未配置 key → 跳过（enabled=false）", async () => {
    const auditor = new LlmAuditor({ baseUrl: "http://localhost:1", model: "test" });
    expect(auditor.enabled).toBe(false);
    const r = await auditor.audit({ tool: "bash", command: "x" }, { allowWrite: true, allowDestructive: false });
    expect(r.allow).toBe(true);
    expect(r.reason).toContain("跳过");
  });
});
