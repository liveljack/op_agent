/**
 * opagent-safety 扩展
 *
 * 在 pi 的 tool_call / user_bash 钩子中拦截所有工具调用，过 PolicyGuard：
 * - 破坏性 / 写操作：阻断或要求交互确认
 * - 硬保护路径：永远阻断
 * - 命令改写：注入 set -o pipefail 与默认 timeout，防资源耗尽
 * 拦截发生在工具执行前（pi 内核层），模型无法绕过。
 * 每次决策写入审计链。
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { PolicyGuard, PolicyDecision } from "./policy.ts";
import type { AuditStore } from "../audit/store.ts";
import { mergeDecisions, type LlmAuditor, type SafetyLevel } from "../audit/llm.ts";

export interface SafetyExtensionDeps {
  guard: PolicyGuard;
  audit: AuditStore;
  /** 可选 LLM 审计器（--llm_audit 启用） */
  auditor?: LlmAuditor;
  /** 当前安全等级，传给 LLM 审计器 */
  safetyLevel: SafetyLevel;
}

const DEFAULT_BASH_TIMEOUT_MS = 120_000;

export function createSafetyExtension(deps: SafetyExtensionDeps) {
  const { guard, audit, auditor, safetyLevel } = deps;

  /**
   * 对写/破坏性操作追加 LLM 语义审计，与模式层判定取严合并。
   * 只读跳过（省延迟）。LLM 审计结果单独入审计链。
   */
  async function llmAugment(
    decision: PolicyDecision,
    tool: string,
    command: string,
    context?: string,
  ): Promise<PolicyDecision> {
    if (!auditor || !decision.allow || decision.risk === "read") return decision;
    const llm = await auditor.audit({ tool, command, context }, safetyLevel);
    audit.append({
      ts: Date.now(),
      tool: "llm_audit",
      input: command.slice(0, 200),
      result: llm.reason,
      risk: llm.risk,
      blocked: !llm.allow,
      reason: `LLM审计 ${tool}`,
    });
    return mergeDecisions(decision, llm);
  }

  return function safetyExtension(pi: ExtensionAPI): void {
    // ---- bash 工具：命令级策略校验 + 改写 ----
    pi.on("tool_call", async (event, ctx) => {
      if (isToolCallEventType("bash", event)) {
        const command = event.input.command ?? "";
        let decision = guard.checkBash(command);
        // 写/破坏性命令追加 LLM 审计
        decision = await llmAugment(decision, "bash", command);

        // 命令改写：注入 pipefail 与默认 timeout（不改变命令语义）
        if (decision.allow) {
          if (!command.includes("set -o pipefail")) {
            event.input.command = `set -o pipefail; ${command}`;
          }
          if (event.input.timeout === undefined) {
            event.input.timeout = DEFAULT_BASH_TIMEOUT_MS;
          }
        }

        return resolveDecision(decision, "bash", command, ctx, audit);
      }

      // ---- write 工具：路径校验 + LLM 审计内容 ----
      if (isToolCallEventType("write", event)) {
        const target = event.input.path ?? "";
        let decision = guard.checkWritePath(target);
        decision = await llmAugment(
          decision,
          "write",
          String(event.input.content ?? "").slice(0, 1000),
          `path=${target}`,
        );
        return resolveDecision(decision, "write", `write ${target}`, ctx, audit);
      }

      // ---- edit 工具：路径校验 + LLM 审计 ----
      if (isToolCallEventType("edit", event)) {
        const target = event.input.path ?? "";
        let decision = guard.checkEditPath(target);
        decision = await llmAugment(decision, "edit", `edit ${target}`, `path=${target}`);
        return resolveDecision(decision, "edit", `edit ${target}`, ctx, audit);
      }

      // ---- run_script 工具：脚本内容过模式层 + LLM 审计（dry_run 放行）----
      if (event.toolName === "run_script") {
        const script = String(event.input?.script ?? "");
        if (event.input?.dry_run) {
          audit.append({
            ts: Date.now(),
            tool: "run_script",
            input: `[dry-run] ${script.slice(0, 200)}`,
            risk: "read",
            blocked: false,
            reason: "dry-run 预览",
          });
          return undefined;
        }
        let decision = guard.checkBash(script);
        // 脚本一律过 LLM 审计（即使模式层判读，脚本语义复杂）
        if (auditor && decision.allow) {
          const llm = await auditor.audit(
            { tool: "run_script", command: script },
            safetyLevel,
          );
          audit.append({
            ts: Date.now(),
            tool: "llm_audit",
            input: script.slice(0, 200),
            result: llm.reason,
            risk: llm.risk,
            blocked: !llm.allow,
            reason: "LLM审计 run_script",
          });
          decision = mergeDecisions(decision, llm);
        }
        return resolveDecision(
          decision,
          "run_script",
          script.slice(0, 200),
          ctx,
          audit,
        );
      }

      return undefined;
    });

    // ---- 执行结果入审计链（所有工具）----
    pi.on("tool_execution_end", async (event, _ctx) => {
      const result = event.result;
      const out =
        typeof result === "string"
          ? result
          : result && typeof result === "object" && "content" in result
            ? JSON.stringify((result as any).content).slice(0, 2000)
            : String(result ?? "").slice(0, 2000);
      audit.append({
        ts: Date.now(),
        tool: event.toolName,
        result: out,
        risk: "read",
        blocked: event.isError ? false : false,
        reason: event.isError ? "执行出错" : "执行结果",
      });
    });

    // ---- 用户 ! 命令：同样过策略 ----
    pi.on("user_bash", async (event, ctx) => {
      const decision = guard.checkBash(event.command);
      if (!decision.allow) {
        if (ctx.hasUI) ctx.ui.notify(`已阻断：${decision.reason}`, "error");
        audit.append({
          ts: Date.now(),
          tool: "user_bash",
          input: event.command,
          risk: decision.risk,
          blocked: true,
          reason: decision.reason,
          matches: decision.matches,
        });
        // 返回空结果以阻止执行
        return {
          result: {
            output: `[blocked by safety policy] ${decision.reason}`,
            exitCode: 126,
            cancelled: false,
            truncated: false,
          },
        };
      }
      return undefined;
    });
  };
}

/**
 * 把 PolicyDecision 解析为 pi 的 tool_call 返回值：
 * - allow + requireConfirm → 交互确认；通过则放行，拒绝则 block
 * - allow + !requireConfirm → 放行
 * - !allow → block + 审计
 */
async function resolveDecision(
  decision: PolicyDecision,
  tool: string,
  inputSummary: string,
  ctx: ExtensionContext,
  audit: AuditStore,
) {
  if (!decision.allow) {
    audit.append({
      ts: Date.now(),
      tool,
      input: inputSummary,
      risk: decision.risk,
      blocked: true,
      reason: decision.reason,
      matches: decision.matches,
    });
    if (ctx.hasUI) ctx.ui.notify(`已阻断：${decision.reason}`, "error");
    return { block: true, reason: decision.reason };
  }

  if (decision.requireConfirm) {
    const canConfirm = ctx.hasUI;
    if (!canConfirm) {
      // 无 UI（print 模式）无法确认 → 保守阻断
      audit.append({
        ts: Date.now(),
        tool,
        input: inputSummary,
        risk: decision.risk,
        blocked: true,
        reason: "无交互 UI，写/破坏性操作自动阻断",
        matches: decision.matches,
      });
      return { block: true, reason: "无 UI 可确认，已阻断写/破坏性操作" };
    }
    const approved = await ctx.ui.confirm(
      `确认${decision.risk === "destructive" ? "破坏性" : "写"}操作？`,
      `${decision.reason}\n目标：${inputSummary}`,
    );
    audit.append({
      ts: Date.now(),
      tool,
      input: inputSummary,
      risk: decision.risk,
      blocked: !approved,
      approver: approved ? "user" : undefined,
      reason: decision.reason,
      matches: decision.matches,
    });
    if (!approved) {
      ctx.ui.notify("已取消", "info");
      return { block: true, reason: "用户拒绝确认" };
    }
  }

  return undefined;
}
