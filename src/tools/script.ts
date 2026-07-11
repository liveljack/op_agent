/**
 * run_script —— 受控脚本执行工具
 *
 * 安全流程（在 safety 扩展的 tool_call 已做命令级策略校验之后）：
 * 1. 语法检查：bash -n（或 python3 -m py_compile），不过则拒绝执行
 * 2. dry_run=true：仅返回脚本预览，不执行
 * 3. 执行：写入临时文件后运行，带超时，捕获输出
 *
 * 决策（阻断/确认）由 safety 扩展统一处理并写入审计；本工具负责语法校验与执行。
 */

import { Type } from "typebox";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { $ } from "bun";
import { writeFileSync, unlinkSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function textOut(s: string, isError = false) {
  return { content: [{ type: "text" as const, text: s }], details: {}, isError };
}

export function createScriptTools() {
  return [
    defineTool({
      name: "run_script",
      label: "执行脚本",
      description:
        "受控执行生成的 bash/python 脚本。自动先做语法检查（bash -n / py_compile）；" +
        "建议先用 dry_run=true 预览，确认无误后再执行。脚本内容由安全策略层校验，" +
        "破坏性/写命令会被阻断或要求确认。",
      parameters: Type.Object({
        script: Type.String({ description: "脚本内容" }),
        interpreter: Type.Optional(
          Type.Union([Type.Literal("bash"), Type.Literal("python3")], {
            description: "解释器，默认 bash",
          }),
        ),
        dry_run: Type.Optional(
          Type.Boolean({ description: "仅预览脚本内容，不执行（建议先 true 预览）" }),
        ),
      }),
      execute: async (_id, params) => {
        const script = String(params.script ?? "");
        const interpreter = params.interpreter === "python3" ? "python3" : "bash";
        if (!script.trim()) return textOut("空脚本", true);

        // dry_run：仅预览，不执行
        if (params.dry_run) {
          return textOut(`[dry-run 预览，未执行] 解释器=${interpreter}\n\n${script}`);
        }

        // 临时文件（独立目录，避免覆盖）
        const dir = mkdtempSync(join(tmpdir(), "opagent-"));
        const ext = interpreter === "python3" ? ".py" : ".sh";
        const file = join(dir, `script${ext}`);
        writeFileSync(file, script, { mode: 0o600 });

        try {
          // 1. 语法检查
          const checkCmd =
            interpreter === "python3"
              ? $`python3 -m py_compile ${file}`.quiet().nothrow()
              : $`bash -n ${file}`.quiet().nothrow();
          const checkRes = await checkCmd;
          if (checkRes.exitCode !== 0) {
            const err = checkRes.stderr.toString().trim() || "语法错误";
            return textOut(`语法检查失败，已拒绝执行：\n${err}`, true);
          }

          // 2. 执行
          const runRes = await Promise.race([
            interpreter === "python3"
              ? $`python3 ${file}`.quiet()
              : $`bash ${file}`.quiet(),
            new Promise<never>((_, reject) =>
              setTimeout(() => reject(new Error("脚本执行超时（60s）")), 60_000),
            ),
          ]);
          const out = (
            runRes.stdout.toString() +
            (runRes.stderr.toString() ? "\n[stderr]\n" + runRes.stderr.toString() : "")
          ).trim();
          return textOut(out || "(无输出)");
        } catch (e: any) {
          const stderr = e?.stderr?.toString?.()?.trim() ?? "";
          return textOut(`执行失败：${e.message}${stderr ? "\n" + stderr : ""}`, true);
        } finally {
          try {
            unlinkSync(file);
          } catch {
            /* ignore */
          }
        }
      },
    }),
  ];
}
