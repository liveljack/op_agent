/**
 * run_script —— 受控脚本执行工具
 *
 * 安全流程（在 safety 扩展的 tool_call 已做命令级策略校验之后）：
 * 1. 语法检查：bash -n（或 python3 -m py_compile），不过则拒绝执行
 * 2. dry_run=true：仅返回脚本预览，不执行
 * 3. 执行：默认（!allowWrite）模式下在 OS 沙箱中执行（仅 scratch 区与 /dev/null 可写，
 *    读/执行/网络不受限）；沙箱不可用时按策略回退（auto）或拒绝（require）
 *
 * 决策（阻断/确认）由 safety 扩展统一处理并写入审计；本工具负责语法校验与沙箱执行。
 */

import { Type } from "typebox";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { $ } from "bun";
import { realpathSync, rmSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { SandboxRunner } from "../safety/sandbox.ts";

const SCRIPT_TIMEOUT_MS = 60_000;

export interface ScriptToolDeps {
  /** OS 沙箱（默认模式注入；未注入则直接执行，如单测场景） */
  sandbox?: SandboxRunner;
  /** scratch 临时区根（临时脚本目录基座，与 PolicyGuard 配置一致；默认 /tmp） */
  scratchPaths?: string[];
}

function textOut(s: string, isError = false) {
  return { content: [{ type: "text" as const, text: s }], details: {}, isError };
}

export function createScriptTools(deps: ScriptToolDeps = {}) {
  // 临时目录基座：scratch 根的 realpath 形态（macOS /tmp → /private/tmp），
  // 保证脚本目录一定落在沙箱可写区内
  const scratchBase = (() => {
    const p = deps.scratchPaths?.[0] ?? "/tmp";
    try {
      return realpathSync(p);
    } catch {
      return p;
    }
  })();

  return [
    defineTool({
      name: "run_script",
      label: "执行脚本",
      description:
        "受控执行生成的 bash/python 脚本。自动先做语法检查（bash -n / py_compile）；" +
        "建议先用 dry_run=true 预览，确认无误后再执行。脚本内容由安全策略层校验，" +
        "破坏性/写命令会被阻断或要求确认；默认模式下在 OS 沙箱中执行，" +
        "仅 /tmp 临时区与 /dev/null 可写。请勿用 bash 直接执行 /tmp 下的脚本，应使用本工具。",
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
        const dir = mkdtempSync(join(scratchBase, "opagent-"));
        const ext = interpreter === "python3" ? ".py" : ".sh";
        const file = join(dir, `script${ext}`);
        writeFileSync(file, script, { mode: 0o600 });

        try {
          // 1. 语法检查（只读语义，py_compile 的 __pycache__ 落在 /tmp 脚本目录内）
          const checkCmd =
            interpreter === "python3"
              ? $`python3 -m py_compile ${file}`.quiet().nothrow()
              : $`bash -n ${file}`.quiet().nothrow();
          const checkRes = await checkCmd;
          if (checkRes.exitCode !== 0) {
            const err = checkRes.stderr.toString().trim() || "语法错误";
            return textOut(`语法检查失败，已拒绝执行：\n${err}`, true);
          }

          // 2. 组装执行命令：默认模式下用 OS 沙箱包裹
          const baseArgv = interpreter === "python3" ? ["python3", file] : ["bash", file];
          let argv = baseArgv;
          const sandbox = deps.sandbox;
          if (sandbox?.shouldSandbox()) {
            const info = await sandbox.info();
            if (info.kind === "none") {
              if (sandbox.policy === "require") {
                sandbox.auditRefused("run_script", info);
                return textOut(
                  `OS 沙箱不可用，已拒绝执行（OPAGENT_SANDBOX=require）：${info.detail}`,
                  true,
                );
              }
              sandbox.auditFallback("run_script", info);
            } else {
              const wrapped = await sandbox.wrap(baseArgv);
              if (wrapped.refused) {
                sandbox.auditRefused("run_script", info);
                return textOut(`OS 沙箱包裹失败，已拒绝执行：${wrapped.reason}`, true);
              }
              argv = wrapped.argv;
              sandbox.auditEnabled("run_script", info);
            }
          }

          // 3. 执行（统一 Bun.spawn，TMPDIR 指向脚本目录：临时文件全部落在沙箱可写区）
          const proc = Bun.spawn(argv, {
            stdout: "pipe",
            stderr: "pipe",
            env: { ...process.env, TMPDIR: dir },
          });
          const timer = setTimeout(() => proc.kill(), SCRIPT_TIMEOUT_MS);
          let stdout = "";
          let stderr = "";
          let exitCode: number;
          try {
            [stdout, stderr, exitCode] = await Promise.all([
              new Response(proc.stdout).text(),
              new Response(proc.stderr).text(),
              proc.exited,
            ]);
          } finally {
            clearTimeout(timer);
          }
          const out = (stdout + (stderr ? "\n[stderr]\n" + stderr : "")).trim();
          if (exitCode !== 0) {
            return textOut(`执行失败（exit ${exitCode}）：\n${out || "(无输出)"}`, true);
          }
          return textOut(out || "(无输出)");
        } catch (e: any) {
          return textOut(`执行失败：${e.message}`, true);
        } finally {
          try {
            rmSync(dir, { recursive: true, force: true });
          } catch {
            /* ignore */
          }
        }
      },
    }),
  ];
}
