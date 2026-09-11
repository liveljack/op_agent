/**
 * PolicyGuard —— 安全策略核心
 *
 * 所有写/删操作的判定都经过这里。除注入的 realpath（只读探测符号链接，可 mock 测试）
 * 外无 IO、无状态变化。
 * safety 扩展在 pi 的 tool_call / spawnHook 钩子中调用本模块。
 *
 * 判定原则（保守）：
 * - 破坏性操作默认阻断（除非 --allow-destructive，且仍需二次确认）
 * - 系统状态变更（服务/进程/包管理/挂载/crontab/数据源写）默认阻断，永不享受 scratch 豁免
 * - 文件写默认仅 scratch 临时区（默认 /tmp）与 /dev/null（丢弃输出）放行且免确认
 * - 写白名单路径需 --allow-write 且逐次确认
 * - 硬保护区路径永远阻断
 * - symlink 逃逸（scratch 内软链指向外部）经 realpath 解析拦截
 * - 只读放行
 */

import { realpathSync } from "node:fs";
import {
  DATA_SOURCE_WRITE_PATTERNS,
  DESTRUCTIVE_COMMAND_PATTERNS,
  DESTRUCTIVE_SQL_PATTERNS,
  NULL_DEVICE,
  PROTECTED_HOME_RELATIVE,
  PROTECTED_PATH_PATTERNS,
  WRITE_COMMAND_PATTERNS,
  WRITE_SQL_PATTERNS,
  type Risk,
} from "./patterns.ts";

export type { Risk };

/** 写目标落区：discard=/dev/null 丢弃；scratch=临时区；whitelist=写白名单；outside=其余 */
export type WriteZone = "discard" | "scratch" | "whitelist" | "outside";

/** realpath 注入接口：返回 null 表示路径不存在/无法解析 */
export type RealpathFn = (p: string) => string | null;

const defaultRealpath: RealpathFn = (p) => {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
};

/** 可直接作为脚本的解释器（scratch 内脚本禁止直接执行，须走 run_script 沙箱） */
const INTERPRETER_CMDS = new Set([
  "bash",
  "sh",
  "zsh",
  "dash",
  "ksh",
  "python",
  "python3",
  "node",
  "ruby",
  "perl",
]);

/** 命令前置包装器剥离（env/nohup/timeout/exec/nice/stdbuf/sudo 等） */
function stripWrappers(tokens: string[]): string[] {
  let i = 0;
  while (i < tokens.length) {
    const w = tokens[i]!;
    if (w === "env") {
      i++;
      while (i < tokens.length && /^[A-Za-z_]\w*=/.test(tokens[i]!)) i++;
      continue;
    }
    if (w === "timeout") {
      i++;
      if (i < tokens.length && /^[\d.]+[smhd]?$/.test(tokens[i]!)) i++;
      continue;
    }
    if (w === "stdbuf") {
      i++;
      while (i < tokens.length && tokens[i]!.startsWith("-")) i++;
      continue;
    }
    if (w === "nohup" || w === "exec" || w === "nice" || w === "command" || w === "sudo") {
      i++;
      continue;
    }
    break;
  }
  return tokens.slice(i);
}

function isWithin(p: string, root: string): boolean {
  return p === root || p.startsWith(root.endsWith("/") ? root : root + "/");
}

export interface PolicyDecision {
  /** 是否允许执行 */
  allow: boolean;
  /** 风险等级 */
  risk: Risk;
  /** 是否需要交互确认（y/N） */
  requireConfirm: boolean;
  /** 阻断或确认的原因 */
  reason?: string;
  /** 命中的规则名 */
  matches: string[];
  /** 写目标落区（读操作无此字段） */
  zone?: WriteZone;
}

export interface PolicyGuardOptions {
  /** 是否允许写操作（--allow-write） */
  allowWrite: boolean;
  /** 是否允许破坏性操作（--allow-destructive） */
  allowDestructive: boolean;
  /** 写操作路径白名单（绝对路径前缀） */
  writePaths: string[];
  /** 当前工作目录，用于解析相对路径 */
  cwd: string;
  /** 用户 home 目录，用于检测敏感文件 */
  home: string;
  /** scratch 临时区根路径（默认 ["/tmp"]）：免确认可写，但 symlink 不可逃逸出区 */
  scratchPaths?: string[];
  /** realpath 注入（默认 node:fs realpathSync；测试可 mock） */
  realpath?: RealpathFn;
}

/** checkBash 上下文 */
export interface CheckBashContext {
  /** 调用方已处于 OS 沙箱中（run_script 沙箱内执行）：scratch 脚本直接执行放行，边界由沙箱强制 */
  sandboxed?: boolean;
}

const ALLOW_READ: PolicyDecision = {
  allow: true,
  risk: "read",
  requireConfirm: false,
  matches: [],
};

/** 文件写目标（classifyFileWrites 提取） */
interface WriteTarget {
  intent: "redirect" | "tee" | "dd_of" | "mv" | "cp" | "ln" | "path_op";
  path: string;
  /** mv/ln 的源路径：mv 移动会删源；ln 指向外部的链即拦 */
  srcs?: string[];
}

interface ClassifiedWrites {
  targets: WriteTarget[];
  /** 目标不可解析（变量/命令替换/glob/引号不配对）→ 保守走 allowWrite 逻辑 */
  unresolved: boolean;
  /** 全部重定向均为 fd 聚合（如 cmd 2>&1），无真实文件目标 */
  dupOnlyRedirect: boolean;
}

export class PolicyGuard {
  private realpathFn: RealpathFn;
  /** scratch 根（词法 + realpath 双形态，macOS 上 /tmp 与 /private/tmp 等价） */
  private scratchRoots: string[];

  constructor(private opts: PolicyGuardOptions) {
    this.realpathFn = opts.realpath ?? defaultRealpath;
    const scratch = opts.scratchPaths ?? ["/tmp"];
    const roots = new Set<string>();
    for (const p of scratch) {
      const abs = this.resolve(p);
      roots.add(abs);
      const real = this.realpathFn(abs);
      if (real) roots.add(real);
    }
    this.scratchRoots = [...roots];
  }

  /**
   * 检查 bash 命令。返回最终判定。
   * 顺序：硬保护路径 → 破坏性命令 → 危险 SQL → scratch 脚本执行 → 写命令分区 → 只读放行。
   */
  checkBash(command: string, ctx: CheckBashContext = {}): PolicyDecision {
    const matches: string[] = [];

    // 1. 提取命令中出现的路径（重定向目标、参数等），先过硬保护预检。
    for (const p of this.extractPaths(command)) {
      const protectedDecision = this.checkProtectedPath(p);
      if (!protectedDecision.allow) {
        return protectedDecision;
      }
    }

    // 2. 破坏性命令
    for (const pat of DESTRUCTIVE_COMMAND_PATTERNS) {
      if (pat.pattern.test(command)) {
        matches.push(pat.name);
        if (!this.opts.allowDestructive) {
          return {
            allow: false,
            risk: "destructive",
            requireConfirm: false,
            reason: `破坏性命令被阻断：命中规则 ${pat.name}（需 --allow-destructive 并通过二次确认）`,
            matches,
          };
        }
        return {
          allow: true,
          risk: "destructive",
          requireConfirm: true,
          reason: `破坏性操作，需二次确认：${pat.name}`,
          matches,
        };
      }
    }

    // 3. 嵌入的 SQL（destructive 优先于 write）
    const sqlDecision = this.checkSql(command);
    if (sqlDecision.matches.length > 0) {
      if (!sqlDecision.allow) return sqlDecision;
      if (sqlDecision.risk !== "read") return sqlDecision;
    }

    // 3.5 直接执行 scratch 脚本：内容未经逐条校验，默认禁止，须走 run_script（沙箱内执行）
    const scratchExecHits = this.detectScratchScriptExec(command);
    if (scratchExecHits.length > 0) {
      matches.push("scratch_script_exec");
      if (ctx.sandboxed) {
        return {
          allow: true,
          risk: "write",
          requireConfirm: false,
          zone: "scratch",
          reason: `沙箱内执行 scratch 脚本（写边界由 OS 沙箱强制）：${scratchExecHits.join(", ")}`,
          matches,
        };
      }
      if (!this.opts.allowWrite) {
        return {
          allow: false,
          risk: "write",
          requireConfirm: false,
          reason:
            `默认模式禁止直接执行 /tmp 脚本（内容未经校验）：${scratchExecHits[0]}。` +
            `请使用 run_script 工具（OS 沙箱内执行）`,
          matches,
        };
      }
      return {
        allow: true,
        risk: "write",
        requireConfirm: true,
        reason: `直接执行 scratch 脚本，需确认：${scratchExecHits.join(", ")}`,
        matches,
      };
    }

    // 4. 写类命令：全量收集命中，按 kind 分流
    const sysHits: string[] = [];
    const fileHits: string[] = [];
    for (const pat of WRITE_COMMAND_PATTERNS) {
      if (pat.pattern.test(command)) (pat.kind === "file" ? fileHits : sysHits).push(pat.name);
    }
    for (const pat of DATA_SOURCE_WRITE_PATTERNS) {
      if (pat.pattern.test(command)) sysHits.push(pat.name);
    }
    if (sysHits.length === 0 && fileHits.length === 0) {
      return { ...ALLOW_READ, matches };
    }
    matches.push(...sysHits, ...fileHits);

    /** 系统写/越界写：走 allowWrite 门禁（默认阻断，开启后逐次确认） */
    const denyWrite = (target?: string): PolicyDecision => {
      const hint = target ? `（越界目标 ${target}）` : "";
      if (!this.opts.allowWrite) {
        return {
          allow: false,
          risk: "write",
          requireConfirm: false,
          reason: `写操作被阻断：命中规则 ${[...sysHits, ...fileHits].join(", ")}${hint}（需 --allow-write 并确认）`,
          matches,
        };
      }
      return {
        allow: true,
        risk: "write",
        requireConfirm: true,
        reason: `写操作，需确认：${[...sysHits, ...fileHits].join(", ")}${hint}`,
        matches,
      };
    };

    // 系统状态变更（服务/进程/包管理/挂载/crontab/数据源写）：永不享受 scratch 豁免
    if (sysHits.length > 0) return denyWrite();

    // 文件写：提取全部写目标，按 discard(/dev/null) / scratch / normal 分区
    const { targets, unresolved, dupOnlyRedirect } = this.classifyFileWrites(command);
    if (unresolved) return denyWrite();
    if (targets.length === 0) {
      // 纯 fd 聚合（cmd 2>&1）无文件目标 → 读语义
      if (dupOnlyRedirect && fileHits.every((h) => h === "redirect_write")) {
        return { ...ALLOW_READ, matches };
      }
      return denyWrite();
    }
    // 目标硬保护检查（解释器引号内路径等预检未覆盖的形态）
    for (const t of targets) {
      const pd = this.checkProtectedPath(t.path);
      if (!pd.allow) return pd;
      if (t.srcs) {
        for (const s of t.srcs) {
          const psd = this.checkProtectedPath(s);
          if (!psd.allow) return psd;
        }
      }
    }
    const zones = targets.map((t) => this.zoneOf(t));
    const normalIdx = zones.indexOf("normal");
    if (normalIdx >= 0) return denyWrite(targets[normalIdx]?.path);
    if (zones.includes("scratch")) {
      return {
        allow: true,
        risk: "write",
        requireConfirm: false,
        zone: "scratch",
        reason: "scratch 临时区写入（/tmp），免确认",
        matches,
      };
    }
    // 全部为 /dev/null 丢弃：无状态变化，读语义（inspect 只读工具可直接使用）
    return {
      allow: true,
      risk: "read",
      requireConfirm: false,
      zone: "discard",
      reason: "输出丢弃至 /dev/null，无状态变化",
      matches: ["discard", ...matches],
    };
  }

  /** 检查 SQL 语句（或含 SQL 的命令）：destructive 优先，其次写 SQL（数据源只读） */
  checkSql(sql: string): PolicyDecision {
    const matches: string[] = [];
    for (const pat of DESTRUCTIVE_SQL_PATTERNS) {
      if (pat.pattern.test(sql)) {
        matches.push(pat.name);
        if (!this.opts.allowDestructive) {
          return {
            allow: false,
            risk: "destructive",
            requireConfirm: false,
            reason: `危险 SQL 被阻断：${pat.name}（需 --allow-destructive 并通过二次确认）`,
            matches,
          };
        }
        return {
          allow: true,
          risk: "destructive",
          requireConfirm: true,
          reason: `破坏性 SQL，需二次确认：${pat.name}`,
          matches,
        };
      }
    }
    for (const pat of WRITE_SQL_PATTERNS) {
      if (pat.pattern.test(sql)) {
        matches.push(pat.name);
        if (!this.opts.allowWrite) {
          return {
            allow: false,
            risk: "write",
            requireConfirm: false,
            reason: `写 SQL 被阻断：${pat.name}（数据源只读，需 --allow-write 并确认）`,
            matches,
          };
        }
        return {
          allow: true,
          risk: "write",
          requireConfirm: true,
          zone: "outside",
          reason: `写 SQL，需确认：${pat.name}`,
          matches,
        };
      }
    }
    return { ...ALLOW_READ, matches };
  }

  /** 检查 write 工具目标路径 */
  checkWritePath(targetPath: string): PolicyDecision {
    return this.checkPath(targetPath, "write");
  }

  /** 检查 edit 工具目标路径 */
  checkEditPath(targetPath: string): PolicyDecision {
    return this.checkPath(targetPath, "write");
  }

  /** 检查删除目标路径 */
  checkDeletePath(targetPath: string): PolicyDecision {
    const decision = this.checkPath(targetPath, "delete");
    // 删除一律视为 destructive
    if (decision.allow) {
      if (!this.opts.allowDestructive) {
        return {
          allow: false,
          risk: "destructive",
          requireConfirm: false,
          reason: "删除操作被阻断（需 --allow-destructive 并通过二次确认）",
          matches: decision.matches,
        };
      }
      return {
        allow: true,
        risk: "destructive",
        requireConfirm: true,
        reason: "删除操作，需二次确认",
        matches: decision.matches,
      };
    }
    return decision;
  }

  /**
   * 路径判定的内部实现。
   * - 硬保护区 → 永远阻断（destructive）
   * - 写：scratch 临时区免确认放行；白名单需 allowWrite + 确认
   * - 删 → 必须在 writePaths 白名单内（scratch 删除同样走 destructive 门禁）
   */
  private checkPath(rawPath: string, intent: "write" | "delete"): PolicyDecision {
    const abs = this.resolve(rawPath);
    const matches: string[] = [];

    // 硬保护：系统路径
    for (const pat of PROTECTED_PATH_PATTERNS) {
      if (pat.test(abs)) {
        matches.push(`protected:${pat.source}`);
        return {
          allow: false,
          risk: "destructive",
          requireConfirm: false,
          reason: `硬保护路径，禁止写/删：${abs}`,
          matches,
        };
      }
    }
    // 硬保护：home 下敏感文件
    const rel = abs.startsWith(this.opts.home + "/") ? abs.slice(this.opts.home.length + 1) : "";
    const homeRel = rel ? "/" + rel : abs;
    for (const pat of PROTECTED_HOME_RELATIVE) {
      if (pat.test(homeRel) || pat.test(rel)) {
        matches.push(`protected_home:${pat.source}`);
        return {
          allow: false,
          risk: "destructive",
          requireConfirm: false,
          reason: `用户敏感文件，禁止写/删：${abs}`,
          matches,
        };
      }
    }

    if (intent === "write") {
      // scratch 临时区：免确认放行（symlink 逃逸由 isScratchPath 拦截）
      if (this.isScratchPath(abs)) {
        return {
          allow: true,
          risk: "write",
          requireConfirm: false,
          zone: "scratch",
          reason: `scratch 临时区写入：${abs}`,
          matches,
        };
      }
      // 白名单写必须先开启 allowWrite
      if (!this.opts.allowWrite) {
        return {
          allow: false,
          risk: "write",
          requireConfirm: false,
          reason: `写操作未开启（需 --allow-write）：${abs}`,
          matches,
        };
      }
      // 且必须在白名单内
      if (!this.isWithinWritePaths(abs)) {
        return {
          allow: false,
          risk: "write",
          requireConfirm: false,
          reason: `写路径不在白名单内：${abs}`,
          matches,
        };
      }
      return {
        allow: true,
        risk: "write",
        requireConfirm: true,
        zone: "whitelist",
        reason: `写操作，需确认：${abs}`,
        matches,
      };
    }

    // delete 路径已通过硬保护检查；是否在白名单内决定是否可删
    if (!this.isWithinWritePaths(abs)) {
      return {
        allow: false,
        risk: "destructive",
        requireConfirm: false,
        reason: `删除路径不在白名单内：${abs}`,
        matches,
      };
    }
    return { allow: true, risk: "destructive", requireConfirm: true, reason: `删除，需确认：${abs}`, matches };
  }

  private isWithinWritePaths(abs: string): boolean {
    if (this.opts.writePaths.length === 0) return false;
    return this.opts.writePaths.some((p) => {
      const prefix = this.resolve(p);
      return isWithin(abs, prefix);
    });
  }

  /**
   * 解析路径：~ 展开、相对路径基于 cwd，再做词法规范化（消除 . / ..，
   * 堵住 /tmp/../etc/x 与白名单穿越）。
   */
  private resolve(p: string): string {
    if (p.startsWith("~/")) p = this.opts.home + p.slice(1);
    if (p.startsWith("/")) return this.normalizeAbs(p);
    return this.normalizeAbs(this.opts.cwd.replace(/\/$/, "") + "/" + p.replace(/^\.\//, ""));
  }

  private normalizeAbs(p: string): string {
    if (!p.startsWith("/")) return p;
    const out: string[] = [];
    for (const seg of p.split("/")) {
      if (seg === "" || seg === ".") continue;
      if (seg === "..") {
        out.pop();
        continue;
      }
      out.push(seg);
    }
    return "/" + out.join("/");
  }

  /**
   * scratch 区判定：词法前缀在区内 且 realpath 解析后仍在区内。
   * - 目标是符号链指向区外（逃逸）→ false
   * - 路径不存在时逐级回退到最近存在的祖先解析（新建文件常态）
   * - 完全无法解析 → false（保守拒绝）
   */
  private isScratchPath(abs: string): boolean {
    if (this.scratchRoots.length === 0) return false;
    if (!this.scratchRoots.some((r) => isWithin(abs, r))) return false;
    const real = this.resolveRealPath(abs);
    if (real === null) return false;
    return this.scratchRoots.some((r) => isWithin(real, r));
  }

  private resolveRealPath(abs: string): string | null {
    const direct = this.realpathFn(abs);
    if (direct) return direct;
    const segs = abs.split("/").filter(Boolean);
    for (let i = segs.length - 1; i >= 1; i--) {
      const anc = "/" + segs.slice(0, i).join("/");
      const rp = this.realpathFn(anc);
      if (rp) return rp.replace(/\/$/, "") + "/" + segs.slice(i).join("/");
    }
    // 只有根可解析：根实路径 + 全部剩余段
    const rootRp = this.realpathFn("/");
    return rootRp === null ? null : rootRp.replace(/\/$/, "") + "/" + segs.join("/");
  }

  /** 写目标落区判定 */
  private zoneOf(t: WriteTarget): "discard" | "scratch" | "normal" {
    const abs = this.resolve(t.path);
    // /dev/null 豁免仅限丢弃意图（redirect/tee/dd of=）；mv 到 /dev/null 会替换设备节点，不豁免
    if ((t.intent === "redirect" || t.intent === "tee" || t.intent === "dd_of") && abs === NULL_DEVICE) {
      return "discard";
    }
    if (this.isScratchPath(abs)) {
      // mv 移动会删源、ln 指向区外即拦（堵同命令建链写链 TOCTOU）：源必须都在 scratch 内
      if ((t.intent === "mv" || t.intent === "ln") && t.srcs) {
        if (!t.srcs.every((s) => this.isScratchPath(this.resolve(s)))) return "normal";
      }
      return "scratch";
    }
    return "normal";
  }

  /**
   * 从命令中提取全部文件写目标（全局扫描，复合命令的所有目标都会入列）。
   * - 重定向（含 fd 聚合识别）、tee、dd of=、mv/cp/ln/路径操作数、解释器内路径字面量
   * - token 去引号；含变量/命令替换/glob/引号不配对 → unresolved（保守走 allowWrite 门禁）
   */
  private classifyFileWrites(command: string): ClassifiedWrites {
    const targets: WriteTarget[] = [];
    let unresolved = false;
    let dupRedirect = false;
    let nonDupRedirect = false;

    const pushTarget = (intent: WriteTarget["intent"], rawPath: string, rawSrcs?: string[]) => {
      const path = this.cleanToken(rawPath);
      if (path === null) {
        unresolved = true;
        return;
      }
      let srcs: string[] | undefined;
      if (rawSrcs) {
        srcs = [];
        for (const s of rawSrcs) {
          const c = this.cleanToken(s);
          if (c === null) {
            unresolved = true;
            return;
          }
          srcs.push(c);
        }
      }
      targets.push({ intent, path, srcs });
    };

    // a) 重定向：> / >> / 2> / &>；fd 聚合（2>&1 / >&2）不算文件目标
    for (const m of command.matchAll(/(?:\d*&?)>>?\s*([^\s;|<>]+)/g)) {
      const t = m[1]!;
      if (this.isFdDup(t)) {
        dupRedirect = true;
        continue;
      }
      nonDupRedirect = true;
      pushTarget("redirect", t);
    }

    // b) dd of=
    for (const m of command.matchAll(/\bof\s*=\s*([^\s;|&=]+)/g)) {
      pushTarget("dd_of", m[1]!);
    }

    // c) 解释器内路径字面量（python open('p','w') / node writeFileSync / ruby File.write）
    const interpPatterns = [
      /\bopen\s*\(\s*(['"])([^'"]*)\1\s*,\s*['"][awx+]/g,
      /\b(?:write|append)FileSync\s*\(\s*(['"])([^'"]*)\1/g,
      /\bfs\.writeFile\w*\s*\(\s*(['"])([^'"]*)\1/g,
      /\bFile\.(?:write|binwrite)\s*\(\s*(['"])([^'"]*)\1/g,
      /\bFile\.open\s*\(\s*(['"])([^'"]*)\1\s*,\s*['"][aw]/g,
    ];
    for (const re of interpPatterns) {
      for (const m of command.matchAll(re)) {
        pushTarget("path_op", m[2]!);
      }
    }

    // d) 段级命令解析：mv/cp/ln/touch/mkdir/rm/sed -i/chmod 等
    for (const seg of this.splitSegments(command)) {
      let tokens = this.tokenize(seg);
      if (tokens.length === 0) continue;
      tokens = stripWrappers(tokens);
      if (tokens.length === 0) continue;
      const cmd = tokens[0]!.split("/").pop()!;
      switch (cmd) {
        case "tee": {
          const ops = this.operandsOf(tokens);
          if (ops.length === 0) unresolved = true;
          else ops.forEach((o) => pushTarget("tee", o));
          break;
        }
        case "mv": {
          const ops = this.operandsOf(tokens);
          if (ops.length < 2) {
            unresolved = true;
            break;
          }
          pushTarget("mv", ops[ops.length - 1]!, ops.slice(0, -1));
          break;
        }
        case "cp":
        case "install":
        case "rsync": {
          const ops = this.operandsOf(tokens, cmd === "install" ? ["-m", "-o", "-g", "-S"] : []);
          if (ops.length < 2) {
            unresolved = true;
            break;
          }
          pushTarget("cp", ops[ops.length - 1]!);
          break;
        }
        case "ln": {
          const ops = this.operandsOf(tokens);
          if (ops.length < 2) {
            unresolved = true;
            break;
          }
          pushTarget("ln", ops[ops.length - 1]!, [ops[ops.length - 2]!]);
          break;
        }
        case "touch":
        case "mkdir":
        case "rm": {
          const ops = this.operandsOf(tokens, cmd === "touch" ? ["-t", "-d", "-r"] : []);
          if (ops.length === 0) {
            unresolved = true;
            break;
          }
          ops.forEach((o) => pushTarget("path_op", o));
          break;
        }
        case "truncate": {
          const ops = this.operandsOf(tokens, ["-s", "--size"]);
          if (ops.length === 0) {
            unresolved = true;
            break;
          }
          ops.forEach((o) => pushTarget("path_op", o));
          break;
        }
        case "sed": {
          const inplace = tokens.slice(1).some(
            (t) => t === "-i" || t.startsWith("--in-place") || /^-[a-zA-Z]*i[a-zA-Z]*$/.test(t),
          );
          if (!inplace) break;
          const ops = this.operandsOf(tokens);
          if (ops.length < 2) {
            unresolved = true;
            break;
          }
          ops.slice(1).forEach((o) => pushTarget("path_op", o)); // 首个操作数是 sed 脚本
          break;
        }
        case "chmod":
        case "chown":
        case "chgrp": {
          const ops = this.operandsOf(tokens);
          if (ops.length < 2) {
            unresolved = true;
            break;
          }
          ops.slice(1).forEach((o) => pushTarget("path_op", o)); // 首个操作数是 mode/user
          break;
        }
      }
    }

    return { targets, unresolved, dupOnlyRedirect: dupRedirect && !nonDupRedirect };
  }

  /** 检测直接执行 scratch 脚本：解释器 + scratch 路径、直接执行、source、stdin 喂入 */
  private detectScratchScriptExec(command: string): string[] {
    const hits: string[] = [];
    for (const seg of this.splitSegments(command)) {
      let tokens = this.tokenize(seg);
      if (tokens.length === 0) continue;
      tokens = stripWrappers(tokens);
      if (tokens.length === 0) continue;
      const cmd = tokens[0]!.split("/").pop()!;
      if (INTERPRETER_CMDS.has(cmd) || cmd === "source" || cmd === ".") {
        for (const arg of tokens.slice(1)) {
          if (arg.startsWith("-") || arg === "<") continue;
          const abs = this.resolve(arg);
          if (this.isScratchPath(abs)) {
            hits.push(`${cmd} ${abs}`);
            break;
          }
        }
        const lt = tokens.indexOf("<");
        if (lt >= 0 && tokens[lt + 1]) {
          const abs = this.resolve(tokens[lt + 1]!);
          if (this.isScratchPath(abs)) hits.push(`${cmd} < ${abs}`);
        }
        continue;
      }
      if (tokens[0]!.includes("/")) {
        const abs = this.resolve(tokens[0]!);
        if (this.isScratchPath(abs)) hits.push(abs);
      }
    }
    return [...new Set(hits)];
  }

  /**
   * 仅检查硬保护路径（不强制写白名单）。
   * 用于 bash 命令中路径的预检：命中保护区则阻断，否则放行交后续规则判定。
   */
  private checkProtectedPath(rawPath: string): PolicyDecision {
    const abs = this.resolve(rawPath);
    for (const pat of PROTECTED_PATH_PATTERNS) {
      if (pat.test(abs)) {
        return {
          allow: false,
          risk: "destructive",
          requireConfirm: false,
          reason: `硬保护路径，禁止操作：${abs}`,
          matches: [`protected:${pat.source}`],
        };
      }
    }
    const rel = abs.startsWith(this.opts.home + "/") ? abs.slice(this.opts.home.length + 1) : "";
    const homeRel = rel ? "/" + rel : abs;
    for (const pat of PROTECTED_HOME_RELATIVE) {
      if (pat.test(homeRel) || pat.test(rel)) {
        return {
          allow: false,
          risk: "destructive",
          requireConfirm: false,
          reason: `用户敏感文件，禁止操作：${abs}`,
          matches: [`protected_home:${pat.source}`],
        };
      }
    }
    return ALLOW_READ;
  }

  /**
   * 从命令中粗略提取路径候选（重定向目标、参数等），用于硬保护预检。
   * token 去引号（防 > "/etc/passwd" 绕过）、跳过 fd 聚合（2>&1 的 &1）。
   */
  private extractPaths(command: string): string[] {
    const paths: string[] = [];
    const push = (g: IterableIterator<RegExpMatchArray>) => {
      for (const m of g) {
        const raw = m[1];
        if (!raw) continue;
        if (this.isFdDup(raw)) continue;
        const cleaned = this.cleanToken(raw);
        if (cleaned !== null) paths.push(cleaned);
      }
    };
    push(command.matchAll(/>>?\s*([^\s;|&<>]+)/g)); // 重定向 > file, >> file（不含尾部 ; 等分隔符）
    push(command.matchAll(/\btee\s+(?:-a\s+)?(\S+)/g)); // tee file
    push(command.matchAll(/\bof\s*=\s*(\S+)/g)); // dd of=file
    push(command.matchAll(/\s(\/[\w./-]+)/g)); // 裸绝对路径参数
    return paths;
  }

  /** fd 聚合 token：&1 / 2（如 2>&1 的目标），非文件路径 */
  private isFdDup(t: string): boolean {
    return /^&?\d+$/.test(t);
  }

  /**
   * 清理 token：剥掉成对包裹引号；含变量/命令替换/glob/元字符或引号不配对 → null（不可解析）。
   */
  private cleanToken(t: string): string | null {
    if (
      (t.startsWith('"') && t.endsWith('"') && t.length > 1) ||
      (t.startsWith("'") && t.endsWith("'") && t.length > 1)
    ) {
      t = t.slice(1, -1);
    }
    if (t.length === 0) return null;
    if (/[`$()*?<>{}]/.test(t)) return null;
    return t;
  }

  /** 段级操作数提取：跳过 flag 与带值 flag 的值；'' / "" 视为 macOS sed -i 的空后缀 */
  private operandsOf(argv: string[], valueFlags: string[] = []): string[] {
    const ops: string[] = [];
    for (let i = 1; i < argv.length; i++) {
      const t = argv[i]!;
      if (t === "''" || t === '""') continue;
      if (t.startsWith("-") && t.length > 1) {
        if (valueFlags.includes(t) && i + 1 < argv.length) i++;
        continue;
      }
      ops.push(t);
    }
    return ops;
  }

  /**
   * 按命令分隔符切段（保留 token 原样）。
   * 注意：& 不在 ; 后重定向（2>&1）与 &> 聚合（&>/dev/null）处切分。
   */
  private splitSegments(command: string): string[] {
    return command.split(/;|\|\||&&|\||\n|(?<!>)&(?!\/?\d|>)/);
  }

  private tokenize(seg: string): string[] {
    return seg.trim().split(/\s+/).filter(Boolean);
  }
}
