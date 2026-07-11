/**
 * PolicyGuard —— 安全策略纯函数核心
 *
 * 所有写/删操作的判定都经过这里。纯函数、无 IO，便于单测。
 * safety 扩展在 pi 的 tool_call / spawnHook 钩子中调用本模块。
 *
 * 判定原则（保守）：
 * - 破坏性操作默认阻断（除非 --allow-destructive，且仍需二次确认）
 * - 写操作默认阻断（除非 --allow-write，且仍需逐次确认）
 * - 硬保护区路径永远阻断
 * - 只读放行
 */

import {
  DESTRUCTIVE_COMMAND_PATTERNS,
  DESTRUCTIVE_SQL_PATTERNS,
  PROTECTED_HOME_RELATIVE,
  PROTECTED_PATH_PATTERNS,
  WRITE_COMMAND_PATTERNS,
  type Risk,
} from "./patterns.ts";

export type { Risk };

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
}

const ALLOW_READ: PolicyDecision = {
  allow: true,
  risk: "read",
  requireConfirm: false,
  matches: [],
};

export class PolicyGuard {
  constructor(private opts: PolicyGuardOptions) {}

  /**
   * 检查 bash 命令。返回最终判定。
   * 顺序：硬保护路径 → 破坏性命令 → 危险 SQL → 写命令 → 只读放行。
   */
  checkBash(command: string): PolicyDecision {
    const matches: string[] = [];

    // 1. 提取命令中出现的路径（重定向目标、参数等），先过硬保护预检。
    //    注意：此处只拦截硬保护路径，不强制写白名单——路径出现在命令中不代表
    //    一定被写入（可能是读取）。写白名单由 WRITE_COMMAND_PATTERNS 命中后处理。
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

    // 3. 嵌入的危险 SQL
    const sqlDecision = this.checkSql(command);
    if (sqlDecision.matches.length > 0) {
      if (!sqlDecision.allow) return sqlDecision;
      // SQL 写/破坏性需确认
      if (sqlDecision.risk !== "read") return sqlDecision;
    }

    // 4. 写类命令
    for (const pat of WRITE_COMMAND_PATTERNS) {
      if (pat.pattern.test(command)) {
        matches.push(pat.name);
        if (!this.opts.allowWrite) {
          return {
            allow: false,
            risk: "write",
            requireConfirm: false,
            reason: `写操作被阻断：命中规则 ${pat.name}（需 --allow-write 并确认）`,
            matches,
          };
        }
        return {
          allow: true,
          risk: "write",
          requireConfirm: true,
          reason: `写操作，需确认：${pat.name}`,
          matches,
        };
      }
    }

    // 5. 只读放行
    return { ...ALLOW_READ, matches };
  }

  /** 检查 SQL 语句（或含 SQL 的命令） */
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
   * - 写/删 → 必须在 writePaths 白名单内
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
      // 写必须先开启 allowWrite
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
      return abs === prefix || abs.startsWith(prefix.endsWith("/") ? prefix : prefix + "/");
    });
  }

  private resolve(p: string): string {
    if (p.startsWith("~/")) p = this.opts.home + p.slice(1);
    if (p.startsWith("/")) return p;
    // 简单相对路径解析
    return this.opts.cwd.replace(/\/$/, "") + "/" + p.replace(/^\.\//, "");
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

  /** 从命令中粗略提取路径候选（重定向目标、参数等），用于硬保护预检 */
  private extractPaths(command: string): string[] {
    const paths: string[] = [];
    const push = (g: IterableIterator<RegExpMatchArray>) => {
      for (const m of g) if (m[1]) paths.push(m[1]);
    };
    push(command.matchAll(/>>?\s*(\S+)/g)); // 重定向 > file, >> file
    push(command.matchAll(/\btee\s+(?:-a\s+)?(\S+)/g)); // tee file
    push(command.matchAll(/\bof\s*=\s*(\S+)/g)); // dd of=file
    push(command.matchAll(/\s(\/[\w./-]+)/g)); // 裸绝对路径参数
    return paths;
  }
}
