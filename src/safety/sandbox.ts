/**
 * OS 沙箱 —— run_script 的进程级写隔离（安全模型第四层）
 *
 * 默认只读模式下，run_script 生成的脚本在 OS 沙箱中执行：
 * 只允许写 scratch 临时区（默认 /tmp）与 /dev/null，读/执行/网络不受限
 * （只读分析是核心用例，限制只在写维度）。
 *
 * - macOS：sandbox-exec（SBPL profile；Apple 标记 deprecated 但仍工作，探测回退为其移除兜底）
 * - Linux：bwrap（bubblewrap；多数发行版默认未装，apt install bubblewrap）
 * - 均不可用：auto 策略回退模式层执行 + 审计警告；require 策略拒绝执行
 *
 * 沙箱仅默认（!allowWrite）模式启用：allowWrite 模式每次写已有人工确认，
 * 沙箱强制反而可能把确认过的脚本截断在半执行状态。
 */

import { realpathSync } from 'node:fs';
import type { AuditStore } from '../audit/store.ts';

export type SandboxKind = 'sandbox-exec' | 'bwrap' | 'none';
export type SandboxPolicy = 'auto' | 'require' | 'off';

export interface SandboxInfo {
  kind: SandboxKind;
  detail: string;
}

/** 探测执行器（测试可注入 mock）；exitCode 0 视为可用，throw 视为不可用 */
export type ProbeRunner = (argv: string[]) => Promise<{ exitCode: number }>;

const defaultProbe: ProbeRunner = async (argv) => {
  const proc = Bun.spawn(argv, { stdout: 'ignore', stderr: 'ignore' });
  const exitCode = await proc.exited;
  return { exitCode };
};

/** realpath 解析（scratch 根的词法/实路径并集用） */
type RealpathFn = (p: string) => string | null;

const defaultRealpath: RealpathFn = (p) => {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
};

/**
 * macOS sandbox-exec profile：读/执行/网络全放行，仅写受限。
 * SBPL 中带 subpath/literal 过滤的规则比宽泛规则更具体、优先生效。
 * /dev/dtracehelper 是 dyld 进程启动的已知必需写。
 */
export function buildMacProfile(writableRoots: string[]): string {
  const allowExprs = writableRoots.map((r) => `(subpath "${r}")`).join('\n    ');
  return [
    '(version 1)',
    '(allow default)',
    '(deny file-write*)',
    '(allow file-write*',
    '    (literal "/dev/null")',
    '    (literal "/dev/dtracehelper")',
    `    ${allowExprs}`,
    ')',
  ].join('\n');
}

/** Linux bwrap 参数：全系统只读挂载，scratch 根可写，独立 /dev 与 /proc */
export function buildBwrapArgs(writableRoots: string[], argv: string[]): string[] {
  const args: string[] = ['--ro-bind', '/', '/'];
  for (const r of writableRoots) {
    args.push('--bind', r, r);
  }
  args.push(
    '--dev',
    '/dev',
    '--proc',
    '/proc',
    '--tmpfs',
    '/dev/shm',
    '--new-session',
    '--die-with-parent',
    '--',
    ...argv
  );
  return args;
}

/** 探测可用沙箱：先 sandbox-exec（macOS），后 bwrap（Linux），进程级缓存由调用方管理 */
export async function detectSandbox(runner: ProbeRunner = defaultProbe): Promise<SandboxInfo> {
  try {
    const r = await runner(['sandbox-exec', '-p', '(version 1)(allow default)', '/usr/bin/true']);
    if (r.exitCode === 0) return { kind: 'sandbox-exec', detail: 'macOS sandbox-exec 可用' };
  } catch {
    /* 未安装（非 macOS）→ 尝试 bwrap */
  }
  try {
    const r = await runner([
      'bwrap',
      '--ro-bind',
      '/',
      '/',
      '--dev',
      '/dev',
      '--proc',
      '/proc',
      '--tmpfs',
      '/dev/shm',
      '/bin/true',
    ]);
    if (r.exitCode === 0) return { kind: 'bwrap', detail: 'Linux bwrap 可用' };
  } catch {
    /* 未安装 */
  }
  return {
    kind: 'none',
    detail: 'sandbox-exec / bwrap 均不可用（macOS 内置前者；Linux 可 apt install bubblewrap）',
  };
}

export interface SandboxRunnerDeps {
  policy: SandboxPolicy;
  allowWrite: boolean;
  /** scratch 临时区根（与 PolicyGuard 配置一致） */
  scratchPaths: string[];
  audit: AuditStore;
  /** 探测器注入（测试） */
  probe?: ProbeRunner;
  /** realpath 注入（测试） */
  realpath?: RealpathFn;
}

/** 包装结果：refused 时须拒绝执行 */
export type WrapResult = { refused: false; argv: string[] } | { refused: true; reason: string };

export class SandboxRunner {
  private cachedInfo?: Promise<SandboxInfo>;
  /** 沙箱可写根：scratchPaths 词法 + realpath 双形态并集（macOS /tmp 与 /private/tmp） */
  readonly writableRoots: string[];
  /** 沙箱策略（script.ts 按 require 决定不可用时拒绝） */
  readonly policy: SandboxPolicy;
  /** 运行时可变：会话内调级（/level 或 adjust_level）时同步更新 */
  private allowWriteFlag: boolean;

  constructor(private deps: SandboxRunnerDeps) {
    this.policy = deps.policy;
    this.allowWriteFlag = deps.allowWrite;
    const rp = deps.realpath ?? defaultRealpath;
    const roots = new Set<string>();
    for (const p of deps.scratchPaths) {
      roots.add(p);
      const real = rp(p);
      if (real) roots.add(real);
    }
    this.writableRoots = [...roots];
  }

  /** 会话内调级时同步沙箱开关（写模式升级后沙箱停用，降级后恢复） */
  setAllowWrite(allowWrite: boolean): void {
    this.allowWriteFlag = allowWrite;
  }

  /** 探测结果（进程级缓存） */
  info(): Promise<SandboxInfo> {
    if (!this.cachedInfo) this.cachedInfo = detectSandbox(this.deps.probe);
    return this.cachedInfo;
  }

  /** 是否应启用沙箱：默认（!allowWrite）模式且策略非 off */
  shouldSandbox(): boolean {
    return this.deps.policy !== 'off' && !this.allowWriteFlag;
  }

  /** 沙箱是否实际生效（应启用且探测可用）——extension 用于 run_script 的 sandboxed 上下文 */
  async sandboxActive(): Promise<boolean> {
    if (!this.shouldSandbox()) return false;
    return (await this.info()).kind !== 'none';
  }

  /**
   * 包裹执行命令。前提：shouldSandbox() 为 true 且 info().kind !== "none"
   * （kind 为 none 时由调用方按 policy 决定回退或拒绝）。
   */
  async wrap(argv: string[]): Promise<WrapResult> {
    const info = await this.info();
    switch (info.kind) {
      case 'sandbox-exec':
        return {
          refused: false,
          argv: ['sandbox-exec', '-p', buildMacProfile(this.writableRoots), ...argv],
        };
      case 'bwrap':
        return { refused: false, argv: buildBwrapArgs(this.writableRoots, argv) };
      default:
        return {
          refused: true,
          reason: `OS 沙箱不可用（${info.detail}）`,
        };
    }
  }

  // ---- 审计 ----

  auditEnabled(tool: string, info: SandboxInfo) {
    this.deps.audit.append({
      ts: Date.now(),
      tool: 'sandbox',
      input: tool,
      result: `enabled:${info.kind}`,
      risk: 'read',
      blocked: false,
      reason: `${tool} 在 OS 沙箱中执行`,
    });
  }

  auditFallback(tool: string, info: SandboxInfo) {
    this.deps.audit.append({
      ts: Date.now(),
      tool: 'sandbox',
      input: tool,
      result: `fallback:${info.kind}`,
      risk: 'write',
      blocked: false,
      reason: `OS 沙箱不可用（${info.detail}），回退模式层执行——深度防御缺失，建议安装 bwrap 或 sandbox-exec`,
    });
  }

  auditRefused(tool: string, info: SandboxInfo) {
    this.deps.audit.append({
      ts: Date.now(),
      tool: 'sandbox',
      input: tool,
      result: `refused:${info.kind}`,
      risk: 'write',
      blocked: true,
      reason: `OS 沙箱不可用（${info.detail}），OPAGENT_SANDBOX=require 已拒绝执行`,
    });
  }
}
