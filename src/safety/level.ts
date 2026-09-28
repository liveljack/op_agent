/**
 * SafetyLevelManager —— 会话内运行时安全级别管理
 *
 * 设计目标：只读模式下排查完问题后，可临时提升级别执行方案，完成后降回只读。
 * 级别只能由用户显式操作（斜杠命令 /level 或 adjust_level 工具的交互确认）变更，
 * 模型无法自行提权；每次变更写入审计链。
 *
 * 级别（从低到高）：
 * - readonly     ：默认。仅 scratch(/tmp) 与 /dev/null 可写，其余写/破坏性一律阻断。
 * - write        ：白名单写 + 系统写放行（仍逐次确认）；破坏性仍阻断。
 * - destructive  ：在 write 基础上放开破坏性通道（仍需二次确认 + 理由）。
 *
 * 硬保护路径（/etc /boot /proc ~/.ssh 等）在任何级别下都保持阻断——
 * 运行时调级只影响 allowWrite / allowDestructive 两个门禁，不触碰硬保护规则。
 */

import type { AuditStore } from '../audit/store.ts';

export type SafetyMode = 'readonly' | 'write' | 'destructive';

export const SAFETY_MODES: readonly SafetyMode[] = ['readonly', 'write', 'destructive'];

export const SAFETY_MODE_LABELS: Record<SafetyMode, string> = {
  readonly: '只读（默认）',
  write: '允许写（逐次确认）',
  destructive: '允许写 + 破坏性（二次确认）',
};

export interface SafetyLevelManagerOptions {
  /** 启动级别（由 CLI flags / env 决定） */
  initialMode: SafetyMode;
  audit: AuditStore;
}

export class SafetyLevelManager {
  private mode: SafetyMode;
  private audit: AuditStore;

  constructor(opts: SafetyLevelManagerOptions) {
    this.mode = opts.initialMode;
    this.audit = opts.audit;
  }

  get current(): SafetyMode {
    return this.mode;
  }

  get label(): string {
    return SAFETY_MODE_LABELS[this.mode];
  }

  /** 当前级别下 PolicyGuard 的两个门禁值 */
  get gates(): { allowWrite: boolean; allowDestructive: boolean } {
    return {
      allowWrite: this.mode !== 'readonly',
      allowDestructive: this.mode === 'destructive',
    };
  }

  /** 变更级别并写入审计链。返回是否实际发生变化。 */
  set(mode: SafetyMode, approver: string, reason?: string): boolean {
    if (mode === this.mode) return false;
    const prev = this.mode;
    this.mode = mode;
    this.audit.append({
      ts: Date.now(),
      tool: 'safety_level',
      input: `${prev} -> ${mode}`,
      risk: 'read',
      blocked: false,
      approver,
      reason: reason ?? `安全级别变更：${SAFETY_MODE_LABELS[prev]} → ${SAFETY_MODE_LABELS[mode]}`,
    });
    return true;
  }
}

/** 由 CLI flags / env 推导启动级别（与 loadConfig 的 allowWrite/allowDestructive 一致） */
export function modeFromFlags(allowWrite: boolean, allowDestructive: boolean): SafetyMode {
  if (allowDestructive) return 'destructive';
  if (allowWrite) return 'write';
  return 'readonly';
}
