/**
 * opagent-level 扩展 —— 会话内临时安全级别升降
 *
 * 场景：只读模式排查完问题、给出方案后，需要临时提权执行；执行完降回只读。
 *
 * 组成：
 * 1. /level 斜杠命令：用户交互选择级别（select 对话框），变更写入审计链
 * 2. adjust_level 自定义工具：模型可发起调级请求，但必须经用户在对话框中
 *    显式确认（模型无法自行提权）；拒绝时仅通知，不阻断会话
 * 3. 状态栏实时显示当前级别（ui.setStatus）
 * 4. before_agent_start：级别非默认时向本轮系统提示注入当前级别说明，
 *    让模型知道现在处于什么级别、完成后应建议降回
 *
 * 安全语义：
 * - 级别变更只影响 PolicyGuard 的 allowWrite/allowDestructive 门禁与沙箱开关；
 *   硬保护路径（/etc /boot /proc ~/.ssh 等）在任何级别下都保持阻断
 * - 每次变更（无论来自命令还是工具确认）都写入审计链（approver=user）
 * - 降级（提权 → 收紧）无需确认，随时可降
 */

import { Type } from 'typebox';
import { defineTool } from '@earendil-works/pi-coding-agent';
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { SAFETY_MODES, SAFETY_MODE_LABELS, SafetyLevelManager, type SafetyMode } from './level.ts';
import type { PolicyGuard } from './policy.ts';
import type { SandboxRunner } from './sandbox.ts';
import type { AuditStore } from '../audit/store.ts';

export interface LevelExtensionDeps {
  manager: SafetyLevelManager;
  guard: PolicyGuard;
  sandbox?: SandboxRunner;
  audit: AuditStore;
  /** 启动时是否由 CLI flags 显式开启（用于提示降级是否影响启动配置） */
  startupAllowWrite: boolean;
  startupAllowDestructive: boolean;
}

const STATUS_KEY = 'opagent-level';

function modeDescription(mode: SafetyMode): string {
  switch (mode) {
    case 'readonly':
      return '仅 scratch(/tmp) 与 /dev/null 可写；其余写/系统变更/破坏性操作一律阻断';
    case 'write':
      return '白名单写与系统写放行（每次仍需确认）；破坏性操作仍阻断';
    case 'write_all':
      return '写操作放行且免逐次确认（需启动时 --allow-write-all）；破坏性操作仍阻断';
    case 'destructive':
      return '写放行（逐次确认）+ 破坏性通道开启（二次确认 + 理由）';
  }
}

/** 应用级别到 guard / sandbox，并刷新状态栏 */
function applyLevel(deps: LevelExtensionDeps, ctx: ExtensionContext, mode: SafetyMode): void {
  deps.guard.setLevel(deps.manager.gates);
  deps.sandbox?.setAllowWrite(deps.manager.gates.allowWrite);
  ctx.ui.setStatus(STATUS_KEY, mode === 'readonly' ? undefined : `级别:${mode}`);
}

export function createLevelExtension(deps: LevelExtensionDeps) {
  const { manager, audit } = deps;

  /** 核心变更流程：确认 → 应用 → 审计 → 通知。返回是否变更成功 */
  async function changeLevel(
    ctx: ExtensionContext,
    mode: SafetyMode,
    approver: string,
    via: string
  ): Promise<boolean> {
    const prev = manager.current;
    if (prev === mode) {
      ctx.ui.notify(`当前已是「${SAFETY_MODE_LABELS[mode]}」，无变化`, 'info');
      return false;
    }
    // 降级（收紧）无需确认；提权需用户显式确认
    const isEscalation = SAFETY_MODES.indexOf(mode) > SAFETY_MODES.indexOf(prev);
    if (isEscalation) {
      const approved = await ctx.ui.confirm(
        '提升安全级别？',
        [
          `当前：${SAFETY_MODE_LABELS[prev]}`,
          `目标：${SAFETY_MODE_LABELS[mode]}`,
          '',
          `目标级别说明：${modeDescription(mode)}`,
          '硬保护路径（/etc /boot /proc ~/.ssh 等）仍保持阻断。',
          mode === 'write_all' && !deps.guard.writeAll
            ? '注意：启动时未开 --allow-write-all，本次切换后写操作仍会逐次确认。'
            : '所有写/破坏性操作仍逐次确认并写入审计链。',
        ]
          .filter(Boolean)
          .join('\n')
      );
      if (!approved) {
        audit.append({
          ts: Date.now(),
          tool: 'safety_level',
          input: `${prev} -> ${mode}`,
          risk: 'read',
          blocked: true,
          reason: `用户拒绝提权（via ${via}）`,
        });
        ctx.ui.notify('已取消，级别未变更', 'info');
        return false;
      }
    }
    manager.set(mode, approver, `via ${via}`);
    applyLevel(deps, ctx, mode);
    ctx.ui.notify(`安全级别：${SAFETY_MODE_LABELS[prev]} → ${SAFETY_MODE_LABELS[mode]}`, 'info');
    // write_all 的免确认门禁固定于启动 flag：未启用时明确告知实际效果
    if (mode === 'write_all' && !deps.guard.writeAll) {
      ctx.ui.notify(
        '提示：启动时未开 --allow-write-all，写操作仍会逐次确认（免确认需重启并加该参数）',
        'warning'
      );
    }
    return true;
  }

  return function levelExtension(pi: ExtensionAPI): void {
    // ---- /level 斜杠命令 ----
    pi.registerCommand('level', {
      description: '查看/切换安全级别（只读/写/破坏性）',
      getArgumentCompletions: (prefix) => {
        const items = SAFETY_MODES.filter((m) => m.startsWith(prefix)).map((m) => ({
          value: m,
          label: `${m} — ${SAFETY_MODE_LABELS[m]}`,
        }));
        return items.length > 0 ? items : null;
      },
      handler: async (args, ctx) => {
        const arg = args.trim() as SafetyMode;
        // 带参数：直接切换
        if (arg && (SAFETY_MODES as readonly string[]).includes(arg)) {
          await changeLevel(ctx, arg, 'user', '/level 命令');
          return;
        }
        if (arg) {
          ctx.ui.notify(`未知级别「${arg}」，可选：${SAFETY_MODES.join(' / ')}`, 'warning');
        }
        // 无参数：显示当前级别 + 选择框（write_all 未启用启动 flag 时标注）
        const options = SAFETY_MODES.map((m) => {
          const marker = m === manager.current ? '● ' : '  ';
          const hint =
            m === 'write_all' && !deps.guard.writeAll
              ? '（未启用：需启动时 --allow-write-all）'
              : '';
          return `${marker}${m} — ${SAFETY_MODE_LABELS[m]}${hint}`;
        });
        const selected = await ctx.ui.select(
          `当前级别：${manager.label}（${manager.current}）`,
          options
        );
        if (!selected) return;
        const mode = selected.trim().split(/\s+/)[0] as SafetyMode;
        if ((SAFETY_MODES as readonly string[]).includes(mode)) {
          await changeLevel(ctx, mode, 'user', '/level 命令');
        }
      },
    });

    // ---- adjust_level 工具：模型发起，用户确认 ----
    pi.registerTool(
      defineTool({
        name: 'adjust_level',
        label: '调整安全级别',
        description:
          '请求临时调整会话安全级别（只读/写/写免确认/破坏性）。用于只读排查完成、给出方案后需要执行的场景。' +
          '调用后会弹出确认对话框，必须由用户显式确认才会生效；用户拒绝时你会收到拒绝通知。' +
          '执行完方案后应主动请求降回 readonly。硬保护路径在任何级别下都保持阻断。',
        parameters: Type.Object({
          mode: Type.Union(
            SAFETY_MODES.map((m) => Type.Literal(m)),
            {
              description:
                '目标级别：readonly=只读（默认）/ write=允许写（逐次确认）/ write_all=写免确认（需启动时 --allow-write-all）/ destructive=允许破坏性',
            }
          ),
          reason: Type.String({ description: '调级理由（展示给用户并写入审计）' }),
        }),
        execute: async (_id, params, _signal, _onUpdate, ctx) => {
          const mode = params.mode as SafetyMode;
          const reason = String(params.reason ?? '').trim();
          if (!reason) {
            return {
              content: [{ type: 'text' as const, text: '必须填写调级理由' }],
              details: {},
              isError: true,
            };
          }
          const prev = manager.current;
          if (prev === mode) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: `当前已是「${SAFETY_MODE_LABELS[mode]}」，无需调整`,
                },
              ],
              details: {},
            };
          }
          // 提权：弹确认框（理由展示给用户）；降级：直接生效
          const isEscalation = SAFETY_MODES.indexOf(mode) > SAFETY_MODES.indexOf(prev);
          let approved = true;
          if (isEscalation && ctx.hasUI) {
            approved = await ctx.ui.confirm(
              '模型请求提升安全级别',
              [
                `理由：${reason}`,
                '',
                `当前：${SAFETY_MODE_LABELS[prev]}`,
                `目标：${SAFETY_MODE_LABELS[mode]}`,
                `说明：${modeDescription(mode)}`,
                mode === 'write_all' && !deps.guard.writeAll
                  ? '注意：启动时未开 --allow-write-all，本次切换后写操作仍会逐次确认。'
                  : '',
                '',
                '硬保护路径仍保持阻断；所有写/破坏性操作仍逐次确认并写入审计链。',
              ]
                .filter(Boolean)
                .join('\n')
            );
          } else if (isEscalation && !ctx.hasUI) {
            // 无 UI（print 模式）无法确认 → 拒绝提权
            approved = false;
          }
          audit.append({
            ts: Date.now(),
            tool: 'safety_level',
            input: `${prev} -> ${mode}`,
            risk: 'read',
            blocked: !approved,
            approver: approved ? 'user' : undefined,
            reason: `adjust_level 工具：${reason}`,
          });
          if (!approved) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: `用户拒绝了本次提权请求（${SAFETY_MODE_LABELS[prev]} → ${SAFETY_MODE_LABELS[mode]}）。请继续在当前级别下工作，或改用只读方式汇报方案。`,
                },
              ],
              details: {},
            };
          }
          manager.set(mode, 'user', `adjust_level 工具：${reason}`);
          applyLevel(deps, ctx, mode);
          const writeAllHint =
            mode === 'write_all' && !deps.guard.writeAll
              ? '注意：启动时未开 --allow-write-all，写操作仍会逐次确认。'
              : '';
          return {
            content: [
              {
                type: 'text' as const,
                text:
                  `安全级别已调整：${SAFETY_MODE_LABELS[prev]} → ${SAFETY_MODE_LABELS[mode]}（已写入审计链）。` +
                  (writeAllHint ? `\n${writeAllHint}` : '') +
                  (mode !== 'readonly'
                    ? '方案执行完成后，请调用 adjust_level(mode=readonly) 降回只读。'
                    : ''),
              },
            ],
            details: {},
          };
        },
      })
    );

    // ---- 状态栏 + 会话启动提示 ----
    pi.on('session_start', async (_event, ctx) => {
      applyLevel(deps, ctx, manager.current);
    });

    // ---- 每轮 agent 启动前注入当前级别说明（级别非默认时） ----
    pi.on('before_agent_start', async (_event, _ctx) => {
      const mode = manager.current;
      if (mode === 'readonly') return undefined;
      const gates = manager.gates;
      const writeAllNote = deps.guard.writeAll
        ? '- 已启用 --allow-write-all：写操作免逐次确认（硬保护路径与破坏性门禁仍生效）。'
        : '';
      const note = [
        '',
        '# 当前安全级别（会话内临时调整）',
        '',
        `- 级别：${mode}（${SAFETY_MODE_LABELS[mode]}）`,
        `- allowWrite=${gates.allowWrite}，allowDestructive=${gates.allowDestructive}`,
        `- ${modeDescription(mode)}`,
        writeAllNote,
        '- 这是用户批准的临时提权：完成后应主动调用 adjust_level(mode="readonly") 降回只读。',
      ]
        .filter(Boolean)
        .join('\n');
      return { systemPrompt: _event.systemPrompt + note };
    });
  };
}
