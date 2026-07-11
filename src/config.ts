/**
 * OpAgent 配置
 *
 * 从环境变量读取，DeepSeek 为默认模型。
 * pi 原生支持 DeepSeek provider，DEEPSEEK_API_KEY 即可鉴权。
 */

import { homedir } from "node:os";
import { join } from "node:path";

export interface OpAgentConfig {
  /** 模型标识，格式 provider/model（pi resolveCliModel 解析），默认 deepseek */
  model: string;
  /** DeepSeek / 其它 provider 的 API key */
  apiKey?: string;
  /** opagent 全局配置目录（替代 ~/.pi/agent，独立隔离） */
  agentDir: string;
  /** 工作目录 */
  cwd: string;
  /** 是否允许写操作 */
  allowWrite: boolean;
  /** 是否允许破坏性操作 */
  allowDestructive: boolean;
  /** 写操作路径白名单（绝对路径前缀） */
  writePaths: string[];
  /** 审计 DB 路径 */
  auditDbPath: string;
  /** 内置技能目录 */
  skillsDir: string;
  /** 是否启用 LLM 语义审计（--llm_audit） */
  llmAudit: boolean;
  /** LLM 审计端点（OpenAI 兼容），默认 DeepSeek */
  auditBaseUrl: string;
  /** LLM 审计模型 */
  auditModel: string;
  /** LLM 审计 API key */
  auditApiKey?: string;
  /** 用户 home */
  home: string;
}

export function loadConfig(overrides: Partial<OpAgentConfig> = {}): OpAgentConfig {
  const home = homedir();
  const cwd = overrides.cwd ?? process.cwd();
  const agentDir = overrides.agentDir ?? process.env.OPAGENT_DIR ?? join(home, ".opagent");

  const allowWrite = overrides.allowWrite ?? process.env.OPAGENT_ALLOW_WRITE === "1";
  const allowDestructive =
    overrides.allowDestructive ?? process.env.OPAGENT_ALLOW_DESTRUCTIVE === "1";

  // 写白名单：默认工作区目录；可通过 OPAGENT_WRITE_PATHS（冒号分隔）扩展
  const writePathsEnv = process.env.OPAGENT_WRITE_PATHS ?? "";
  const writePaths = [
    join(cwd, "workspace"),
    ...writePathsEnv.split(":").filter(Boolean),
  ];

  return {
    model: overrides.model ?? process.env.OPAGENT_MODEL ?? "deepseek/deepseek-v4-flash",
    apiKey:
      overrides.apiKey ??
      process.env.DEEPSEEK_API_KEY ??
      process.env.OPAGENT_API_KEY,
    agentDir,
    cwd,
    allowWrite,
    allowDestructive,
    writePaths: overrides.writePaths ?? writePaths,
    auditDbPath: overrides.auditDbPath ?? process.env.OPAGENT_AUDIT_DB ?? join(agentDir, "audit.db"),
    skillsDir: overrides.skillsDir ?? join(cwd, "skills"),
    llmAudit: overrides.llmAudit ?? process.env.OPAGENT_LLM_AUDIT === "1",
    auditBaseUrl:
      overrides.auditBaseUrl ?? process.env.OPAGENT_AUDIT_BASE_URL ?? "https://api.deepseek.com",
    auditModel: overrides.auditModel ?? process.env.OPAGENT_AUDIT_MODEL ?? "deepseek-chat",
    auditApiKey:
      overrides.auditApiKey ??
      process.env.OPAGENT_AUDIT_API_KEY ??
      process.env.DEEPSEEK_API_KEY,
    home,
  };
}
