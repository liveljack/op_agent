/**
 * OpAgent 配置
 *
 * 配置来源优先级（高 → 低）：
 *   1. CLI overrides（--allow-write 等）
 *   2. process.env（真实环境变量 + Bun 自动加载的 cwd .env）
 *   3. ~/.op_agent/.env 全局配置文件（仅填充 process.env 中缺失的键）
 *
 * DeepSeek 为默认模型；pi 原生支持 DeepSeek provider，DEEPSEEK_API_KEY 即可鉴权。
 */

import { homedir } from "node:os";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const DEFAULT_AGENT_DIR_NAME = ".op_agent";

export interface OpAgentConfig {
  /** 模型标识，格式 provider/model（pi resolveCliModel 解析），默认 deepseek */
  model: string;
  /** DeepSeek / 其它 provider 的 API key */
  apiKey?: string;
  /** opagent 全局配置目录（默认 ~/.op_agent） */
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

/**
 * 解析 .env 文件并把缺失的键填入 process.env。
 * 已存在于 process.env 的键不覆盖（保证 process.env 优先）。
 *
 * 解析规则：
 * - 跳过空行与 # 注释行
 * - 支持 `export KEY=VALUE` 形式
 * - 去除值两侧成对引号
 * - 仅在 key 不在 process.env 时写入
 *
 * 文件不存在时静默返回（全局 .env 可选）。
 */
export function loadEnvFile(envPath: string): { loaded: number; path: string } {
  if (!existsSync(envPath)) return { loaded: 0, path: envPath };
  const text = readFileSync(envPath, "utf-8");
  let loaded = 0;
  for (const raw of text.split("\n")) {
    let line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("export ")) line = line.slice(7).trim();
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    // 去除注释（仅对未加引号的值）
    if (!val.startsWith('"') && !val.startsWith("'")) {
      const hash = val.indexOf(" #");
      if (hash >= 0) val = val.slice(0, hash).trim();
    }
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (key && !(key in process.env)) {
      process.env[key] = val;
      loaded++;
    }
  }
  return { loaded, path: envPath };
}

export function loadConfig(overrides: Partial<OpAgentConfig> = {}): OpAgentConfig {
  const home = homedir();
  const cwd = overrides.cwd ?? process.cwd();

  // agentDir 优先级：overrides > OPAGENT_DIR(真实 env) > ~/.op_agent
  // 先确定 agentDir，再从 <agentDir>/.env 兜底加载缺失环境变量
  const agentDir =
    overrides.agentDir ?? process.env.OPAGENT_DIR ?? join(home, DEFAULT_AGENT_DIR_NAME);

  // 全局 .env 兜底：仅填充 process.env 中缺失的键（process.env 优先）
  loadEnvFile(join(agentDir, ".env"));

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
