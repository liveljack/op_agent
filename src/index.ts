#!/usr/bin/env bun
/**
 * OpAgent CLI 入口
 *
 * 组装 pi coding agent SDK + OpAgent 安全/审计扩展 + 运维工具/技能，
 * 启动 pi 的 InteractiveMode（hermes/pi 风格对话框）或 print 模式。
 */

import {
  AuthStorage,
  createAgentSessionFromServices,
  createAgentSessionRuntime,
  createAgentSessionServices,
  DefaultResourceLoader,
  getAgentDir,
  InteractiveMode,
  type InlineExtension,
  ModelRegistry,
  resolveCliModel,
  runPrintMode,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";

import { loadConfig, type OpAgentConfig } from "./config.ts";
import { buildSystemPrompt } from "./prompt.ts";
import { PolicyGuard } from "./safety/policy.ts";
import { createSafetyExtension } from "./safety/extension.ts";
import { createAuditExtension } from "./audit/extension.ts";
import { createAuditStore } from "./audit/store.ts";
import { createInspectTools } from "./tools/inspect.ts";
import { createDestructiveTools } from "./tools/destructive.ts";
import { createScriptTools } from "./tools/script.ts";
import { LlmAuditor } from "./audit/llm.ts";
import { loadBuiltinSkills } from "./skills/index.ts";

interface CliArgs {
  allowWrite?: boolean;
  allowDestructive?: boolean;
  llmAudit?: boolean;
  model?: string;
  cwd?: string;
  print?: string;
  selfTest: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    selfTest: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--allow-write":
        args.allowWrite = true;
        break;
      case "--allow-destructive":
        args.allowDestructive = true;
        break;
      case "--llm_audit":
      case "--llm-audit":
        args.llmAudit = true;
        break;
      case "--model":
        args.model = argv[++i];
        break;
      case "--cwd":
        args.cwd = argv[++i];
        break;
      case "-p":
      case "--print":
        args.print = argv[++i];
        break;
      case "--self-test":
        args.selfTest = true;
        break;
      case "-h":
      case "--help":
        args.help = true;
        break;
    }
  }
  return args;
}

const HELP = `OpAgent —— 轻量化 Linux 运维 Agent

用法:
  opagent [选项]

选项:
  --allow-write             开启写操作（仍逐次确认）
  --allow-destructive       开启破坏性操作通道（仍需二次确认 + 理由）
  --llm_audit               启用 LLM 语义审计：写/破坏性命令与脚本额外过 LLM 审计
                           （与 --allow-write/--allow-destructive 配合定安全等级）
  --model <provider/model>  覆盖模型，默认 deepseek/deepseek-v4-flash
  --cwd <path>              工作目录
  -p, --print "<prompt>"    headless 单次执行（不进 TUI）
  --self-test               自检：加载配置/策略/工具/技能并打印摘要
  -h, --help                显示帮助

环境变量:
  DEEPSEEK_API_KEY          DeepSeek API 密钥
  OPAGENT_MODEL             模型 provider/model
  OPAGENT_DIR               配置目录（默认 ~/.opagent）
  OPAGENT_ALLOW_WRITE=1     等同 --allow-write
  OPAGENT_ALLOW_DESTRUCTIVE=1
  OPAGENT_LLM_AUDIT=1       等同 --llm_audit
  OPAGENT_AUDIT_BASE_URL    LLM 审计端点（默认 https://api.deepseek.com）
  OPAGENT_AUDIT_MODEL       LLM 审计模型（默认 deepseek-chat）
  OPAGENT_AUDIT_API_KEY     LLM 审计 key（默认同 DEEPSEEK_API_KEY）
  OPAGENT_WRITE_PATHS       写白名单（冒号分隔）

示例:
  DEEPSEEK_API_KEY=sk-... opagent
  DEEPSEEK_API_KEY=sk-... opagent --allow-write
  opagent --self-test
`;

/** 构建进程级共享对象：config / guard / audit / 扩展 / 工具 / 技能 */
function buildShared(args: CliArgs) {
  const config = loadConfig({
    allowWrite: args.allowWrite,
    allowDestructive: args.allowDestructive,
    llmAudit: args.llmAudit,
    model: args.model,
    cwd: args.cwd,
  });
  const guard = new PolicyGuard({
    allowWrite: config.allowWrite,
    allowDestructive: config.allowDestructive,
    writePaths: config.writePaths,
    cwd: config.cwd,
    home: config.home,
  });
  const audit = createAuditStore(config.auditDbPath);

  // LLM 审计器：仅 --llm_audit 启用且配置了 key 时生效
  const auditor = config.llmAudit
    ? new LlmAuditor({
        baseUrl: config.auditBaseUrl,
        model: config.auditModel,
        apiKey: config.auditApiKey,
      })
    : undefined;
  if (config.llmAudit && !auditor?.enabled) {
    console.warn("[opagent] --llm_audit 已启用但未配置 API key（OPAGENT_AUDIT_API_KEY/DEEPSEEK_API_KEY），LLM 审计将跳过");
  }

  const safetyLevel = {
    allowWrite: config.allowWrite,
    allowDestructive: config.allowDestructive,
  };

  const extensions: InlineExtension[] = [
    {
      name: "opagent-safety",
      factory: createSafetyExtension({ guard, audit, auditor, safetyLevel }),
    },
    { name: "opagent-audit", factory: createAuditExtension(audit) },
  ];

  const customTools = [...createInspectTools(guard), ...createScriptTools()];
  if (config.allowDestructive) {
    customTools.push(...createDestructiveTools(guard));
  }

  const builtinSkills = loadBuiltinSkills(config.skillsDir);
  return { config, guard, audit, auditor, extensions, customTools, builtinSkills };
}

/** 解析模型；失败则返回 undefined 交由 pi 兜底选第一个可用 */
function resolveModel(config: OpAgentConfig, authStorage: AuthStorage, modelRegistry: ModelRegistry) {
  const parts = config.model.split("/");
  const provider = parts[0] ?? config.model;
  const modelId = parts.slice(1).join("/") || config.model;
  if (config.apiKey) {
    try {
      authStorage.setRuntimeApiKey(provider, config.apiKey);
    } catch {
      /* provider 未知时忽略，交由 pi 兜底 */
    }
  }
  const res = resolveCliModel({
    cliModel: `${provider}/${modelId}`,
    modelRegistry,
  });
  if (res.error) {
    console.warn(`[opagent] 模型解析失败：${res.error}（将使用第一个可用模型）`);
    return undefined;
  }
  if (res.warning) console.warn(`[opagent] ${res.warning}`);
  return res.model;
}

/** 构建工具允许列表 */
function buildToolAllowlist(config: OpAgentConfig, customToolNames: string[]): string[] {
  const tools = ["read", "grep", "find", "ls", "bash", ...customToolNames];
  if (config.allowWrite) tools.push("write", "edit");
  return tools;
}

function buildRuntimeFactory(shared: ReturnType<typeof buildShared>) {
  const { config, extensions, customTools, builtinSkills } = shared;
  const authStorage = AuthStorage.create(`${config.agentDir}/auth.json`);
  const modelRegistry = ModelRegistry.create(
    authStorage,
    `${config.agentDir}/models.json`,
  );
  const settingsManager = SettingsManager.create(config.cwd, config.agentDir);

  return async ({ cwd, sessionManager, sessionStartEvent }: any) => {
    const services = await createAgentSessionServices({
      cwd,
      authStorage,
      settingsManager,
      modelRegistry,
      resourceLoaderOptions: {
        extensionFactories: extensions,
        systemPromptOverride: () => buildSystemPrompt(config),
        skillsOverride: (current: any) => ({
          skills: [...(current.skills ?? []), ...builtinSkills],
          diagnostics: current.diagnostics ?? [],
        }),
      },
    });

    const customToolNames = customTools.map((t: any) => t.name);
    const result = await createAgentSessionFromServices({
      services,
      sessionManager,
      sessionStartEvent,
      model: resolveModel(config, authStorage, modelRegistry),
      tools: buildToolAllowlist(config, customToolNames),
      customTools,
    });

    return {
      ...result,
      services,
      diagnostics: services.diagnostics,
    };
  };
}

function selfTest(shared: ReturnType<typeof buildShared>) {
  const { config, guard, audit, customTools, builtinSkills } = shared;
  console.log("=== OpAgent 自检 ===");
  console.log(`工作目录   : ${config.cwd}`);
  console.log(`配置目录   : ${config.agentDir}`);
  console.log(`模型       : ${config.model}`);
  console.log(`API Key    : ${config.apiKey ? "已设置" : "未设置"}`);
  console.log(`允许写     : ${config.allowWrite}`);
  console.log(`允许破坏性 : ${config.allowDestructive}`);
  console.log(`LLM审计    : ${config.llmAudit ? `启用 (${config.auditModel}${shared.auditor?.enabled ? "" : ", 无key跳过"})` : "关闭"}`);
  console.log(`写白名单   : ${config.writePaths.join(", ") || "（空）"}`);
  console.log(`审计 DB    : ${config.auditDbPath}`);
  console.log(`工具       : ${customTools.map((t: any) => t.name).join(", ")}`);
  console.log(`技能       : ${builtinSkills.map((s) => s.name).join(", ") || "（无）"}`);
  console.log("\n=== 策略抽测 ===");
  const cases = [
    "df -h",
    "rm -rf /tmp/x",
    "systemctl restart nginx",
    "cat /etc/shadow",
    "echo hi > /etc/passwd",
  ];
  for (const c of cases) {
    const d = guard.checkBash(c);
    const tag = d.allow ? (d.requireConfirm ? "CONFIRM" : "READ") : "BLOCKED";
    console.log(`  [${tag}] ${c}  ${d.reason ? "— " + d.reason : ""}`);
  }
  console.log(`\n审计链校验: ${audit.verify().ok ? "OK" : "损坏"}`);
  console.log("=== 自检完成 ===");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(HELP);
    return;
  }

  const shared = buildShared(args);

  if (args.selfTest) {
    selfTest(shared);
    return;
  }

  const { config } = shared;
  const runtime = await createAgentSessionRuntime(buildRuntimeFactory(shared), {
    cwd: config.cwd,
    agentDir: getAgentDir() ?? config.agentDir,
    sessionManager: SessionManager.create(config.cwd),
  });

  if (args.print !== undefined) {
    await runPrintMode(runtime, {
      mode: "text",
      initialMessage: args.print || undefined,
      initialImages: [],
      messages: [],
    } as any);
    return;
  }

  const mode = new InteractiveMode(runtime, {
    migratedProviders: [],
    modelFallbackMessage: runtime.modelFallbackMessage,
    initialMessage: undefined,
    initialImages: [],
    initialMessages: [],
  } as any);
  await mode.run();
}

main().catch((e) => {
  console.error("[opagent] 启动失败:", e);
  process.exit(1);
});
