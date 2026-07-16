/**
 * 自定义插件模板生成
 *
 * 生成可运行的 collector/notifier 模板到用户目录，用户填充实现即可。
 */

import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const COLLECTOR_TEMPLATE = (name: string) => `/**
 * 自定义 Collector: ${name}
 * 部署：~/.op_agent/monitor/${name}.ts
 * 守护进程 SIGHUP 或重启后自动加载。
 */

export default {
  type: "${name}",
  // 参数 schema（typebox 或 plain JSON schema）。secret 字段标 { secret: true }
  paramsSchema: {
    type: "object",
    properties: {
      target: { type: "string", description: "监控目标" },
    },
  },
  fields: ["value"],
  async collect(params, ctx) {
    // TODO: 实现采集逻辑。如需跑命令/SQL，调用 ctx.guard 校验。
    return {
      ts: Date.now(),
      fields: { value: 0 },
      labels: { target: String(params.target ?? "") },
    };
  },
};
`;

const NOTIFIER_TEMPLATE = (name: string) => `/**
 * 自定义 Notifier: ${name}
 * 部署：~/.op_agent/notification/${name}.ts
 */

export default {
  type: "${name}",
  paramsSchema: {
    type: "object",
    properties: {
      endpoint: { type: "string" },
      token: { type: "string", secret: true },
    },
  },
  async notify(alert, params) {
    // TODO: 实现通知发送
    await fetch(params.endpoint, {
      method: "POST",
      headers: { Authorization: \`Bearer \${params.token}\` },
      body: JSON.stringify({ text: \`[\${alert.severity}] \${alert.message}\` }),
    });
  },
  async test(params) {
    await this.notify(
      {
        id: "test", monitorId: "test", severity: "warn",
        message: "测试通知", sample: { ts: Date.now(), fields: {} },
        host: "test", ts: Date.now(), status: "firing",
      },
      params,
    );
  },
};
`;

export function generateCollectorScaffold(agentDir: string, name: string): string {
  const dir = join(agentDir, "monitor");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${name}.ts`);
  if (existsSync(path)) throw new Error(`已存在: ${path}`);
  writeFileSync(path, COLLECTOR_TEMPLATE(name), { mode: 0o600 });
  return path;
}

export function generateNotifierScaffold(agentDir: string, name: string): string {
  const dir = join(agentDir, "notification");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${name}.ts`);
  if (existsSync(path)) throw new Error(`已存在: ${path}`);
  writeFileSync(path, NOTIFIER_TEMPLATE(name), { mode: 0o600 });
  return path;
}
