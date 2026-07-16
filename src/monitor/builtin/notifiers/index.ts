/**
 * 内置 Notifier：log / webhook / feishu / dingtalk
 *
 * 飞书/钉钉签名各按官方算法实现。secret 字段用 SecretString 标注。
 */

import { Type } from "typebox";
import { createHmac } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Alert, Notifier } from "../../types.ts";
import { SecretString } from "../../types.ts";

function alertText(a: Alert): string {
  return `[${a.status === "resolved" ? "恢复" : a.severity.toUpperCase()}] ${a.monitorId} @ ${a.host}\n${a.message}`;
}

export const logNotifier: Notifier = {
  type: "log",
  paramsSchema: Type.Object({
    path: Type.Optional(Type.String({ description: "日志路径，默认 ~/.op_agent/monitor.log" })),
  }),
  async notify(a, params) {
    const path = String(params.path ?? join(homedir(), ".op_agent", "monitor.log"));
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, `${new Date(a.ts).toISOString()} ${alertText(a)}\n`);
  },
  async test(params) {
    await this.notify(
      { id: "test", monitorId: "test", severity: "warn", message: "测试通知", sample: { ts: Date.now(), fields: {} }, host: "test", ts: Date.now(), status: "firing" },
      params,
    );
  },
};

async function postJson(url: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text().catch(() => "")}`);
}

export const webhookNotifier: Notifier = {
  type: "webhook",
  paramsSchema: Type.Object({
    url: Type.String({ description: "webhook URL" }),
    headers: Type.Optional(Type.Object({})),
  }),
  async notify(a, params) {
    await postJson(String(params.url), { alert: a, text: alertText(a) }, (params.headers as any) ?? {});
  },
  async test(params) {
    await postJson(String(params.url), { text: "opagent 测试通知" }, (params.headers as any) ?? {});
  },
};

/** 飞书签名：sign = base64(HMAC-SHA256(timestamp + "\n" + secret, "")) */
function feishuSign(secret: string, ts: number): string {
  const stringToSign = `${ts}\n${secret}`;
  const hmac = createHmac("sha256", stringToSign);
  return hmac.update("").digest("base64");
}

export const feishuNotifier: Notifier = {
  type: "feishu",
  paramsSchema: Type.Object({
    webhook_url: Type.String({ description: "飞书自定义机器人 webhook URL" }),
    secret: SecretString({ description: "签名校验密钥" }),
  }),
  async notify(a, params) {
    const url = new URL(String(params.webhook_url));
    if (params.secret) {
      const ts = Math.floor(Date.now() / 1000);
      url.searchParams.set("timestamp", String(ts));
      url.searchParams.set("sign", feishuSign(String(params.secret), ts));
    }
    await postJson(url.toString(), {
      msg_type: "text",
      content: { text: alertText(a) },
    });
  },
  async test(params) {
    const url = new URL(String(params.webhook_url));
    if (params.secret) {
      const ts = Math.floor(Date.now() / 1000);
      url.searchParams.set("timestamp", String(ts));
      url.searchParams.set("sign", feishuSign(String(params.secret), ts));
    }
    await postJson(url.toString(), { msg_type: "text", content: { text: "opagent 测试通知" } });
  },
};

/** 钉钉签名：sign = base64(HMAC-SHA256(secret, timestamp + "\n" + secret))，再 urlencode */
function dingtalkSign(secret: string, ts: number): string {
  const stringToSign = `${ts}\n${secret}`;
  const hmac = createHmac("sha256", secret);
  return encodeURIComponent(hmac.update(stringToSign).digest("base64"));
}

export const dingtalkNotifier: Notifier = {
  type: "dingtalk",
  paramsSchema: Type.Object({
    webhook: Type.String({ description: "钉钉自定义机器人 webhook URL" }),
    secret: SecretString({ description: "加签密钥" }),
  }),
  async notify(a, params) {
    const url = new URL(String(params.webhook));
    if (params.secret) {
      const ts = Date.now();
      url.searchParams.set("timestamp", String(ts));
      url.searchParams.set("sign", dingtalkSign(String(params.secret), ts));
    }
    await postJson(url.toString(), {
      msgtype: "text",
      text: { content: alertText(a) },
    });
  },
  async test(params) {
    const url = new URL(String(params.webhook));
    if (params.secret) {
      const ts = Date.now();
      url.searchParams.set("timestamp", String(ts));
      url.searchParams.set("sign", dingtalkSign(String(params.secret), ts));
    }
    await postJson(url.toString(), { msgtype: "text", text: { content: "opagent 测试通知" } });
  },
};

export const builtinNotifiers: Notifier[] = [
  logNotifier,
  webhookNotifier,
  feishuNotifier,
  dingtalkNotifier,
];
