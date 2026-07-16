import { test, expect, describe } from "bun:test";
import { evalCondition } from "../../src/monitor/condition.ts";
import { parseDuration, expandVars, redactParams } from "../../src/monitor/config.ts";
import { parseDf, parseMeminfo, parseLoadavg, parseNetdev } from "../../src/monitor/builtin/collectors/system.ts";
import { isSecret, Secret, SECRET } from "../../src/monitor/types.ts";
import { Type } from "typebox";

describe("condition —— 声明式条件评估", () => {
  const f = { usage: 92, count: 5, name: "x" };
  test("数值比较", () => {
    expect(evalCondition({ field: "usage", op: ">", value: 85 }, f)).toBe(true);
    expect(evalCondition({ field: "usage", op: "<", value: 85 }, f)).toBe(false);
    expect(evalCondition({ field: "usage", op: ">=", value: 92 }, f)).toBe(true);
    expect(evalCondition({ field: "usage", op: "==", value: 92 }, f)).toBe(true);
  });
  test("字符串相等", () => {
    expect(evalCondition({ field: "name", op: "==", value: "x" }, f)).toBe(true);
    expect(evalCondition({ field: "name", op: "!=", value: "y" }, f)).toBe(true);
  });
  test("字段缺失 → false（保守不告警）", () => {
    expect(evalCondition({ field: "nope", op: ">", value: 0 }, f)).toBe(false);
  });
  test("all / any 组合", () => {
    expect(evalCondition({ all: [{ field: "usage", op: ">", value: 85 }, { field: "count", op: ">", value: 0 }] }, f)).toBe(true);
    expect(evalCondition({ all: [{ field: "usage", op: ">", value: 85 }, { field: "count", op: ">", value: 99 }] }, f)).toBe(false);
    expect(evalCondition({ any: [{ field: "usage", op: "<", value: 50 }, { field: "count", op: ">", value: 0 }] }, f)).toBe(true);
  });
});

describe("config —— duration / vars / redact", () => {
  test("parseDuration", () => {
    expect(parseDuration("60s")).toBe(60_000);
    expect(parseDuration("5m")).toBe(300_000);
    expect(parseDuration("2h")).toBe(7_200_000);
    expect(parseDuration(1000)).toBe(1000);
    expect(parseDuration(undefined)).toBe(0);
  });
  test("expandVars", () => {
    process.env.OPAGENT_TEST_V = "hello";
    expect(expandVars("${OPAGENT_TEST_V} world")).toBe("hello world");
    expect(expandVars("${UNSET_VAR} x")).toBe("${UNSET_VAR} x"); // 未定义保留
    delete process.env.OPAGENT_TEST_V;
  });
  test("redactParams 脱敏 secret", () => {
    const schema = Type.Object({
      url: Type.String(),
      token: Secret(Type.String()),
    });
    const redacted = redactParams(schema as any, { url: "http://x", token: "sk-secret" });
    expect(redacted.url).toBe("http://x");
    expect(redacted.token).toBe("***");
  });
  test("isSecret 支持 plain schema 的 secret:true", () => {
    expect(isSecret({ type: "string", secret: true })).toBe(true);
    expect(isSecret({ type: "string", "x-secret": true })).toBe(true);
    expect(isSecret({ type: "string" })).toBe(false);
    expect(isSecret(Secret(Type.String()))).toBe(true);
  });
});

describe("system collectors —— 纯解析函数", () => {
  test("parseDf", () => {
    const out = `Filesystem     1024-blocks    Used     Available Capacity Mounted on\n/dev/sda1        20971520  15728640    5242880      75% /\n/dev/sdb1       104857600  20971520   83886080      20% /data`;
    const rows = parseDf(out);
    expect(rows).toHaveLength(2);
    expect(rows[0]!.mount).toBe("/");
    expect(rows[0]!.usage).toBe(75);
    expect(rows[1]!.mount).toBe("/data");
  });
  test("parseMeminfo", () => {
    const text = `MemTotal:       16384000 kB
MemFree:         2000000 kB
MemAvailable:    8000000 kB
Cached:          4000000 kB
SwapTotal:       2097152 kB
SwapFree:        2097152 kB`;
    const m = parseMeminfo(text);
    expect(m.totalKb).toBe(16384000);
    expect(m.availKb).toBe(8000000);
    expect(m.swapTotalKb).toBe(2097152);
  });
  test("parseLoadavg", () => {
    const la = parseLoadavg("0.52 0.45 0.39 2/300 1234");
    expect(la.load1).toBe(0.52);
    expect(la.load5).toBe(0.45);
  });
  test("parseNetdev", () => {
    const text = `Inter-|   Receive                                                |  Transmit\n  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    eth0: 1234567     100    0    0    0     0          0         0  7654321     200    0    0    0     0       0          0`;
    const r = parseNetdev(text, "eth0");
    expect(r.rx).toBe(1234567);
    expect(r.tx).toBe(7654321);
  });
});
