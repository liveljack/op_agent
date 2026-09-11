import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { loadEnvFile, loadConfig } from "../src/config.ts";

const TMP = join(import.meta.dir, ".tmp-env");

beforeEach(() => {
  mkdirSync(TMP, { recursive: true });
});
afterEach(() => {
  rmSync(TMP, { recursive: true, force: true });
});

describe("loadEnvFile —— 优先级与解析", () => {
  test("缺失键被填入 process.env", () => {
    const key = "OPAGENT_TEST_MISSING_KEY";
    delete process.env[key];
    const f = join(TMP, ".env");
    writeFileSync(f, `${key}=fromfile\n`);
    const r = loadEnvFile(f);
    expect(r.loaded).toBe(1);
    expect(process.env[key]).toBe("fromfile");
    delete process.env[key];
  });

  test("已存在的 process.env 不被覆盖（process.env 优先）", () => {
    const key = "OPAGENT_TEST_EXISTING";
    process.env[key] = "fromenv";
    const f = join(TMP, ".env");
    writeFileSync(f, `${key}=fromfile\n`);
    const r = loadEnvFile(f);
    expect(r.loaded).toBe(0); // 未填入
    expect(process.env[key]).toBe("fromenv");
    delete process.env[key];
  });

  test("支持 export 前缀与引号", () => {
    const k1 = "OPAGENT_TEST_EXPORT";
    const k2 = "OPAGENT_TEST_QUOTED";
    delete process.env[k1];
    delete process.env[k2];
    const f = join(TMP, ".env");
    writeFileSync(f, `export ${k1}=plain\n${k2}="quoted value"\n`);
    loadEnvFile(f);
    expect(process.env[k1]).toBe("plain");
    expect(process.env[k2]).toBe("quoted value");
    delete process.env[k1];
    delete process.env[k2];
  });

  test("跳过注释与空行", () => {
    const key = "OPAGENT_TEST_COMMENT";
    delete process.env[key];
    const f = join(TMP, ".env");
    writeFileSync(f, `# 这是注释\n\n  ${key}=value  # 行内注释\n`);
    loadEnvFile(f);
    expect(process.env[key]).toBe("value");
    delete process.env[key];
  });

  test("文件不存在时静默返回", () => {
    const r = loadEnvFile(join(TMP, "nope.env"));
    expect(r.loaded).toBe(0);
  });
});

describe("loadConfig —— scratch 临时区与沙箱策略", () => {
  test("scratchPaths 默认 /tmp", () => {
    delete process.env.OPAGENT_SCRATCH_PATHS;
    const c = loadConfig({ cwd: "/data/ws" });
    expect(c.scratchPaths).toEqual(["/tmp"]);
  });

  test("OPAGENT_SCRATCH_PATHS 冒号分隔解析（含去空）", () => {
    process.env.OPAGENT_SCRATCH_PATHS = "/tmp : /var/tmp :";
    try {
      const c = loadConfig({ cwd: "/data/ws" });
      expect(c.scratchPaths).toEqual(["/tmp", "/var/tmp"]);
    } finally {
      delete process.env.OPAGENT_SCRATCH_PATHS;
    }
  });

  test("sandbox 默认 auto，非法值回退 auto", () => {
    delete process.env.OPAGENT_SANDBOX;
    expect(loadConfig({ cwd: "/data/ws" }).sandbox).toBe("auto");
    process.env.OPAGENT_SANDBOX = "bogus";
    try {
      expect(loadConfig({ cwd: "/data/ws" }).sandbox).toBe("auto");
    } finally {
      delete process.env.OPAGENT_SANDBOX;
    }
  });

  test("sandbox 合法值 require / off 生效，overrides 优先", () => {
    process.env.OPAGENT_SANDBOX = "require";
    try {
      expect(loadConfig({ cwd: "/data/ws" }).sandbox).toBe("require");
      expect(loadConfig({ cwd: "/data/ws", sandbox: "off" }).sandbox).toBe("off");
    } finally {
      delete process.env.OPAGENT_SANDBOX;
    }
  });
});
