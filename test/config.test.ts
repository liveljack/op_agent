import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { loadEnvFile } from "../src/config.ts";

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
