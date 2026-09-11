import { test, expect, describe } from "bun:test";
import {
  SandboxRunner,
  buildBwrapArgs,
  buildMacProfile,
  detectSandbox,
  type ProbeRunner,
} from "../../src/safety/sandbox.ts";

/** 审计 mock：只记录 append 调用 */
function makeAudit() {
  const records: any[] = [];
  return {
    records,
    store: {
      append: (r: any) => {
        records.push(r);
        return { seq: records.length, hash: "x" };
      },
      list: () => [],
      verify: () => ({ ok: true }),
    },
  };
}

describe("buildMacProfile", () => {
  test("包含写拒绝与 scratch/设备放行", () => {
    const p = buildMacProfile(["/tmp", "/private/tmp"]);
    expect(p).toContain("(deny file-write*)");
    expect(p).toContain('(subpath "/tmp")');
    expect(p).toContain('(subpath "/private/tmp")');
    expect(p).toContain('(literal "/dev/null")');
    expect(p).toContain('(literal "/dev/dtracehelper")');
    expect(p).toContain("(allow default)");
  });
});

describe("buildBwrapArgs", () => {
  test("全系统只读 + scratch 可写 + 独立 dev/proc", () => {
    const args = buildBwrapArgs(["/tmp"], ["bash", "/tmp/x.sh"]);
    expect(args).toContain("--ro-bind");
    const bindIdx = args.indexOf("--bind");
    expect(args[bindIdx + 1]).toBe("/tmp");
    expect(args[bindIdx + 2]).toBe("/tmp");
    expect(args).toContain("--dev");
    expect(args).toContain("--proc");
    expect(args).toContain("--die-with-parent");
    const sep = args.indexOf("--");
    expect(args.slice(sep + 1)).toEqual(["bash", "/tmp/x.sh"]);
  });
});

describe("detectSandbox —— 注入 mock 探测器", () => {
  test("sandbox-exec 探测成功", async () => {
    const probe: ProbeRunner = async (argv) => {
      if (argv[0] === "sandbox-exec") return { exitCode: 0 };
      throw new Error("not found");
    };
    const info = await detectSandbox(probe);
    expect(info.kind).toBe("sandbox-exec");
  });
  test("sandbox-exec 不可用回退 bwrap", async () => {
    const probe: ProbeRunner = async (argv) => {
      if (argv[0] === "bwrap") return { exitCode: 0 };
      throw new Error("not found");
    };
    const info = await detectSandbox(probe);
    expect(info.kind).toBe("bwrap");
  });
  test("均不可用返回 none", async () => {
    const probe: ProbeRunner = async () => {
      throw new Error("not found");
    };
    const info = await detectSandbox(probe);
    expect(info.kind).toBe("none");
  });
  test("探测非零退出码视为不可用", async () => {
    const probe: ProbeRunner = async () => ({ exitCode: 1 });
    expect((await detectSandbox(probe)).kind).toBe("none");
  });
});

describe("SandboxRunner", () => {
  const scratchPaths = ["/tmp"];
  const realpath = (p: string) => (p === "/tmp" ? "/private/tmp" : p === "/" ? "/" : null);

  function makeRunner(opts: { policy?: "auto" | "require" | "off"; allowWrite?: boolean } = {}) {
    const audit = makeAudit();
    const runner = new SandboxRunner({
      policy: opts.policy ?? "auto",
      allowWrite: opts.allowWrite ?? false,
      scratchPaths,
      audit: audit.store,
      probe: async (argv) => {
        if (argv[0] === "sandbox-exec") return { exitCode: 0 };
        throw new Error("not found");
      },
      realpath,
    });
    return { runner, audit };
  }

  test("writableRoots 含词法与 realpath 双形态", () => {
    const { runner } = makeRunner();
    expect(runner.writableRoots).toContain("/tmp");
    expect(runner.writableRoots).toContain("/private/tmp");
  });

  test("shouldSandbox 矩阵：默认模式启用、off/allowWrite 关闭", () => {
    expect(makeRunner().runner.shouldSandbox()).toBe(true);
    expect(makeRunner({ policy: "off" }).runner.shouldSandbox()).toBe(false);
    expect(makeRunner({ allowWrite: true }).runner.shouldSandbox()).toBe(false);
    expect(makeRunner({ policy: "require" }).runner.shouldSandbox()).toBe(true);
  });

  test("sandboxActive：可用时 true、不可用时 false", async () => {
    expect(await makeRunner().runner.sandboxActive()).toBe(true);
    const none = new SandboxRunner({
      policy: "auto",
      allowWrite: false,
      scratchPaths,
      audit: makeAudit().store,
      probe: async () => {
        throw new Error("not found");
      },
      realpath,
    });
    expect(await none.sandboxActive()).toBe(false);
  });

  test("wrap 生成 sandbox-exec 包裹命令", async () => {
    const { runner } = makeRunner();
    const r = await runner.wrap(["bash", "/tmp/x.sh"]);
    expect(r.refused).toBe(false);
    if (!r.refused) {
      expect(r.argv[0]).toBe("sandbox-exec");
      expect(r.argv[1]).toBe("-p");
      expect(r.argv[2]).toContain("(deny file-write*)");
      expect(r.argv.slice(-2)).toEqual(["bash", "/tmp/x.sh"]);
    }
  });

  test("wrap 沙箱不可用时 refused", async () => {
    const runner = new SandboxRunner({
      policy: "auto",
      allowWrite: false,
      scratchPaths,
      audit: makeAudit().store,
      probe: async () => {
        throw new Error("not found");
      },
      realpath,
    });
    const r = await runner.wrap(["bash", "/tmp/x.sh"]);
    expect(r.refused).toBe(true);
  });

  test("审计三态：enabled / fallback / refused 入审计链", () => {
    const { runner, audit } = makeRunner();
    const info = { kind: "sandbox-exec" as const, detail: "ok" };
    runner.auditEnabled("run_script", info);
    runner.auditFallback("run_script", info);
    runner.auditRefused("run_script", info);
    expect(audit.records.length).toBe(3);
    expect(audit.records[0].result).toBe("enabled:sandbox-exec");
    expect(audit.records[1].blocked).toBe(false);
    expect(audit.records[2].blocked).toBe(true);
  });
});
