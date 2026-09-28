import { test, expect, describe, beforeEach } from 'bun:test';
import { PolicyGuard } from '../../src/safety/policy.ts';
import { SafetyLevelManager, modeFromFlags, SAFETY_MODES } from '../../src/safety/level.ts';
import type { AuditStore, AuditRecord } from '../../src/audit/store.ts';

/** 内存审计 store：记录 append 调用，供断言 */
function makeMemoryAudit(): AuditStore & { records: AuditRecord[] } {
  const records: AuditRecord[] = [];
  return {
    records,
    append(record) {
      records.push(record);
      return { seq: records.length, hash: 'mock' };
    },
    list: () => [],
    verify: () => ({ ok: true }),
  };
}

function makeGuard(allowWrite = false, allowDestructive = false) {
  return new PolicyGuard({
    allowWrite,
    allowDestructive,
    writePaths: ['/data/workspace'],
    cwd: '/data/workspace',
    home: '/home/ops',
    scratchPaths: ['/tmp'],
    realpath: (p: string) => (p === '/' ? '/' : null),
  });
}

describe('SafetyLevelManager', () => {
  test('modeFromFlags：flags 组合映射级别', () => {
    expect(modeFromFlags(false, false)).toBe('readonly');
    expect(modeFromFlags(true, false)).toBe('write');
    expect(modeFromFlags(true, true)).toBe('destructive');
    expect(modeFromFlags(false, true)).toBe('destructive');
  });

  test('gates：级别到门禁的映射', () => {
    const audit = makeMemoryAudit();
    const m = new SafetyLevelManager({ initialMode: 'readonly', audit });
    expect(m.gates).toEqual({ allowWrite: false, allowDestructive: false });
    m.set('write', 'user');
    expect(m.gates).toEqual({ allowWrite: true, allowDestructive: false });
    m.set('destructive', 'user');
    expect(m.gates).toEqual({ allowWrite: true, allowDestructive: true });
  });

  test('set：变更写入审计链，同级别不变更不写审计', () => {
    const audit = makeMemoryAudit();
    const m = new SafetyLevelManager({ initialMode: 'readonly', audit });
    expect(m.set('write', 'user', '测试提权')).toBe(true);
    expect(m.current).toBe('write');
    expect(audit.records).toHaveLength(1);
    expect(audit.records[0]!.tool).toBe('safety_level');
    expect(audit.records[0]!.input).toBe('readonly -> write');
    expect(audit.records[0]!.approver).toBe('user');
    // 同级别：无变化
    expect(m.set('write', 'user')).toBe(false);
    expect(audit.records).toHaveLength(1);
  });
});

describe('PolicyGuard 运行时调级', () => {
  test('默认只读：写命令阻断，setLevel 提权后放行（需确认）', () => {
    const g = makeGuard();
    // 只读：系统写阻断
    expect(g.checkBash('systemctl restart nginx').allow).toBe(false);
    // 提权到 write
    g.setLevel({ allowWrite: true, allowDestructive: false });
    const d = g.checkBash('systemctl restart nginx');
    expect(d.allow).toBe(true);
    expect(d.requireConfirm).toBe(true);
    // 降回只读：再次阻断
    g.setLevel({ allowWrite: false, allowDestructive: false });
    expect(g.checkBash('systemctl restart nginx').allow).toBe(false);
  });

  test('提权后破坏性仍阻断，destructive 级别才放行', () => {
    const g = makeGuard();
    g.setLevel({ allowWrite: true, allowDestructive: false });
    expect(g.checkBash('rm -rf /data/workspace/x').allow).toBe(false);
    g.setLevel({ allowWrite: true, allowDestructive: true });
    const d = g.checkBash('rm -rf /data/workspace/x');
    expect(d.allow).toBe(true);
    expect(d.requireConfirm).toBe(true);
  });

  test('写 SQL 门禁随级别变化', () => {
    const g = makeGuard();
    expect(g.checkSql('INSERT INTO t VALUES(1)').allow).toBe(false);
    g.setLevel({ allowWrite: true, allowDestructive: false });
    expect(g.checkSql('INSERT INTO t VALUES(1)').requireConfirm).toBe(true);
  });

  test('scratch 区写不受级别影响（始终免确认放行）', () => {
    const g = makeGuard();
    const d0 = g.checkBash('echo x > /tmp/a.txt');
    expect(d0.allow).toBe(true);
    expect(d0.zone).toBe('scratch');
    g.setLevel({ allowWrite: true, allowDestructive: true });
    const d1 = g.checkBash('echo x > /tmp/a.txt');
    expect(d1.allow).toBe(true);
    expect(d1.zone).toBe('scratch');
  });

  test('硬保护路径在任何级别下都阻断', () => {
    const g = makeGuard();
    for (const level of [
      { allowWrite: false, allowDestructive: false },
      { allowWrite: true, allowDestructive: false },
      { allowWrite: true, allowDestructive: true },
    ]) {
      g.setLevel(level);
      expect(g.checkBash('echo hi > /etc/passwd').allow).toBe(false);
      expect(g.checkWritePath('/etc/shadow').allow).toBe(false);
    }
  });

  test('level getter 返回当前门禁快照', () => {
    const g = makeGuard();
    expect(g.level).toEqual({ allowWrite: false, allowDestructive: false });
    g.setLevel({ allowWrite: true, allowDestructive: true });
    expect(g.level).toEqual({ allowWrite: true, allowDestructive: true });
  });
});

describe('级别流转场景（排查 → 提权执行 → 降回）', () => {
  let audit: ReturnType<typeof makeMemoryAudit>;
  let manager: SafetyLevelManager;
  let guard: PolicyGuard;

  beforeEach(() => {
    audit = makeMemoryAudit();
    manager = new SafetyLevelManager({ initialMode: 'readonly', audit });
    guard = makeGuard();
  });

  function applyLevel() {
    guard.setLevel(manager.gates);
  }

  test('完整工作流：只读排查 → write 执行 → 降回只读', () => {
    // 1. 只读排查：SELECT 放行，写阻断
    applyLevel();
    expect(guard.checkBash("psql -c 'SELECT * FROM t'").allow).toBe(true);
    expect(guard.checkBash('psql -c "INSERT INTO t VALUES(1)"').allow).toBe(false);

    // 2. 用户批准提权到 write
    manager.set('write', 'user', '排查完成，执行修复方案');
    applyLevel();
    expect(guard.checkBash('psql -c "INSERT INTO t VALUES(1)"').allow).toBe(true);
    expect(guard.checkBash('psql -c "INSERT INTO t VALUES(1)"').requireConfirm).toBe(true);
    // 破坏性仍阻断
    expect(guard.checkBash("psql -c 'DROP TABLE t'").allow).toBe(false);

    // 3. 执行完成，降回只读
    manager.set('readonly', 'user', '方案执行完成');
    applyLevel();
    expect(guard.checkBash('psql -c "INSERT INTO t VALUES(1)"').allow).toBe(false);

    // 4. 审计链记录了完整流转
    const levelRecords = audit.records.filter((r) => r.tool === 'safety_level');
    expect(levelRecords).toHaveLength(2);
    expect(levelRecords[0]!.input).toBe('readonly -> write');
    expect(levelRecords[1]!.input).toBe('write -> readonly');
  });

  test('SAFETY_MODES 顺序：索引即严重度，提权判定依赖它', () => {
    expect(SAFETY_MODES).toEqual(['readonly', 'write', 'destructive']);
    expect(SAFETY_MODES.indexOf('write')).toBeGreaterThan(SAFETY_MODES.indexOf('readonly'));
    expect(SAFETY_MODES.indexOf('destructive')).toBeGreaterThan(SAFETY_MODES.indexOf('write'));
  });
});
