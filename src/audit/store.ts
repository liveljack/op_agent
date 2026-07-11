/**
 * 审计存储 —— 哈希链 append-only
 *
 * 每条记录的 hash = sha256(prev_hash || canonical(record_fields))。
 * 任何篡改会破坏链，事后可校验。
 */

import { createHash } from "node:crypto";
import type { Database } from "bun:sqlite";
import { getAuditDb } from "./db.ts";

export interface AuditRecord {
  ts: number;
  tool: string;
  input?: string;
  result?: string;
  risk: string;
  blocked: boolean;
  approver?: string;
  reason?: string;
  matches?: string[];
}

export interface AuditStore {
  append(record: AuditRecord): { seq: number; hash: string };
  list(limit?: number): AuditRow[];
  verify(): { ok: boolean; brokenAt?: number };
}

export interface AuditRow extends AuditRecord {
  seq: number;
  prev_hash: string | null;
  hash: string;
}

export function createAuditStore(dbPath: string): AuditStore {
  const db = getAuditDb(dbPath);

  const lastHash = (): string | null => {
    const row = db
      .prepare("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
      .get() as { hash: string } | undefined;
    return row?.hash ?? null;
  };

  const computeHash = (prev: string | null, r: AuditRecord): string => {
    const canonical = [
      r.ts,
      r.tool,
      r.input ?? "",
      r.result ?? "",
      r.risk,
      r.blocked ? 1 : 0,
      r.approver ?? "",
      r.reason ?? "",
      (r.matches ?? []).join(","),
      prev ?? "",
    ].join("|");
    return createHash("sha256").update(canonical).digest("hex");
  };

  return {
    append(record) {
      const prev = lastHash();
      const hash = computeHash(prev, record);
      const ins = db.prepare(`
        INSERT INTO audit (ts, tool, input, result, risk, blocked, approver, reason, matches, prev_hash, hash)
        VALUES ($ts, $tool, $input, $result, $risk, $blocked, $approver, $reason, $matches, $prev_hash, $hash)
      `);
      const info = ins.run({
        $ts: record.ts,
        $tool: record.tool,
        $input: record.input ?? null,
        $result: record.result ?? null,
        $risk: record.risk,
        $blocked: record.blocked ? 1 : 0,
        $approver: record.approver ?? null,
        $reason: record.reason ?? null,
        $matches: (record.matches ?? []).join(",") || null,
        $prev_hash: prev,
        $hash: hash,
      });
      return { seq: Number(info.lastInsertRowid), hash };
    },

    list(limit = 100): AuditRow[] {
      const rows = db
        .prepare("SELECT * FROM audit ORDER BY seq DESC LIMIT ?")
        .all(limit) as any[];
      return rows.map((r) => ({
        seq: r.seq,
        ts: r.ts,
        tool: r.tool,
        input: r.input ?? undefined,
        result: r.result ?? undefined,
        risk: r.risk,
        blocked: r.blocked === 1,
        approver: r.approver ?? undefined,
        reason: r.reason ?? undefined,
        matches: r.matches ? r.matches.split(",") : [],
        prev_hash: r.prev_hash,
        hash: r.hash,
      }));
    },

    verify() {
      const rows = db
        .prepare("SELECT * FROM audit ORDER BY seq ASC")
        .all() as any[];
      let prev: string | null = null;
      for (const r of rows) {
        const rec: AuditRecord = {
          ts: r.ts,
          tool: r.tool,
          input: r.input ?? undefined,
          result: r.result ?? undefined,
          risk: r.risk,
          blocked: r.blocked === 1,
          approver: r.approver ?? undefined,
          reason: r.reason ?? undefined,
          matches: r.matches ? r.matches.split(",") : [],
        };
        const expected = computeHash(prev, rec);
        if (expected !== r.hash) {
          return { ok: false, brokenAt: r.seq };
        }
        prev = r.hash;
      }
      return { ok: true };
    },
  };
}
