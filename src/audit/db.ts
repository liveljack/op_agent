/**
 * 审计 DB —— bun:sqlite 单文件
 *
 * append-only audit 表 + 哈希链，保证不可篡改。
 */

import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

let db: Database | undefined;

export function getAuditDb(dbPath: string): Database {
  if (db && dbPath === (db as any)._opagentPath) return db;
  mkdirSync(dirname(dbPath), { recursive: true });
  const database = new Database(dbPath);
  database.exec("PRAGMA journal_mode = WAL;");
  database.exec("PRAGMA synchronous = NORMAL;");
  database.exec(`
    CREATE TABLE IF NOT EXISTS audit (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      tool TEXT NOT NULL,
      input TEXT,
      result TEXT,
      risk TEXT NOT NULL,
      blocked INTEGER NOT NULL,
      approver TEXT,
      reason TEXT,
      matches TEXT,
      prev_hash TEXT,
      hash TEXT NOT NULL
    );
  `);
  database.exec(`CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit(ts);`);
  database.exec(`CREATE INDEX IF NOT EXISTS audit_tool_idx ON audit(tool);`);
  (database as any)._opagentPath = dbPath;
  db = database;
  return database;
}
