/**
 * 监控数据存储 —— bun:sqlite
 *
 * samples 表：window/rate 计算 + agent 查询，TTL 1h
 * alerts 表：告警生命周期，长期
 */

import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Alert, Sample } from "./types.ts";

let db: Database | undefined;

export function getMonitorDb(dbPath: string): Database {
  if (db && (db as any)._path === dbPath) return db;
  mkdirSync(dirname(dbPath), { recursive: true });
  const database = new Database(dbPath);
  database.exec("PRAGMA journal_mode = WAL;");
  database.exec(`CREATE TABLE IF NOT EXISTS samples (
    monitor_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    fields TEXT NOT NULL,
    labels TEXT
  );`);
  database.exec(`CREATE INDEX IF NOT EXISTS samples_monitor_ts ON samples(monitor_id, ts);`);
  database.exec(`CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    monitor_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    sample TEXT,
    host TEXT,
    ts INTEGER NOT NULL,
    resolved_at INTEGER
  );`);
  database.exec(`CREATE INDEX IF NOT EXISTS alerts_monitor ON alerts(monitor_id);`);
  (database as any)._path = dbPath;
  db = database;
  return database;
}

export interface MonitorStore {
  appendSample(monitorId: string, s: Sample): void;
  /** 取最近 windowMs 内的 samples（升序） */
  history(monitorId: string, windowMs: number): Sample[];
  /** 清理 1h 前的 samples */
  prune(now: number): number;
  insertAlert(a: Alert): void;
  resolveAlert(id: string, resolvedAt: number): void;
  listAlerts(limit?: number): Alert[];
  activeAlerts(monitorId: string): Alert[];
}

export function createStore(dbPath: string): MonitorStore {
  const db = getMonitorDb(dbPath);
  const SAMPLE_TTL = 3_600_000;

  return {
    appendSample(monitorId, s) {
      db.prepare(
        "INSERT INTO samples (monitor_id, ts, fields, labels) VALUES (?, ?, ?, ?)",
      ).run(monitorId, s.ts, JSON.stringify(s.fields), s.labels ? JSON.stringify(s.labels) : null);
    },
    history(monitorId, windowMs) {
      const since = Date.now() - windowMs;
      const rows = db
        .prepare("SELECT ts, fields, labels FROM samples WHERE monitor_id = ? AND ts >= ? ORDER BY ts ASC")
        .all(monitorId, since) as any[];
      return rows.map((r) => ({
        ts: r.ts,
        fields: JSON.parse(r.fields),
        labels: r.labels ? JSON.parse(r.labels) : undefined,
      }));
    },
    prune(now) {
      const cutoff = now - SAMPLE_TTL;
      const info = db.prepare("DELETE FROM samples WHERE ts < ?").run(cutoff);
      return Number(info.changes);
    },
    insertAlert(a) {
      db.prepare(
        `INSERT OR REPLACE INTO alerts (id, monitor_id, severity, status, message, sample, host, ts, resolved_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(a.id, a.monitorId, a.severity, a.status, a.message, JSON.stringify(a.sample), a.host, a.ts, null);
    },
    resolveAlert(id, resolvedAt) {
      db.prepare("UPDATE alerts SET status='resolved', resolved_at=? WHERE id=?").run(resolvedAt, id);
    },
    listAlerts(limit = 100) {
      const rows = db
        .prepare("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?")
        .all(limit) as any[];
      return rows.map((r) => ({
        id: r.id,
        monitorId: r.monitor_id,
        severity: r.severity,
        status: r.status,
        message: r.message,
        sample: JSON.parse(r.sample),
        host: r.host,
        ts: r.ts,
      })) as Alert[];
    },
    activeAlerts(monitorId) {
      const rows = db
        .prepare("SELECT * FROM alerts WHERE monitor_id=? AND status='firing' ORDER BY ts DESC")
        .all(monitorId) as any[];
      return rows.map((r) => ({
        id: r.id,
        monitorId: r.monitor_id,
        severity: r.severity,
        status: "firing",
        message: r.message,
        sample: JSON.parse(r.sample),
        host: r.host,
        ts: r.ts,
      })) as Alert[];
    },
  };
}
