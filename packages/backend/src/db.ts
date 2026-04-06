import { createClient, type Client } from "@libsql/client";
import { createHmac } from "crypto";

// Turso database client
const db: Client = createClient({
  url: process.env.TURSO_DATABASE_URL || "file:./local.db",
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Initialize tables
async function initDB() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS activities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      device_name TEXT NOT NULL,
      platform TEXT NOT NULL,
      app_id TEXT NOT NULL,
      app_name TEXT NOT NULL,
      window_title TEXT DEFAULT '',
      title_hash TEXT NOT NULL DEFAULT '',
      time_bucket INTEGER NOT NULL DEFAULT 0,
      started_at TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      display_title TEXT DEFAULT ''
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_dedup
      ON activities(device_id, app_id, title_hash, time_bucket)`,
    `CREATE INDEX IF NOT EXISTS idx_activities_device_started
      ON activities(device_id, started_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_activities_started
      ON activities(started_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_activities_created
      ON activities(created_at)`,
    `CREATE TABLE IF NOT EXISTS device_states (
      device_id TEXT PRIMARY KEY,
      device_name TEXT NOT NULL,
      platform TEXT NOT NULL,
      app_id TEXT NOT NULL,
      app_name TEXT NOT NULL,
      window_title TEXT DEFAULT '',
      display_title TEXT DEFAULT '',
      last_seen_at TEXT NOT NULL,
      extra TEXT DEFAULT '{}',
      is_online INTEGER DEFAULT 1
    )`,
    `CREATE TABLE IF NOT EXISTS health_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      type TEXT NOT NULL,
      value REAL NOT NULL,
      unit TEXT NOT NULL,
      recorded_at TEXT NOT NULL,
      end_time TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(device_id, type, recorded_at, end_time)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_health_records_recorded
      ON health_records(recorded_at)`,
    `CREATE INDEX IF NOT EXISTS idx_health_records_type
      ON health_records(type, recorded_at)`,
  ]);
  console.log("[db] Database initialized");
}

export const dbReady = initDB();

dbReady.catch((e) => {
  console.error("[db] Init failed:", e);
  process.exit(1);
});

export { db };

// HMAC secret validation
const HASH_SECRET = process.env.HASH_SECRET || "";
if (!HASH_SECRET) {
  console.error("[db] FATAL: HASH_SECRET not set. This is required for privacy-safe title hashing.");
  console.error("[db] Generate one with: openssl rand -hex 32");
  process.exit(1);
}

export function hmacTitle(title: string): string {
  return createHmac("sha256", HASH_SECRET).update(title).digest("hex");
}

// Database query functions (all async)
export async function insertActivity(
  deviceId: string,
  deviceName: string,
  platform: string,
  appId: string,
  appName: string,
  windowTitle: string,
  displayTitle: string,
  titleHash: string,
  timeBucket: number,
  startedAt: string
) {
  await db.execute({
    sql: `INSERT INTO activities (device_id, device_name, platform, app_id, app_name, window_title, display_title, title_hash, time_bucket, started_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(device_id, app_id, title_hash, time_bucket) DO NOTHING`,
    args: [deviceId, deviceName, platform, appId, appName, windowTitle, displayTitle, titleHash, timeBucket, startedAt],
  });
}

export async function upsertDeviceState(
  deviceId: string,
  deviceName: string,
  platform: string,
  appId: string,
  appName: string,
  windowTitle: string,
  displayTitle: string,
  lastSeenAt: string,
  extra: string
) {
  await db.execute({
    sql: `INSERT INTO device_states (device_id, device_name, platform, app_id, app_name, window_title, display_title, last_seen_at, extra, is_online)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
          ON CONFLICT(device_id) DO UPDATE SET
            device_name = excluded.device_name,
            platform = excluded.platform,
            app_id = excluded.app_id,
            app_name = excluded.app_name,
            window_title = excluded.window_title,
            display_title = excluded.display_title,
            last_seen_at = excluded.last_seen_at,
            extra = excluded.extra,
            is_online = 1`,
    args: [deviceId, deviceName, platform, appId, appName, windowTitle, displayTitle, lastSeenAt, extra],
  });
}

export async function getAllDeviceStates() {
  const result = await db.execute("SELECT * FROM device_states ORDER BY last_seen_at DESC");
  return result.rows;
}

export async function getDeviceStateById(deviceId: string) {
  const result = await db.execute({
    sql: "SELECT * FROM device_states WHERE device_id = ? LIMIT 1",
    args: [deviceId],
  });
  return result.rows[0] ?? null;
}

export async function getRecentActivities() {
  const result = await db.execute("SELECT * FROM activities ORDER BY started_at DESC LIMIT 20");
  return result.rows;
}

export async function getTimelineByDate(date: string) {
  const result = await db.execute({
    sql: "SELECT * FROM activities WHERE date(started_at) = ? ORDER BY started_at ASC",
    args: [date],
  });
  return result.rows;
}

export async function getTimelineByDateAndDevice(date: string, deviceId: string) {
  const result = await db.execute({
    sql: "SELECT * FROM activities WHERE date(started_at) = ? AND device_id = ? ORDER BY started_at ASC",
    args: [date, deviceId],
  });
  return result.rows;
}

export async function getTimelineByDateWithTZ(date: string, modifier: string) {
  const result = await db.execute({
    sql: `SELECT * FROM activities WHERE date(started_at, '${modifier}') = ? ORDER BY started_at ASC`,
    args: [date],
  });
  return result.rows;
}

export async function getTimelineByDateAndDeviceWithTZ(date: string, deviceId: string, modifier: string) {
  const result = await db.execute({
    sql: `SELECT * FROM activities WHERE date(started_at, '${modifier}') = ? AND device_id = ? ORDER BY started_at ASC`,
    args: [date, deviceId],
  });
  return result.rows;
}

export async function markOfflineDevices() {
  await db.execute(
    "UPDATE device_states SET is_online = 0 WHERE is_online = 1 AND (last_seen_at IS NULL OR last_seen_at = '' OR datetime(last_seen_at) < datetime('now', '-1 minute'))"
  );
}

export async function cleanupOldActivities() {
  const result = await db.execute("DELETE FROM activities WHERE created_at < datetime('now', '-7 days')");
  return result.rowsAffected || 0;
}

export async function cleanupOldHealthRecords() {
  const result = await db.execute(
    "DELETE FROM health_records WHERE created_at < datetime('now', '-7 days')"
  );
  return result.rowsAffected || 0;
}

// Health records
export async function insertHealthRecord(
  deviceId: string,
  type: string,
  value: number,
  unit: string,
  recordedAt: string,
  endTime: string
) {
  await db.execute({
    sql: `INSERT INTO health_records (device_id, type, value, unit, recorded_at, end_time)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(device_id, type, recorded_at, end_time) DO NOTHING`,
    args: [deviceId, type, value, unit, recordedAt, endTime],
  });
}

export async function insertManyHealthRecords(
  records: { deviceId: string; type: string; value: number; unit: string; recordedAt: string; endTime: string }[]
) {
  if (records.length === 0) return 0;

  const stmts = records.map((r) => ({
    sql: `INSERT INTO health_records (device_id, type, value, unit, recorded_at, end_time)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(device_id, type, recorded_at, end_time) DO NOTHING`,
    args: [r.deviceId, r.type, r.value, r.unit, r.recordedAt, r.endTime],
  }));

  const results = await db.batch(stmts);
  return results.reduce((sum, r) => sum + (r.rowsAffected || 0), 0);
}

export async function getHealthRecordsByDate(date: string) {
  const result = await db.execute({
    sql: "SELECT device_id, type, value, unit, recorded_at, end_time FROM health_records WHERE date(recorded_at) = ? ORDER BY recorded_at ASC",
    args: [date],
  });
  return result.rows;
}

export async function getHealthRecordsByDateAndDevice(date: string, deviceId: string) {
  const result = await db.execute({
    sql: "SELECT device_id, type, value, unit, recorded_at, end_time FROM health_records WHERE date(recorded_at) = ? AND device_id = ? ORDER BY recorded_at ASC",
    args: [date, deviceId],
  });
  return result.rows;
}

export async function getHealthRecordsByDateWithTZ(date: string, modifier: string) {
  const result = await db.execute({
    sql: `SELECT device_id, type, value, unit, recorded_at, end_time FROM health_records WHERE date(recorded_at, '${modifier}') = ? ORDER BY recorded_at ASC`,
    args: [date],
  });
  return result.rows;
}

export async function getHealthRecordsByDateAndDeviceWithTZ(date: string, deviceId: string, modifier: string) {
  const result = await db.execute({
    sql: `SELECT device_id, type, value, unit, recorded_at, end_time FROM health_records WHERE date(recorded_at, '${modifier}') = ? AND device_id = ? ORDER BY recorded_at ASC`,
    args: [date, deviceId],
  });
  return result.rows;
}

export async function getHealthRecordsByDateRange(startOfDay: string, startOfNextDay: string) {
  const result = await db.execute({
    sql: "SELECT device_id, type, value, unit, recorded_at, end_time FROM health_records WHERE recorded_at >= ? AND recorded_at < ? ORDER BY recorded_at ASC",
    args: [startOfDay, startOfNextDay],
  });
  return result.rows;
}

export async function getHealthRecordsByDateRangeAndDevice(startOfDay: string, startOfNextDay: string, deviceId: string) {
  const result = await db.execute({
    sql: "SELECT device_id, type, value, unit, recorded_at, end_time FROM health_records WHERE recorded_at >= ? AND recorded_at < ? AND device_id = ? ORDER BY recorded_at ASC",
    args: [startOfDay, startOfNextDay, deviceId],
  });
  return result.rows;
}

export default db;
