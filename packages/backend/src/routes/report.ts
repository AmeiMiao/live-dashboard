import { authenticateToken } from "../middleware/auth";
import { resolveAppName } from "../services/app-mapper";
import { isNSFW } from "../services/nsfw-filter";
import { processDisplayTitle } from "../services/privacy-tiers";
import { insertActivity, upsertDeviceState, hmacTitle, getDeviceStateById, insertHealthRecord } from "../db";

const MAX_TITLE_LENGTH = 256;

function parseClientTimestamp(rawTimestamp: unknown): string | null {
  let ts: Date | null = null;

  if (typeof rawTimestamp === "string" && rawTimestamp) {
    const parsed = new Date(rawTimestamp);
    if (!isNaN(parsed.getTime())) {
      ts = parsed;
    }
  } else if (typeof rawTimestamp === "number" && Number.isFinite(rawTimestamp)) {
    // Accept both Unix seconds and milliseconds from clients.
    const epochMs = rawTimestamp < 1e12 ? rawTimestamp * 1000 : rawTimestamp;
    const parsed = new Date(epochMs);
    if (!isNaN(parsed.getTime())) {
      ts = parsed;
    }
  }

  if (!ts) return null;

  const now = Date.now();
  if (Math.abs(ts.getTime() - now) >= 5 * 60 * 1000) {
    return null;
  }

  return ts.toISOString();
}

function parseExtraJson(extra: unknown): Record<string, unknown> {
  if (typeof extra !== "string" || !extra) return {};
  try {
    const parsed = JSON.parse(extra);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Ignore malformed stored extra JSON.
  }
  return {};
}

function sanitizeExtra(bodyExtra: any): Record<string, unknown> {
  const extra: Record<string, unknown> = {};
  if (!bodyExtra || typeof bodyExtra !== "object" || Array.isArray(bodyExtra)) {
    return extra;
  }

  if (typeof bodyExtra.battery_percent === "number" && Number.isFinite(bodyExtra.battery_percent)) {
    extra.battery_percent = Math.max(0, Math.min(100, Math.round(bodyExtra.battery_percent)));
  }

  if (typeof bodyExtra.battery_charging === "boolean") {
    extra.battery_charging = bodyExtra.battery_charging;
  }

  if (typeof bodyExtra.heart_rate === "number" && Number.isFinite(bodyExtra.heart_rate)) {
    extra.heart_rate = Math.max(0, Math.min(250, Math.round(bodyExtra.heart_rate)));
  }

  const rawMusic = bodyExtra.music;
  if (rawMusic != null && typeof rawMusic === "object" && !Array.isArray(rawMusic)) {
    const music: Record<string, string> = {};
    if (typeof rawMusic.title === "string") music.title = rawMusic.title.slice(0, 256);
    if (typeof rawMusic.artist === "string") music.artist = rawMusic.artist.slice(0, 256);
    if (typeof rawMusic.app === "string") music.app = rawMusic.app.slice(0, 64);
    // Check if music has any non-empty values
    const hasNonEmptyMusic = Object.values(music).some(v => v.length > 0);
    if (hasNonEmptyMusic) {
      extra.music = music;
    } else if (Object.keys(music).length > 0) {
      // All values are empty strings — explicitly mark music for clearing
      extra.music = null;
    }
  }

  return extra;
}

export async function handleReport(req: Request): Promise<Response> {
  // Auth
  const device = authenticateToken(req.headers.get("authorization"));
  if (!device) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Parse body
  let body: any;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const appId = typeof body.app_id === "string" ? body.app_id.trim() : "";
  if (!appId) {
    return Response.json({ error: "app_id required" }, { status: 400 });
  }

  // Truncate window_title
  let windowTitle =
    typeof body.window_title === "string" ? body.window_title : "";
  if (windowTitle.length > MAX_TITLE_LENGTH) {
    windowTitle = windowTitle.slice(0, MAX_TITLE_LENGTH);
  }

  // Validate client timestamp (optional, used for display only)
  const startedAt = parseClientTimestamp(body.timestamp) || new Date().toISOString();

  // NSFW filter - silently discard
  if (isNSFW(appId, windowTitle)) {
    return Response.json({ ok: true });
  }

  // Resolve app name
  const appName = resolveAppName(appId, device.platform);

  // Privacy: generate display_title (safe for public), then discard raw window_title
  const displayTitle = processDisplayTitle(appName, windowTitle);

  // Dedup: HMAC hash of the original title (keyed, not reversible)
  const timeBucket = Math.floor(Date.now() / 10000);
  const titleHash = hmacTitle(windowTitle.toLowerCase().trim());

  // Parse extra (battery, etc.) — preserve prior device state fields when omitted.
  const incomingExtra = sanitizeExtra(body.extra);
  let mergedExtra = incomingExtra;
  let existingExtra: Record<string, unknown> = {};
  try {
    const existingState = await getDeviceStateById(device.device_id);
    if (existingState) {
      existingExtra = parseExtraJson(existingState.extra);
      mergedExtra = { ...existingExtra, ...incomingExtra };
      // If incoming explicitly set music to null, clear it from merged result
      if ("music" in incomingExtra && incomingExtra.music === null) {
        delete mergedExtra.music;
      }
    }
  } catch (e: any) {
    console.warn("[report] Failed to load existing extra, using incoming extra only:", e.message);
  }

  if (typeof incomingExtra.heart_rate === "number" && Number.isFinite(incomingExtra.heart_rate)) {
    const nowIso = new Date().toISOString();
    mergedExtra.heart_rate_updated_at = nowIso;
    const previousHeartRate = typeof existingExtra.heart_rate === "number" && Number.isFinite(existingExtra.heart_rate)
      ? existingExtra.heart_rate
      : null;
    if (previousHeartRate === null || previousHeartRate !== incomingExtra.heart_rate) {
      mergedExtra.heart_rate_changed_at = nowIso;
    } else if (typeof existingExtra.heart_rate_changed_at === "string") {
      mergedExtra.heart_rate_changed_at = existingExtra.heart_rate_changed_at;
    }
  }
  const extraJson = JSON.stringify(mergedExtra);

  // Insert activity — window_title is NEVER stored (privacy: empty string)
  try {
    await insertActivity(
      device.device_id,
      device.device_name,
      device.platform,
      appId,
      appName,
      "",           // window_title: always empty for privacy
      displayTitle,
      titleHash,
      timeBucket,
      startedAt
    );
  } catch (e: any) {
    // Log but don't expose internals
    if (!e.message?.includes("UNIQUE constraint")) {
      console.error("[report] DB insert error:", e.message);
    }
  }

  // Always update device state (even if activity was deduped)
  try {
    await upsertDeviceState(
      device.device_id,
      device.device_name,
      device.platform,
      appId,
      appName,
      "",           // window_title: always empty for privacy
      displayTitle,
      new Date().toISOString(),
      extraJson
    );
  } catch (e: any) {
    console.error("[report] Device state update error:", e.message);
    return Response.json({ error: "Internal error" }, { status: 500 });
  }

  // Save heart rate to health_records if present
  if (typeof incomingExtra.heart_rate === "number" && Number.isFinite(incomingExtra.heart_rate)) {
    try {
      await insertHealthRecord(
        device.device_id,
        "heart_rate",
        incomingExtra.heart_rate,
        "bpm",
        new Date().toISOString(),
        new Date().toISOString()
      );
    } catch (e: any) {
      if (!e.message?.includes("UNIQUE constraint")) {
        console.error("[report] Heart rate record insert error:", e.message);
      }
    }
  }

  return Response.json({ ok: true });
}
