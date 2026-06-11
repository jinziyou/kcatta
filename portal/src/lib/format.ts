/**
 * Pure display formatters shared across pages. No domain labels live here
 * (those are in `./meta.ts`) — only value→string transforms.
 */

/** Render an ISO timestamp as a compact, locale-stable `YYYY-MM-DD HH:mm` (UTC). */
export function fmtTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/:\d{2}\.\d+Z$/, "Z");
}

/** Full second-precision UTC timestamp, e.g. `2026-06-10 12:34:56Z`. */
export function fmtTimestampFull(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

/**
 * Human relative time, e.g. `3m ago`, `just now`, `in 5s`.
 * Use only in client components — SSR + client can disagree and warn on hydration.
 */
export function fmtRelative(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const delta = Math.round((t - now) / 1000); // seconds; negative = past
  const abs = Math.abs(delta);
  const suffix = delta < 0 ? "前" : "后";
  if (abs < 5) return "刚刚";
  if (abs < 60) return `${abs}秒${suffix}`;
  if (abs < 3600) return `${Math.floor(abs / 60)}分钟${suffix}`;
  if (abs < 86400) return `${Math.floor(abs / 3600)}小时${suffix}`;
  return `${Math.floor(abs / 86400)}天${suffix}`;
}

/** Elapsed wall-clock between two ISO instants, e.g. `4.2s`, `1m12s`. */
export function fmtDuration(
  start: string | null | undefined,
  end: string | null | undefined,
): string {
  if (!start || !end) return "—";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m${Math.round(s % 60)}s`;
}

/** Byte count as a compact human string, e.g. `1.4 KB`, `12 MB`. */
export function fmtBytes(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

/** Shorten a long opaque id for display, keeping the head, e.g. `scan-1a2b3c…`. */
export function shortId(id: string | null | undefined, head = 12): string {
  if (!id) return "—";
  return id.length > head + 1 ? `${id.slice(0, head)}…` : id;
}

/** `host:port` where the port may be absent. */
export function endpoint(ip: string, port: number | null | undefined): string {
  return port != null ? `${ip}:${port}` : ip;
}
