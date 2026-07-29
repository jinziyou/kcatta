export const REPORT_PAGE_SIZE = 50;
const CURSOR_PATTERN = /^[A-Za-z0-9_-]{1,4096}$/;

/** Parse a zero-based page query parameter without allowing negative/huge offsets. */
export function parsePage(value: string | string[] | undefined): number {
  const raw = typeof value === "string" ? value : "0";
  if (!/^\d+$/.test(raw)) return 0;
  const page = Number(raw);
  return Number.isSafeInteger(page) && page >= 0 ? page : 0;
}

/** Preserve page filters while setting/removing the zero-based `page` parameter. */
export function pageHref(path: string, page: number, values: Record<string, string | null>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value) params.set(key, value);
  }
  if (page > 0) params.set("page", String(page));
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

export function parseCursor(value: string | string[] | undefined): string | null {
  return typeof value === "string" && CURSOR_PATTERN.test(value) ? value : null;
}

export function parseCursorTrail(value: string | string[] | undefined): string[] {
  if (typeof value !== "string" || value.length > 16384) return [];
  const parts = value.split(".");
  return parts.length <= 128 && parts.every((part) => part === "~" || CURSOR_PATTERN.test(part))
    ? parts
    : [];
}

function cursorHref(
  path: string,
  page: number,
  cursor: string | null,
  trail: string[],
  values: Record<string, string | null>,
): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value) params.set(key, value);
  }
  if (page > 0) params.set("page", String(page));
  if (cursor) params.set("cursor", cursor);
  if (trail.length > 0) params.set("trail", trail.join("."));
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

export function cursorNavigation(
  path: string,
  page: number,
  currentCursor: string | null,
  nextCursor: string | null,
  trail: string[],
  values: Record<string, string | null>,
): { previousHref?: string; nextHref?: string } {
  const previousMarker = trail.at(-1);
  const previousHref =
    page > 0 && previousMarker
      ? cursorHref(
          path,
          page - 1,
          previousMarker === "~" ? null : previousMarker,
          trail.slice(0, -1),
          values,
        )
      : undefined;
  const nextHref = nextCursor
    ? cursorHref(
        path,
        page + 1,
        nextCursor,
        [...trail, currentCursor ?? "~"],
        values,
      )
    : undefined;
  return { previousHref, nextHref };
}
