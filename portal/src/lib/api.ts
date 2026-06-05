/**
 * Thin client for the form HTTP API.
 *
 * Server Components call these from the request lifecycle, so we use
 * `fetch` with `cache: "no-store"` -- the data is operational and
 * should not be served stale.
 */

import type { Alert, AssetReport, AttackPath, DetectionResult, FlowBatch } from "./contracts";

const DEFAULT_BASE_URL = "http://127.0.0.1:8000";

function baseUrl(): string {
  return process.env.NEXT_PUBLIC_FORM_BASE_URL || DEFAULT_BASE_URL;
}

function requestHeaders(): HeadersInit {
  const token = process.env.FORM_API_TOKEN;
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
}

/** Error raised when a form API request is unreachable or returns a non-OK status. */
export class FormApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name = "FormApiError";
  }
}

async function get<T>(path: string): Promise<T> {
  const url = `${baseUrl()}${path}`;
  let response: Response;
  try {
    response = await fetch(url, { cache: "no-store", headers: requestHeaders() });
  } catch (err) {
    throw new FormApiError(`form API unreachable at ${baseUrl()}`, undefined, err);
  }
  if (!response.ok) {
    throw new FormApiError(`form API ${response.status} on ${path}`, response.status);
  }
  return (await response.json()) as T;
}

/** Fetch the most recent asset reports, newest first, up to `limit`. */
export function listAssetReports(limit = 50): Promise<AssetReport[]> {
  return get<AssetReport[]>(`/reports/asset-reports?limit=${limit}`);
}

/** Fetch a single asset report by its identifier. */
export function getAssetReport(reportId: string): Promise<AssetReport> {
  return get<AssetReport>(`/reports/asset-reports/${encodeURIComponent(reportId)}`);
}

/** Fetch the most recent vulnerability detection results, up to `limit`. */
export function listVulnerabilities(limit = 50): Promise<DetectionResult[]> {
  return get<DetectionResult[]>(`/reports/vulnerabilities?limit=${limit}`);
}

/** Fetch the most recent alerts, newest first, up to `limit`. */
export function listAlerts(limit = 50): Promise<Alert[]> {
  return get<Alert[]>(`/reports/alerts?limit=${limit}`);
}

/** Fetch a single alert by its identifier. */
export function getAlert(alertId: string): Promise<Alert> {
  return get<Alert>(`/reports/alerts/${encodeURIComponent(alertId)}`);
}

/** Fetch the most recent network flow batches, up to `limit`. */
export function listFlowBatches(limit = 50): Promise<FlowBatch[]> {
  return get<FlowBatch[]>(`/reports/flow-batches?limit=${limit}`);
}

/** Predict attack paths from current posture + the latest ingested capability graph. */
export function listAttackPaths(limit = 200): Promise<AttackPath[]> {
  return get<AttackPath[]>(`/attack-paths?limit=${limit}`);
}

/** Fetch a single predicted attack path by its deterministic identifier. */
export function getAttackPath(pathId: string): Promise<AttackPath> {
  return get<AttackPath>(`/attack-paths/${encodeURIComponent(pathId)}`);
}
