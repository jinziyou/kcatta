/**
 * Thin client for the analyzer HTTP API.
 *
 * Server Components call these from the request lifecycle, so we use
 * `fetch` with `cache: "no-store"` -- the data is operational and
 * should not be served stale.
 */

import type {
  Alert,
  AssetReport,
  AttackPath,
  DetectionResult,
  TraceBatch,
  GuardEventBatch,
  ScanJob,
  ScanTarget,
  ScanTargetInput,
  TriggerScanRequest,
} from "./contracts";

const DEFAULT_BASE_URL = "http://127.0.0.1:8000";
const DEFAULT_TIMEOUT_MS = 8000;

function baseUrl(): string {
  return process.env.NEXT_PUBLIC_ANALYZER_BASE_URL || DEFAULT_BASE_URL;
}

function timeoutMs(): number {
  const n = Number(process.env.ANALYZER_API_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
}

function requestHeaders(): HeadersInit {
  const token = process.env.ANALYZER_API_TOKEN;
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
}

/** Error raised when a analyzer API request is unreachable or returns a non-OK status. */
export class AnalyzerApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name = "AnalyzerApiError";
  }
}

async function get<T>(path: string): Promise<T> {
  const url = `${baseUrl()}${path}`;
  let response: Response;
  try {
    // Bound the request: without a timeout a hung/half-open analyzer connection
    // would block this server-rendered request forever (never reaching the
    // catch), so the page would spin instead of showing the error state.
    response = await fetch(url, {
      cache: "no-store",
      headers: requestHeaders(),
      signal: AbortSignal.timeout(timeoutMs()),
    });
  } catch (err) {
    if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
      throw new AnalyzerApiError(`analyzer API timed out after ${timeoutMs()}ms`, undefined, err);
    }
    throw new AnalyzerApiError(`analyzer API unreachable at ${baseUrl()}`, undefined, err);
  }
  if (!response.ok) {
    throw new AnalyzerApiError(`analyzer API ${response.status} on ${path}`, response.status);
  }
  return (await response.json()) as T;
}

/** POST `body` as JSON to analyzer and parse the JSON response (server-side only). */
async function post<T>(path: string, body: unknown): Promise<T> {
  const url = `${baseUrl()}${path}`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      cache: "no-store",
      headers: { ...requestHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs()),
    });
  } catch (err) {
    if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
      throw new AnalyzerApiError(`analyzer API timed out after ${timeoutMs()}ms`, undefined, err);
    }
    throw new AnalyzerApiError(`analyzer API unreachable at ${baseUrl()}`, undefined, err);
  }
  if (!response.ok) {
    // Surface analyzer's `{detail: ...}` validation/business error when present.
    let detail = `${response.status}`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (body?.detail) {
        detail = `${response.status}: ${
          typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)
        }`;
      }
    } catch {
      // non-JSON error body; keep the status-only message
    }
    throw new AnalyzerApiError(`analyzer API ${detail} on ${path}`, response.status);
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

/** Fetch the most recent network trace batches, up to `limit`. */
export function listTraceBatches(limit = 50): Promise<TraceBatch[]> {
  return get<TraceBatch[]>(`/reports/trace-batches?limit=${limit}`);
}

/**
 * Predict attack paths from current posture + the latest ingested capability graph.
 *
 * Defaults to 500 to match analyzer's by-id window, so a path_id from this list
 * resolves consistently via {@link getAttackPath}.
 */
export function listAttackPaths(limit = 500): Promise<AttackPath[]> {
  return get<AttackPath[]>(`/attack-paths?limit=${limit}`);
}

/** Fetch a single predicted attack path by its deterministic identifier. */
export function getAttackPath(pathId: string): Promise<AttackPath> {
  return get<AttackPath>(`/attack-paths/${encodeURIComponent(pathId)}`);
}

// ---- scan orchestration (targets + jobs) -----------------------------------

/** List registered scan targets. */
export function listTargets(): Promise<ScanTarget[]> {
  return get<ScanTarget[]>(`/targets`);
}

/** Register a scan target (a one-time password bootstraps a managed key server-side). */
export function registerTarget(input: ScanTargetInput): Promise<ScanTarget> {
  return post<ScanTarget>(`/targets`, input);
}

/** List scan jobs, newest state per job first. */
export function listScans(): Promise<ScanJob[]> {
  return get<ScanJob[]>(`/scans`);
}

/** Fetch a single scan job (its latest state) by id. */
export function getScan(jobId: string): Promise<ScanJob> {
  return get<ScanJob>(`/scans/${encodeURIComponent(jobId)}`);
}

/** Trigger a scan against a registered target; returns the created (pending) job. */
export function triggerScan(req: TriggerScanRequest): Promise<ScanJob> {
  return post<ScanJob>(`/scans`, req);
}

/** Fetch recent real-time protection event batches, optionally filtered to one host. */
export function listGuardEvents(hostId?: string, limit = 50): Promise<GuardEventBatch[]> {
  const query = hostId
    ? `?host_id=${encodeURIComponent(hostId)}&limit=${limit}`
    : `?limit=${limit}`;
  return get<GuardEventBatch[]>(`/reports/guard-events${query}`);
}
