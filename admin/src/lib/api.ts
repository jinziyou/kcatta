/**
 * Thin server-side client for the Form control-plane API.
 *
 * Server Components call these from the request lifecycle, so we use
 * `fetch` with `cache: "no-store"` -- the data is operational and
 * should not be served stale.
 */

import "server-only";

import type {
  Alert,
  AlertStatus,
  AssetReport,
  AttackPath,
  AgentIdentity,
  CredentialInfo,
  CredentialRevokeResult,
  CredentialTestResult,
  DetectionResult,
  GuardLifecycleStatus,
  TraceBatch,
  GuardEventBatch,
  ScanJob,
  ScanTarget,
  ScanTargetInput,
  TriggerScanRequest,
} from "./contracts";

const DEFAULT_BASE_URL = "http://127.0.0.1:10067";
const DEFAULT_TIMEOUT_MS = 8000;

export interface LineageResponse<T> {
  lineage_id: string;
  expected_chunks: number | null;
  received_chunks: number;
  complete: boolean | null;
  records: T[];
}

export interface LineageSummary {
  lineage_id: string;
  expected_chunks: number | null;
  received_chunks: number;
  complete: boolean | null;
}

type ReportAsset = NonNullable<AssetReport["assets"]>[number];
type DetectionRecordSummary = Omit<DetectionResult, "vulnerabilities">;

/** Bounded projection used by the report-detail page; never implies a partial page is complete. */
export interface ReportDetailPage {
  report: Omit<AssetReport, "assets" | "vulnerabilities">;
  asset_lineage: LineageSummary;
  assets: ReportAsset[];
  asset_total: number;
  asset_kind_totals: Record<string, number>;
  asset_page: number;
  asset_page_size: number;
  asset_has_more: boolean;
  detection_lineage: LineageSummary;
  detection_records: DetectionRecordSummary[];
  vulnerabilities: NonNullable<DetectionResult["vulnerabilities"]>;
  vulnerability_total: number;
  finding_page: number;
  finding_page_size: number;
  finding_has_more: boolean;
}

export interface PageResult<T> {
  items: T[];
  hasMore: boolean;
  nextCursor: string | null;
}

function baseUrl(): string {
  return (process.env.FORM_BASE_URL || DEFAULT_BASE_URL).replace(/\/$/, "");
}

function timeoutMs(): number {
  const n = Number(process.env.FORM_API_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
}

function requestHeaders(): HeadersInit {
  const token = process.env.FORM_API_TOKEN;
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
}

/** Error raised when a Form API request is unreachable or returns a non-OK status. */
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

async function getResponse(path: string): Promise<Response> {
  const url = `${baseUrl()}${path}`;
  let response: Response;
  try {
    // Bound the request: without a timeout a hung/half-open Form connection
    // would block this server-rendered request forever (never reaching the
    // catch), so the page would spin instead of showing the error state.
    response = await fetch(url, {
      cache: "no-store",
      headers: requestHeaders(),
      signal: AbortSignal.timeout(timeoutMs()),
    });
  } catch (err) {
    if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
      throw new FormApiError(`Form API timed out after ${timeoutMs()}ms`, undefined, err);
    }
    throw new FormApiError(`Form API unreachable at ${baseUrl()}`, undefined, err);
  }
  if (!response.ok) {
    throw new FormApiError(`Form API ${response.status} on ${path}`, response.status);
  }
  return response;
}

async function get<T>(path: string): Promise<T> {
  const response = await getResponse(path);
  return (await response.json()) as T;
}

async function getPage<T>(path: string): Promise<PageResult<T>> {
  const response = await getResponse(path);
  return {
    items: (await response.json()) as T[],
    hasMore: response.headers.get("x-kcatta-has-more") === "true",
    nextCursor: response.headers.get("x-kcatta-next-cursor"),
  };
}

/** POST `body` as JSON to Form and parse the JSON response (server-side only). */
async function post<T>(
  path: string,
  body: unknown,
  additionalHeaders: Record<string, string> = {},
): Promise<T> {
  const url = `${baseUrl()}${path}`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      cache: "no-store",
      headers: {
        ...requestHeaders(),
        "Content-Type": "application/json",
        ...additionalHeaders,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs()),
    });
  } catch (err) {
    if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
      throw new FormApiError(`Form API timed out after ${timeoutMs()}ms`, undefined, err);
    }
    throw new FormApiError(`Form API unreachable at ${baseUrl()}`, undefined, err);
  }
  if (!response.ok) {
    // Surface Form's `{detail: ...}` validation/business error when present.
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
    throw new FormApiError(`Form API ${detail} on ${path}`, response.status);
  }
  return (await response.json()) as T;
}

/** Fetch one newest-first page of asset reports. */
export function listAssetReports(limit = 50, offset = 0): Promise<AssetReport[]> {
  return get<AssetReport[]>(`/reports/asset-reports?limit=${limit}&offset=${offset}`);
}

/** Fetch one byte-budget-safe logical page of asset reports. */
export function listAssetReportsPage(page: number, limit = 50): Promise<PageResult<AssetReport>> {
  return getPage<AssetReport>(`/reports/asset-reports?limit=${limit}&page=${page}`);
}

/** Fetch one stable cursor page of asset reports. */
export function listAssetReportsCursor(
  cursor: string | null,
  limit = 50,
): Promise<PageResult<AssetReport>> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (cursor) query.set("cursor", cursor);
  return getPage<AssetReport>(`/reports/asset-reports?${query.toString()}`);
}

/** Fetch a single asset report by its identifier. */
export function getAssetReport(reportId: string): Promise<AssetReport> {
  return get<AssetReport>(`/reports/asset-reports/${encodeURIComponent(reportId)}`);
}

/** Fetch every retained envelope known to belong to one logical asset upload. */
export function getAssetReportLineage(reportId: string): Promise<LineageResponse<AssetReport>> {
  return get<LineageResponse<AssetReport>>(
    `/reports/asset-reports/${encodeURIComponent(reportId)}/lineage`,
  );
}

/** Fetch analyzer-derived findings for one source asset report. */
export function getReportDetections(reportId: string): Promise<DetectionResult> {
  return get<DetectionResult>(`/reports/vulnerabilities/${encodeURIComponent(reportId)}`);
}

/** Fetch derived results for all retained chunks of one logical asset upload. */
export function getReportDetectionLineage(
  reportId: string,
): Promise<LineageResponse<DetectionResult>> {
  return get<LineageResponse<DetectionResult>>(
    `/reports/vulnerabilities/${encodeURIComponent(reportId)}/lineage`,
  );
}

/** Fetch bounded report assets/findings plus complete lineage and coverage summaries. */
export function getReportDetailPage(
  reportId: string,
  assetPage: number,
  findingPage: number,
  assetPageSize = 50,
  findingPageSize = 50,
): Promise<ReportDetailPage> {
  const query = new URLSearchParams({
    asset_page: String(assetPage),
    asset_page_size: String(assetPageSize),
    finding_page: String(findingPage),
    finding_page_size: String(findingPageSize),
  });
  return get<ReportDetailPage>(
    `/reports/report-details/${encodeURIComponent(reportId)}?${query.toString()}`,
  );
}

/** Fetch one newest-first page of vulnerability detection results. */
export function listVulnerabilities(limit = 50, offset = 0): Promise<DetectionResult[]> {
  return get<DetectionResult[]>(`/reports/vulnerabilities?limit=${limit}&offset=${offset}`);
}

/** Fetch one byte-budget-safe logical page of derived detection results. */
export function listVulnerabilitiesPage(
  page: number,
  limit = 50,
): Promise<PageResult<DetectionResult>> {
  return getPage<DetectionResult>(`/reports/vulnerabilities?limit=${limit}&page=${page}`);
}

/** Fetch one stable cursor page of derived detection results. */
export function listVulnerabilitiesCursor(
  cursor: string | null,
  limit = 50,
): Promise<PageResult<DetectionResult>> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (cursor) query.set("cursor", cursor);
  return getPage<DetectionResult>(`/reports/vulnerabilities?${query.toString()}`);
}

/**
 * Fetch alerts, de-duplicated by `alert_key`, newest first, up to `limit`.
 * Suppressed alerts are hidden unless `includeSuppressed` is set.
 */
export function listAlerts(limit = 50, includeSuppressed = false, offset = 0): Promise<Alert[]> {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (includeSuppressed) query.set("include_suppressed", "true");
  return get<Alert[]>(`/reports/alerts?${query.toString()}`);
}

/** Fetch one logical alert by any of its occurrence ids. */
export function getAlert(alertId: string): Promise<Alert> {
  return get<Alert>(`/reports/alerts/${encodeURIComponent(alertId)}`);
}

/** A partial triage update; omitted fields are left unchanged server-side. */
export interface AlertTriageInput {
  status?: AlertStatus;
  assignee?: string | null;
  note?: string | null;
  suppressed?: boolean;
}

/** Apply a triage update to the alert identified by `alertKey`; returns the merged alert. */
export function triageAlert(alertKey: string, input: AlertTriageInput): Promise<Alert> {
  return post<Alert>(`/reports/alerts/${encodeURIComponent(alertKey)}/triage`, input);
}

/** Fetch one newest-first page of trace batches. */
export function listTraceBatches(limit = 50, offset = 0): Promise<TraceBatch[]> {
  return get<TraceBatch[]>(`/reports/trace-batches?limit=${limit}&offset=${offset}`);
}

/** Fetch one byte-budget-safe logical page of trace batches. */
export function listTraceBatchesPage(page: number, limit = 50): Promise<PageResult<TraceBatch>> {
  return getPage<TraceBatch>(`/reports/trace-batches?limit=${limit}&page=${page}`);
}

/** Fetch one stable cursor page of trace batches. */
export function listTraceBatchesCursor(
  cursor: string | null,
  limit = 50,
): Promise<PageResult<TraceBatch>> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (cursor) query.set("cursor", cursor);
  return getPage<TraceBatch>(`/reports/trace-batches?${query.toString()}`);
}

/** Fetch every retained chunk known to belong to one logical trace upload. */
export function getTraceBatchLineage(batchId: string): Promise<LineageResponse<TraceBatch>> {
  return get<LineageResponse<TraceBatch>>(
    `/reports/trace-batches/${encodeURIComponent(batchId)}/lineage`,
  );
}

/**
 * Predict attack paths from current posture + the latest ingested capability graph.
 *
 * Defaults to 500 to match Form's by-id window, so a path_id from this list
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
export function triggerScan(req: TriggerScanRequest, idempotencyKey: string): Promise<ScanJob> {
  return post<ScanJob>(`/scans`, req, { "Idempotency-Key": idempotencyKey });
}

/** Request cooperative cancellation of a queued/running durable scan. */
export function cancelScan(jobId: string): Promise<ScanJob> {
  return post<ScanJob>(`/scans/${encodeURIComponent(jobId)}/cancel`, {});
}

/** Requeue a failed/cancelled scan using the same durable job history. */
export function retryScan(jobId: string): Promise<ScanJob> {
  return post<ScanJob>(`/scans/${encodeURIComponent(jobId)}/retry`, {});
}

/** Fetch recent real-time protection event batches, optionally filtered to one host. */
export function listGuardEvents(
  hostId?: string,
  limit = 50,
  offset = 0,
): Promise<GuardEventBatch[]> {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (hostId) query.set("host_id", hostId);
  return get<GuardEventBatch[]>(`/reports/guard-events?${query.toString()}`);
}

/** Fetch a byte-budget-safe logical page of Guard batches. */
export function listGuardEventsPage(
  page: number,
  hostId?: string,
  limit = 50,
): Promise<PageResult<GuardEventBatch>> {
  const query = new URLSearchParams({ limit: String(limit), page: String(page) });
  if (hostId) query.set("host_id", hostId);
  return getPage<GuardEventBatch>(`/reports/guard-events?${query.toString()}`);
}

/** Fetch a stable cursor page of Guard batches. */
export function listGuardEventsCursor(
  cursor: string | null,
  hostId?: string,
  limit = 50,
): Promise<PageResult<GuardEventBatch>> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (cursor) query.set("cursor", cursor);
  if (hostId) query.set("host_id", hostId);
  return getPage<GuardEventBatch>(`/reports/guard-events?${query.toString()}`);
}

// ---- access-credential management ------------------------------------------

/** List the durable access credentials registered targets reference. */
export function listCredentials(): Promise<CredentialInfo[]> {
  return get<CredentialInfo[]>(`/credentials`);
}

/** Probe whether a credential can still authenticate to its target. */
export function testCredential(credentialId: string): Promise<CredentialTestResult> {
  return post<CredentialTestResult>(`/credentials/${encodeURIComponent(credentialId)}/test`, {});
}

/** Rotate a managed key; ``password`` is only needed if the current key no longer works. */
export function rotateCredential(
  credentialId: string,
  password?: string | null,
): Promise<CredentialInfo> {
  return post<CredentialInfo>(`/credentials/${encodeURIComponent(credentialId)}/rotate`, {
    password: password ?? null,
  });
}

/** Revoke a managed key: remove it from the target and delete the local key files. */
export function revokeCredential(
  credentialId: string,
  password?: string | null,
): Promise<CredentialRevokeResult> {
  return post<CredentialRevokeResult>(`/credentials/${encodeURIComponent(credentialId)}/revoke`, {
    password: password ?? null,
  });
}

// ---- agent mTLS identity management ----------------------------------------

/** List stable Agent identities and their non-secret certificate metadata. */
export function listAgentIdentities(): Promise<AgentIdentity[]> {
  return get<AgentIdentity[]>(`/agent-identities`);
}

/**
 * Irreversibly revoke a whole Agent identity and every certificate generation.
 *
 * `generation: null` is intentional: Admin does not expose per-generation
 * revocation, provisioning, or rotation.  Those workflows return/depend on a
 * one-time private-key bundle and must remain outside the browser UI.
 */
export function revokeAgentIdentity(agentId: string): Promise<AgentIdentity> {
  return post<AgentIdentity>(`/agent-identities/${encodeURIComponent(agentId)}/revoke`, {
    generation: null,
  });
}

// ---- resident guard daemon lifecycle ---------------------------------------

/** Probe whether a target's resident guard daemon is alive (常驻 status). */
export function getGuardStatus(targetId: string): Promise<GuardLifecycleStatus> {
  return get<GuardLifecycleStatus>(`/targets/${encodeURIComponent(targetId)}/guard`);
}

/** Stop + uninstall a target's resident guard daemon (常驻 teardown). */
export function stopGuard(targetId: string): Promise<GuardLifecycleStatus> {
  return post<GuardLifecycleStatus>(`/targets/${encodeURIComponent(targetId)}/guard/stop`, {});
}
