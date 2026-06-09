/**
 * Public contract types for the portal.
 *
 * Generated from `fusion/schemas-json/` via `pnpm generate:contracts`.
 * Edit schemas in Python first, then regenerate — do not hand-edit `schemas/`.
 */

import type {
  Account,
  AssetReport,
  Credential,
  HostInfo,
  Package,
  Port,
  Service,
  Severity,
  Vulnerability,
} from "./schemas/AssetReport";

export type {
  Account,
  AssetReport,
  Credential,
  HostInfo,
  Package,
  Port,
  Service,
  Severity,
  Vulnerability,
};

export type { DetectionResult } from "./schemas/DetectionResult";

export type { Alert, AlertStatus } from "./schemas/Alert";

export type { FlowBatch, FlowEvent, IndicatorType, ThreatMatch } from "./schemas/FlowBatch";

export type { AttackPath, AttackPathStep } from "./schemas/AttackPath";

export type { GuardEventBatch, Events as GuardEvents } from "./schemas/GuardEventBatch";

// Scan orchestration (fusion-internal; hand-mirrored, see ./scan.ts).
export type {
  CredentialMode,
  ScanCapability,
  ScanJob,
  ScanJobOptions,
  ScanJobState,
  ScanResult,
  ScanTarget,
  ScanTargetInput,
  Transport,
  TriggerScanRequest,
} from "./scan";

/** Union of every discoverable asset variant carried by an {@link AssetReport}. */
export type Asset = Package | Service | Port | Account | Credential;

/** Discriminant string identifying which {@link Asset} variant a value is. */
export type AssetKind = NonNullable<Asset["kind"]>;
