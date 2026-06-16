/**
 * Public contract types for the admin.
 *
 * Generated from `analyzer/schemas-json/` via `pnpm generate:contracts`.
 * Edit schemas in Python first, then regenerate — do not hand-edit `schemas/`.
 */

import type {
  Account,
  AssetReport,
  Container,
  Credential,
  HostInfo,
  // The generated name is `Image1` because the Container.image field aliases to
  // `Image`; this is the first-class image ASSET interface (kind: "image").
  Image1 as Image,
  Package,
  Port,
  Service,
  Severity,
  Vulnerability,
} from "./schemas/AssetReport";

export type {
  Account,
  AssetReport,
  Container,
  Credential,
  HostInfo,
  Image,
  Package,
  Port,
  Service,
  Severity,
  Vulnerability,
};

export type { DetectionResult } from "./schemas/DetectionResult";

export type { Alert, AlertStatus } from "./schemas/Alert";

export type { TraceBatch, TraceEvent, IndicatorType, ThreatMatch } from "./schemas/TraceBatch";

export type { AttackPath, AttackPathStep } from "./schemas/AttackPath";

export type { GuardEventBatch, Events as GuardEvents } from "./schemas/GuardEventBatch";

// Scan orchestration (analyzer-internal; hand-mirrored, see ./scan.ts).
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
export type Asset = Package | Service | Port | Account | Credential | Container | Image;

/** Discriminant string identifying which {@link Asset} variant a value is. */
export type AssetKind = NonNullable<Asset["kind"]>;
