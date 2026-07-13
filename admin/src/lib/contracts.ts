/**
 * Public contract types for the admin.
 *
 * Generated from Form's public `form/schemas-json/` via `pnpm generate:contracts`.
 * Edit the Form schemas first, then regenerate — do not hand-edit `schemas/`.
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

// Temporary hand-written mirror until AgentIdentity.schema.json is emitted by
// Form and `pnpm generate:contracts` replaces it with a generated module.
export type {
  AgentCertificate,
  AgentCertificateState,
  AgentIdentity,
  AgentIdentityState,
  AgentScope,
} from "./agent-identity";

// Form-owned orchestration contracts generated from Form JSON Schema. `scan.ts`
// only tightens response fields that FastAPI always serializes despite defaults.
export type {
  CredentialActionRequest,
  CredentialInfo,
  CredentialMode,
  CredentialRevokeResult,
  CredentialTestResult,
  GuardLifecycleStatus,
  ScanCapability,
  ScanJob,
  ScanJobOptions,
  ScanJobState,
  ScanMode,
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
