/**
 * Admin-friendly views of Form's generated control-plane contracts.
 *
 * Pydantic JSON Schema marks fields with server defaults as optional because
 * callers may omit them on input. FastAPI response serialization still emits
 * those defaults, so response-only types below make that wire guarantee
 * explicit while deriving every field and enum from generated modules.
 */

import type {
  ScanCapability,
  ScanJob as GeneratedScanJob,
  ScanJobOptions as GeneratedScanJobOptions,
  ScanJobState,
  ScanMode,
  ScanResult as GeneratedScanResult,
} from "./schemas/ScanJob";
import type { ScanTarget as GeneratedScanTarget } from "./schemas/ScanTarget";
import type {
  CredentialMode,
  Transport,
} from "./schemas/ScanTarget";
import type { CredentialInfo as GeneratedCredentialInfo } from "./schemas/CredentialInfo";
import type { GuardLifecycleStatus as GeneratedGuardLifecycleStatus } from "./schemas/GuardLifecycleStatus";

export type { CredentialMode, ScanCapability, ScanJobState, ScanMode, Transport };

/** Execution mode selected by capability: host/trace = 单次, guard = 常驻. */
export type ScanModeView = ScanMode;

export type ScanTarget = Required<GeneratedScanTarget>;
export type ScanTargetInput =
  import("./schemas/ScanTargetInput").ScanTargetInput;

export type ScanJobOptions = Required<GeneratedScanJobOptions>;
export type ScanResult = Required<GeneratedScanResult>;
export type ScanJob = Required<Omit<GeneratedScanJob, "options" | "result">> & {
  options: ScanJobOptions;
  result: ScanResult | null;
};

export type TriggerScanRequest =
  import("./schemas/TriggerScanRequest").TriggerScanRequest;

export type CredentialInfo = Required<GeneratedCredentialInfo>;
export type CredentialActionRequest =
  import("./schemas/CredentialActionRequest").CredentialActionRequest;
export type CredentialTestResult = Required<
  import("./schemas/CredentialTestResult").CredentialTestResult
>;
export type CredentialRevokeResult = Required<
  import("./schemas/CredentialRevokeResult").CredentialRevokeResult
>;

export type GuardLifecycleStatus = Required<GeneratedGuardLifecycleStatus>;
