# kcatta Architecture

> Repo-level architecture synthesis. This document describes how kcatta's four
> components fit together, the contracts that bind them, and the invariants the
> whole system is built on. For the agent's internal crate-level design, see the
> component-level [`agent/docs/ARCHITECTURE.md`](agent/docs/ARCHITECTURE.md).
> For the planned agent pipeline refactor (`agentd` / `collect` / `detect` /
> `respond`), see [`agent/docs/REFACTOR-PIPELINE.md`](agent/docs/REFACTOR-PIPELINE.md).

## 1. Overview

kcatta is a **defensive (blue-team) security-posture platform**: it collects
host and network telemetry from monitored assets, correlates it centrally, and
surfaces the resulting posture — assets, vulnerabilities, alerts, and predicted
attack paths — through a management console.

Three invariants shape the entire design:

- **Collect-only separation.** The on-host collectors (`agent-collect-host`,
  `agent-collect-trace`) only *collect* and write local artifacts. They never report on
  their own. Reporting is owned exclusively by the umbrella `agentd` binary
  (`agentd <cap> --upload` / `agentd run`). The one collector that also *acts*
  on the host is `agent-respond` (real-time protection), which detects and —
  optionally, off by default — responds. All heavy reasoning (CVE matching,
  cross-source correlation, attack-path prediction) lives in the analyzer, not
  on the endpoint.
- **Form-only integration boundary.** Form is the only component allowed to
  communicate with Admin, Analyzer, and Agent. Runtime edges are
  `admin → form → analyzer` and `form ↔ agent`; direct Admin↔Analyzer,
  Analyzer↔Agent, and Agent↔Analyzer links are prohibited and checked in CI.
- **Single-source-of-truth data contract.** The wire contracts between
  components are defined once as Pydantic models in the analyzer
  (`analyzer/src/analyzer/schemas/`). Those models are exported to JSON Schema
  and published by Form as its public boundary (`form/schemas-json/`), which in
  turn drives the Rust agent's `agent-contract` crate and TypeScript Admin types. CI fails on any drift
  (`make schema-check`, `make contracts-check`).

## 2. Domain model

The contracts fall into three groups: collector **uplink envelopes** (Agent →
Form → Analyzer), Analyzer-**derived** outputs (Analyzer → Form → Admin), and one **external**
input.

| Model | Direction | Produced by | Meaning |
| --- | --- | --- | --- |
| `AssetReport` | uplink | `agent-collect-host` | Host static inventory: host info, packages, SBOM, services, ports, accounts, credentials, containers, and built-in malware-scan hits. |
| `TraceBatch` | uplink | `agent-collect-trace` | Three streams: network `events` (5-tuple metadata + threat-intel IOC hits), plus `file_events` / `process_events` (eBPF tracepoints). |
| `GuardEventBatch` | uplink | `agent-respond` | Real-time protection events (FIM / on-access / behavior / network / IDS) and any response action taken. |
| `CapabilityGraph` | external input | red-team exporter (out of repo) | Opaque reference knowledge: techniques with pre/postconditions + attack templates. The analyzer reasons over it, never executes it. |
| `DetectionResult` | derived | analyzer `detect` | Vulnerabilities for one `AssetReport` (OSV CVE matches + built-in malware findings, combined). |
| `Alert` | derived | analyzer `correlate` | Correlated finding: per-IOC trace aggregation, plus cross-source compound alerts joining IOC hits against vulnerable hosts. |
| `AttackPath` | derived | analyzer `predict` | A predicted chain of `AttackPathStep`s (technique applied on a host) derived from posture + the capability graph. |

Contract conventions (enforced in code): every model inherits `StrictModel`
(`extra="forbid"`, so unknown fields fail loudly); `Asset` is a discriminated
union keyed on `kind`; all timestamps are UTC-aware (`Timestamp`). The
authoritative analysis model definitions live in `analyzer/src/analyzer/schemas/`;
Form publishes the public JSON Schema exports in `form/schemas-json/`.
`ScanTarget`, `ScanJob`, credential and Guard lifecycle models are owned by
`form/src/kcatta_form/schemas/scan.py`.

## 3. Components & boundaries

```
agent/      Rust workspace — on-host collection + real-time protection
form/       Python / FastAPI — public API, orchestration, agent gateway/facade
analyzer/   Python / FastAPI — private ingest, detect, correlate, predict
admin/      Next.js console — read views + scan triggering through Form
```

**agent** is a Rust workspace organized as a pipeline (`agentd` / `collect` /
`detect` / `respond`) under `agent/crates/`. Deploy binaries keep legacy names
(`agent-collect-host` / `agent-collect-trace` / `agent-respond` / `agentd`). See
[`agent/docs/ARCHITECTURE.md`](agent/docs/ARCHITECTURE.md).

- `agent-contract` (`crates/contract`) — Rust mirror of the **Python analyzer**
  schemas. Zero internal dependencies.
- `agent-detect` / `agent-detect-malware` (`crates/detect*`) — on-host finding
  engines (posture / secrets / malware). Not the Python analyzer.
- `agent-collect-host` (`crates/collect/host`) — host inventory collectors + thin detect
  adapters. **Collect-only**, writes files.
- `agent-collect-trace` (`crates/collect/trace`) — `capture_batch` + IOC enrich +
  intel-sync (+ optional eBPF). **Collect-only**, writes files.
- `agent-respond` (`crates/respond`) — real-time protection; optional active
  response (default off).
- `agentd` (`crates/agentd`) — umbrella + **owns ingest** (`--upload` / `run`).
- `agent-ebpf` (`crates/ebpf`) — eBPF support; out of `default-members`.

**form** is the sole control plane and integration boundary. It owns target/job
state, credentials, SSH/WinRM/local deployment, Guard lifecycle, per-target
Agent identity/PKI, Agent ingest gateway, and the Admin-facing facade. The
component is split into a control process (`form-api`, `:10067`) and a dedicated
Agent process (`form-agent-api`, `:10443`). The latter requires mTLS and registers
only the three telemetry ingest routes plus health probes; it has no Admin,
target, scan, credential, query, or capability-graph routes. Both call Analyzer
over a private network with a separate internal service credential. Target registry state uses
`form.db` when configured for SQLite; the durable job queue always uses
`form-jobs.db`, with Analyzer handoff artifacts in `scan-artifacts/`. All are
separate from Analyzer's `analyzer.db`.

The control process owns the Agent CA signing key and certificate lifecycle.
The Agent listener receives only its server leaf/key, the public CA certificate,
and the shared identity registry—never the signing key or deployment
credentials. A verified client certificate resolves to a stable Agent ID,
target, canonical host and route scopes; Form derives provenance from that
principal instead of trusting envelope claims or proxy headers.

**analyzer** is a private FastAPI service that ingests Form-validated envelopes,
runs self-implemented OSV vulnerability detection (`detect/`), rule-based
correlation (`correlate/`), and attack-path prediction (`predict/`). Persistence
is JSONL (default) or SQLite (`storage/`); it has no Agent deployment or Admin
orchestration API.

**admin** is a Next.js (App Router) console: read views over Form's facade
`/reports/*` and `/attack-paths` routes, plus the write path —
registering targets and triggering scans via Server Actions that call
`POST /targets` / `POST /scans`. The bearer token stays server-side; the browser
never holds it.

**Runtime directions:** `admin → form → analyzer` and `form ↔ agent`. Form
dispatches Agent and accepts telemetry; Analyzer and Admin cannot address Agent,
and neither Admin nor Agent can address Analyzer. Analyzer's Pydantic analysis
models feed Form's public contract export, from which Agent and Admin types are generated.

## 4. Data flow

```
                         MONITORED ASSET (host)
   ┌──────────────────────────────────────────────────────────────┐
   │  collectors ──► AssetReport / TraceBatch (local artifacts)    │
   │  agentd     ──► GuardEventBatch / optional collected upload   │
   └───────▲───────────────────────────────┬──────────────────────┘
           │ SSH/WinRM deploy              │ per-Agent mTLS
           │                               │ only 3 × /ingest/*
   ┌───────┴───────────────────────────────▼──────────────────────┐
   │                         FORM COMPONENT                       │
   │ form-api :10067              form-agent-api :10443           │
   │ control/facade/deploy/CA      strict mTLS ingest only         │
   │          │             shared identity registry              │
   └──────────┼──────────────────────────┬────────────────────────┘
              │ private internal API     │ private internal ingest
              └─────────────┬────────────┘
                            ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                         analyzer (:10068)                     │
   │  ingest  ── stores envelope, then best-effort:                │
   │            • detect/  OSV CVE match + malware → DetectionResult│
   │            • correlate/  IOC aggregate + cross-source → Alert  │
   │  predict/  CapabilityGraph + posture → AttackPath  (on demand) │
   └──────────────────────────────────────────────────────────────┘

   ┌──────────────────────────────────────────────────────────────┐
   │ admin (:10063) ── server-side bearer ──► form-api (:10067)   │
   │  reports · vulnerabilities · alerts · traces · guard ·        │
   │  attack-paths · targets · scans                               │
   └──────────────────────────────────────────────────────────────┘

   External input: red-team exporter ──► Form /ingest/capability-graph
                                      ──► Analyzer internal ingest
```

**Active scan loop (admin-triggered, closed-loop).** The admin registers a
target and durably enqueues a scan through Form. A lifespan-owned worker claims
the `ScanJob` from `form-jobs.db` with a renewable lease and epoch fencing,
ships Agent over SSH/WinRM (or runs local), then atomically spools the collected
artifact before POSTing it to Analyzer's private ingest API. Analyzer retries
reuse the same report/batch identity; cancel/retry and expired-lease recovery
survive an HTTP request or Form restart. The execution boundary is at-least-once,
so remote actions remain idempotent/compensatable. An expired final `running`
execution uses a capped `max_attempts + 1` reconciliation attempt number (later
reclaims stay at that number): host/trace may only forward an existing durable
artifact, while Guard may only join an already committed deployment; neither
path repeats an unfenced remote action.

Resident Guard runs as `agentd respond --upload <agent-form-url>` and returns
through Form's dedicated mTLS listener. Form serializes operations per target
in the job store and also takes an owner-fenced, expiring lock on the target.
Guard publication is a remote transaction: it retains the previous files and
identity pointer, proves the new daemon alive, publishes a manifest containing
the deployment/identity generation, content hashes, paths, unit and PID, and
only then activates the staged certificate. Recovery observes manifest and
liveness under the same remote lock; cancellation tears down only an exact
manifest match, so a stale worker cannot stop a newer Guard. During a bounded
mixed-mode migration, an older fleet-token Guard may still use the control
listener; strict mode removes that path. Admin polls Form for job state and
results.

**Per-target architecture selection.** The deploy layer probes the target's
`uname -m` and normalizes it (`amd64`→`x86_64`, `arm64`→`aarch64`), then picks
the matching static-musl binary from `FORM_AGENT_TARGET_DIR/<triple>/release/`
(`x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`). A single
registered target works on either arch with no per-job binary pinning.

## 5. Tech stack & key tradeoffs

| Component | Stack | Why |
| --- | --- | --- |
| agent | Rust (stable; `unsafe_code = "deny"`), static **musl** deploy binaries | Memory-safe collectors; static linking → run on any Linux target regardless of glibc. Form ships these artifacts remotely. |
| agent eBPF | optional `ebpf` feature (nightly + bpf-linker at build time; CAP_BPF/BTF at runtime) | Kernel-level process/file tracing and cgroup-connect netblock. Opt-in + privileged; unavailable live trace fails rather than fabricating mock data, while guard netblock may fall back to nft. |
| form | Python 3.11+ / FastAPI / Pydantic v2 / cryptography / paramiko / optional pywinrm | One authenticated integration boundary, split into a control/orchestration process and a least-privilege Agent mTLS listener. |
| analyzer | Python 3.11+ / FastAPI / Pydantic v2 / uvicorn | Fast iteration on detection/correlation logic; private analysis service. |
| admin | Next.js 16 / React 19 / TypeScript (strict) / Tailwind v4 / shadcn-style components (`@base-ui/react`) / React Flow | Server Components fetch Form server-side; no upstream token reaches the browser. |

Notable tradeoff: vulnerability detection is **self-implemented in the
analyzer** (OSV records + per-ecosystem version comparison) rather than shelling
out to a third-party scanner. This keeps one central advisory store that can
back-match historical inventories, at the cost of owning the matching logic.

## 6. Key invariants & constraints

1. **Collect-only separation of collection and reporting.** `agent-collect-host` and
   `agent-collect-trace` only collect and write local files. The umbrella `agentd` is
   the *only* thing that uploads (ingest lives in `crates/agentd`). `agent-respond`
   is the sole capability that acts on the host, and even then responses are off
   by default and guarded by multiple safety vetoes.
2. **Pydantic schema is the single source of truth.** Analyzer analysis models
   plus Form control models → Form public JSON Schema (`form/schemas-json/`) → consumed by the
   Rust `agent-contract` crate and the admin's generated TS types. **CI enforces
   no drift**: `make schema-check` re-exports and fails if `schemas-json/`
   changed; `make contracts-check` regenerates `admin/src/lib/schemas/` and fails
   on diff.
3. **Self-implemented OSV detection — no third-party scanners.** The analyzer
   matches `AssetReport` package manifests against a local OSV advisory store
   with its own per-ecosystem comparators (dpkg / PEP 440 / rpm EVR / apk /
   SemVer). There is **no trivy/grype** in the detection path. (CI does run a
   Trivy *image* scan, but that scans the built container images for hardening —
   it is not part of the analyzer's vulnerability engine.)
4. **Strict contracts.** Every contract model forbids unknown fields; unexpected
   upstream data fails loudly rather than being silently dropped.
5. **Separated trust domains and endpoint principals.** `FORM_API_TOKEN`
   authorizes Admin control/query, per-Agent client certificates authorize only
   their assigned telemetry scopes on `:10443`, and `ANALYZER_INTERNAL_TOKEN`
   authorizes Form→Analyzer private calls. `FORM_INGEST_TOKEN` is a fleet-wide
   compatibility credential only for mixed/legacy migration and is rejected in
   strict mTLS mode. Revocation is checked from the identity registry on every
   request; certificate-derived target/host provenance overrides untrusted wire
   claims.
6. **Managed credentials.** Remote-scan targets store only metadata + a
   credential *mode*; the long-term credential is a managed SSH key or WinRM
   client certificate on the Form host. A one-time bootstrap password is
   discarded after installation and never persisted. SSH host identity is
   pinned in persistent known_hosts; WinRM validates TLS by default.
7. **Agent leaf keys are ephemeral at Form.** In the current MVP, Form generates
   a client leaf key in memory and returns it only in the newly staged
   generation's one-time bundle. Managed Guard deployment installs that bundle
   through the already authenticated SFTP channel; neither the identity
   registry nor CA service persists the leaf key. Rotation activates only after
   installation and grants the retired generation a 10-minute overlap; revoke
   is immediate. CSR enrollment and TPM/HSM-backed non-exportable endpoint keys
   are explicitly future work, not properties of this MVP.
8. **Guard ownership is proved, not inferred from a process name.** Deployment,
   proof and conditional teardown share the remote owner-fenced lock. The exact
   manifest PID is normally required. A changed systemd `MainPID` is accepted
   only for an mTLS deployment after Form proves the binary/config hashes,
   current identity generation and `/proc/<pid>/exe`, then CAS-updates the old
   manifest bytes. Legacy bearer deployments have no identity generation nonce
   and therefore never receive this PID relaxation; an ambiguous crash remains
   fail-closed and may require operator cleanup.
9. **Server and client leaf rotation are separate.** The control process
   automatically renews the listener server leaf before expiry and publishes an
   atomic generation; `form-agent` validates it and gracefully recycles onto a
   new SSL context while retaining the last-known-good generation on failure.
   Endpoint client leaves can be hot-loaded after installation, but Form does
   not yet schedule their issuance and remote installation. They still require
   managed Guard redeployment or an explicit provision/rotate workflow.

## 7. Deployment forms

**Local stack (Analyzer + Form + Admin).** `make compose-up` (i.e. `docker compose up
--build`) brings up:

- `analyzer` on private port **10068** — reachable only on the internal
  Form↔Analyzer network.
- `form` on port **10067** — Admin/control/facade and external inputs; during
  mixed migration it also accepts the legacy bearer ingest path.
- `form-agent` on port **10443** — the dedicated strict-mTLS Agent listener with
  only the three telemetry ingest routes.
- `admin` on port **10063** — RSC fetches reach Form server-side.
- A one-shot `token-init` generates control, legacy-ingest, and internal tokens.

The two Form processes share only the Agent identity registry and Analyzer
network. The CA signing key and remote deployment credentials are mounted into
`form`, not `form-agent`; the listener sees only its server key/cert and public
CA. Compose defaults to mixed migration mode. Once all resident Agents use
per-Agent certificates, strict mTLS mode makes the fleet token unnecessary.

The Form image bundles Agent's x86_64 static-musl deploy binaries (the Agent
source is an extra build context) so SSH host/trace/guard scans work out
of the box for x86_64 Linux targets. It also carries the Windows GNU
`agent-collect-host.exe` used by WinRM host scans.

**Agent deploy artifacts (multi-arch musl).** Built from the repo root:

- `make build-agent-deploy` → `x86_64-unknown-linux-musl` (needs `musl-tools`)
- `make build-agent-deploy-arm64` → `aarch64-unknown-linux-musl` (uses `cross`)
- `make build-agent-deploy-windows` → `x86_64-pc-windows-gnu` host collector
  (needs `gcc-mingw-w64-x86-64`)

Each arch produces `agent-collect-host`, `agent-collect-trace`, and `agentd` (built with
`onaccess,network,ids` so `agentd respond` ships the full sensor set; pcap and
eBPF are intentionally excluded from deploy binaries). Form selects the
arch automatically per the target's `uname -m`.

**CI.** Push/PR runs per-component build+test jobs (`agent`, `form`, `analyzer`,
`admin`), the eBPF kernel build, two musl deploy builds, component-boundary and
schema/contract drift checks, a dependency audit, secret/image/SAST
scans, and the `e2e` (Playwright) job. See
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## 8. Doc map

| Document | Scope |
| --- | --- |
| [`README.md`](README.md) | Project intro, four-component overview, data flow, quick start. |
| **`ARCHITECTURE.md`** (this file) | Repo-level synthesis: domain model, components, data flow, invariants. |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Deployment runbook: compose, tokens, exposed surfaces, agent deploy binaries, preflight checks. |
| [`agent/README.md`](agent/README.md) | Agent usage: three capabilities, run modes, deploy builds, features. |
| [`agent/docs/ARCHITECTURE.md`](agent/docs/ARCHITECTURE.md) | Component-level agent architecture: crate DAG, guard pipeline, eBPF. |
| [`form/README.md`](form/README.md) | Public API, orchestration, Agent deployment, trust domains, public schemas. |
| [`analyzer/README.md`](analyzer/README.md) | Private Analyzer API, detection, correlation and prediction. |
| [`form/schemas-json/README.md`](form/schemas-json/README.md) | Form-published public JSON Schema contract. |
| [`admin/README.md`](admin/README.md) | Admin console: routes, contract generation, dev/build. |
| [`DCO.md`](DCO.md) · [`.github/BRANCH_PROTECTION.md`](.github/BRANCH_PROTECTION.md) · [`agent/docs/CONTRIBUTING.md`](agent/docs/CONTRIBUTING.md) | DCO 签核、分支保护、agent 贡献流程。 |
