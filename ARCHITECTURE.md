# kcatta Architecture

> Repo-level architecture synthesis. This document describes how kcatta's three
> components fit together, the contracts that bind them, and the invariants the
> whole system is built on. For the agent's internal crate-level design, see the
> component-level [`agent/docs/ARCHITECTURE.md`](agent/docs/ARCHITECTURE.md).

## 1. Overview

kcatta is a **defensive (blue-team) security-posture platform**: it collects
host and network telemetry from monitored assets, correlates it centrally, and
surfaces the resulting posture — assets, vulnerabilities, alerts, and predicted
attack paths — through a management console.

Two invariants shape the entire design:

- **Collect-only separation.** The on-host collectors (`agent-host`,
  `agent-trace`) only *collect* and write local artifacts. They never report on
  their own. Reporting is owned exclusively by the umbrella `agentd` binary
  (`agentd <cap> --upload` / `agentd run`). The one collector that also *acts*
  on the host is `agent-guard` (real-time protection), which detects and —
  optionally, off by default — responds. All heavy reasoning (CVE matching,
  cross-source correlation, attack-path prediction) lives in the analyzer, not
  on the endpoint.
- **Single-source-of-truth data contract.** The wire contracts between
  components are defined once as Pydantic models in the analyzer
  (`analyzer/src/analyzer/schemas/`). Those models are exported to JSON Schema
  (`analyzer/schemas-json/`), which in turn drives the Rust agent's
  `agent-contract` crate and the TypeScript admin types. CI fails on any drift
  (`make schema-check`, `make contracts-check`).

## 2. Domain model

The contracts fall into three groups: collector **uplink envelopes** (agent →
analyzer), analyzer-**derived** outputs (analyzer → admin), and one **external**
input.

| Model | Direction | Produced by | Meaning |
| --- | --- | --- | --- |
| `AssetReport` | uplink | `agent-host` | Host static inventory: host info, packages, SBOM, services, ports, accounts, credentials, containers, and built-in malware-scan hits. |
| `TraceBatch` | uplink | `agent-trace` | Three streams: network `events` (5-tuple metadata + threat-intel IOC hits), plus `file_events` / `process_events` (eBPF tracepoints). |
| `GuardEventBatch` | uplink | `agent-guard` | Real-time protection events (FIM / on-access / behavior / network / IDS) and any response action taken. |
| `CapabilityGraph` | external input | red-team exporter (out of repo) | Opaque reference knowledge: techniques with pre/postconditions + attack templates. The analyzer reasons over it, never executes it. |
| `DetectionResult` | derived | analyzer `detect` | Vulnerabilities for one `AssetReport` (OSV CVE matches + built-in malware findings, combined). |
| `Alert` | derived | analyzer `correlate` | Correlated finding: per-IOC trace aggregation, plus cross-source compound alerts joining IOC hits against vulnerable hosts. |
| `AttackPath` | derived | analyzer `predict` | A predicted chain of `AttackPathStep`s (technique applied on a host) derived from posture + the capability graph. |

Contract conventions (enforced in code): every model inherits `StrictModel`
(`extra="forbid"`, so unknown fields fail loudly); `Asset` is a discriminated
union keyed on `kind`; all timestamps are UTC-aware (`Timestamp`). The
authoritative model definitions live in `analyzer/src/analyzer/schemas/`; their
JSON Schema exports live in `analyzer/schemas-json/`. (`ScanTarget` / `ScanJob`
in `schemas/scan.py` are analyzer-internal orchestration models and are *not*
exported to `schemas-json/`.)

## 3. Components & boundaries

```
agent/      Rust workspace — on-host collection + real-time protection
analyzer/   Python / FastAPI — ingest, detect, correlate, predict, dispatch
admin/      Next.js console — read views + scan triggering
```

**agent** is a Rust workspace of one contract crate + three capabilities + an
umbrella + an eBPF support crate (`agent/crates/`):

- `agent-contract` (`crates/contract`) — Rust mirror of the analyzer schemas
  (`AssetReport` / `TraceBatch` / `GuardEventBatch` + shared enums). Zero
  internal dependencies.
- `agent-host` (`crates/host`) — host static file detection + built-in
  signature malware scan. **Collect-only**, writes files.
- `agent-trace` (`crates/trace`) — network capture + IOC matching + intel-sync,
  and (under the `ebpf` feature) process/file tracepoints. **Collect-only**,
  writes files.
- `agent-guard` (`crates/guard`) — long-running real-time protection daemon;
  detects and (optionally, default off) responds on the host.
- `agentd` (`crates/agentd`) — the umbrella binary: dispatches `agentd
  host|trace|guard` in-process and **owns ingest** (`--upload` / `agentd run`
  POST to the analyzer).
- `agent-ebpf` (`crates/ebpf`) — shared eBPF event-struct lib + two
  bpf-target-only kernel programs (`trace-ebpf`, `guard-ebpf`); kept out of
  `default-members` so host builds never compile the kernel bins.

**analyzer** is a FastAPI service that ingests envelopes, runs self-implemented
OSV vulnerability detection (`detect/`), rule-based correlation (`correlate/`),
attack-path prediction (`predict/`), and dispatches remote scans over SSH/WinRM
(`deploy/`). Persistence is JSONL (default) or SQLite (`storage/`).

**admin** is a Next.js (App Router) console: read views over the analyzer's
`/reports/*` and `/attack-paths` routes, plus the only write path —
registering targets and triggering scans via Server Actions that call
`POST /targets` / `POST /scans`. The bearer token stays server-side; the browser
never holds it.

**Dependency directions (one-way):** `admin → analyzer → agent`. The admin only
talks to the analyzer; the analyzer dispatches and ingests the agent; the agent
depends on nothing upstream. The contract flows the other way: the analyzer's
Pydantic schema is the source from which the agent's Rust contract and the
admin's TS types are generated.

## 4. Data flow

```
                       MONITORED ASSET (host)
   ┌──────────────────────────────────────────────────────────────┐
   │  agent-host  ──► AssetReport (file)                           │
   │  agent-trace ──► TraceBatch  (events + file_events + proc)    │   collect-only:
   │  agent-guard ──► GuardEventBatch (local NDJSON)               │   never self-reports
   └───────────────────────────┬──────────────────────────────────┘
                               │  only via agentd:
                               │  agentd <cap> --upload  /  agentd run
                               ▼
              POST /ingest/{asset-report, trace-batch, guard-event}   (202 Accepted)
   ┌──────────────────────────────────────────────────────────────┐
   │                         analyzer  (:10068)                    │
   │  ingest  ── stores envelope, then best-effort:                │
   │            • detect/  OSV CVE match + malware → DetectionResult│
   │            • correlate/  IOC aggregate + cross-source → Alert  │
   │  predict/  CapabilityGraph + posture → AttackPath  (on demand) │
   │  deploy/   dispatch agent over SSH/WinRM (admin-triggered)     │
   └───────────────────────────┬──────────────────────────────────┘
                               │  GET /reports/*  ·  /attack-paths
                               ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                          admin  (:10063)                      │
   │  reports · vulnerabilities · alerts · traces · guard ·        │
   │  attack-paths · targets · scans                               │
   └──────────────────────────────────────────────────────────────┘

   External input:  red-team exporter ──► POST /ingest/capability-graph
                    (opaque JSON; newest wins; analyzer reasons, never executes)
```

**Active scan loop (admin-triggered, closed-loop).** The admin registers a
target (`POST /targets`) and triggers a scan (`POST /scans`). The analyzer
creates an async `ScanJob`, and the `deploy/` layer ships the agent over SSH to
the target: `agent-host` / `agent-trace` run once and their artifacts are pulled
back and ingested through the *same* `store_asset_report` / `store_trace_batch`
path as a direct agent upload; `agent-guard` is deployed as the `agentd` binary
and left running as `agentd guard --upload` to push `GuardEventBatch`es
continuously. The admin polls `GET /scans/{job_id}` (pending → running →
succeeded/failed) and views results by id.

**Per-target architecture selection.** The deploy layer probes the target's
`uname -m` and normalizes it (`amd64`→`x86_64`, `arm64`→`aarch64`), then picks
the matching static-musl binary from `ANALYZER_AGENT_TARGET_DIR/<triple>/release/`
(`x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`). A single
registered target works on either arch with no per-job binary pinning.

## 5. Tech stack & key tradeoffs

| Component | Stack | Why |
| --- | --- | --- |
| agent | Rust (stable; `unsafe_code = "deny"`), static **musl** deploy binaries | Memory-safe collectors; static linking → run on any Linux target regardless of glibc. The deploy artifacts are what the analyzer ships remotely. |
| agent eBPF | optional `ebpf` feature (nightly + bpf-linker at build time; CAP_BPF/BTF at runtime) | Kernel-level process/file tracing and cgroup-connect netblock. **Opt-in + privileged + graceful fallback** to pcap/mock (trace) or nft (guard); never compiled into the musl deploy binaries. |
| analyzer | Python 3.11+ / FastAPI / Pydantic v2 / uvicorn; paramiko (SSH), optional pywinrm | Fast iteration on detection/correlation logic; Pydantic gives the contract source of truth for free. |
| admin | Next.js 16 / React 19 / TypeScript (strict) / Tailwind v4 / shadcn-style components (`@base-ui/react`) / React Flow | Server Components fetch the analyzer server-side (token never reaches the browser); React Flow renders attack-path graphs. |

Notable tradeoff: vulnerability detection is **self-implemented in the
analyzer** (OSV records + per-ecosystem version comparison) rather than shelling
out to a third-party scanner. This keeps one central advisory store that can
back-match historical inventories, at the cost of owning the matching logic.

## 6. Key invariants & constraints

1. **Collect-only separation of collection and reporting.** `agent-host` and
   `agent-trace` only collect and write local files. The umbrella `agentd` is
   the *only* thing that uploads (ingest lives in `crates/agentd`). `agent-guard`
   is the sole capability that acts on the host, and even then responses are off
   by default and guarded by multiple safety vetoes.
2. **Pydantic schema is the single source of truth.** The analyzer's
   `schemas/*.py` → exported JSON Schema (`schemas-json/`) → consumed by the
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
5. **Auth posture.** All routes except `/health` require a bearer token when
   `ANALYZER_API_TOKEN` is set. Unset → open (dev only). `docker compose`
   auto-generates a strong random token per deployment rather than shipping a
   default.
6. **Managed credentials.** Remote-scan targets store only metadata + a
   credential *mode*; the long-term credential is a managed SSH key on the
   analyzer host. A one-time bootstrap password is discarded after key install
   and never persisted.

## 7. Deployment forms

**Local stack (analyzer + admin).** `make compose-up` (i.e. `docker compose up
--build`) brings up:

- `analyzer` on port **10068** — reachable on the compose network as
  `http://analyzer:10068`; not published to the host by default. SQLite storage,
  bearer auth.
- `admin` on port **10063** — the only service published to the host
  (`http://localhost:10063`). Behind it, RSC fetches reach the analyzer
  server-side.
- A one-shot `token-init` service generates a per-deployment `ANALYZER_API_TOKEN`
  into a shared volume (override via env / `.env`).

The analyzer image bundles the agent's static-musl deploy binary (the agent
source is an extra build context) so remote scanning works out of the box.

**Agent deploy artifacts (multi-arch musl).** Built from the repo root:

- `make build-agent-deploy` → `x86_64-unknown-linux-musl` (needs `musl-tools`)
- `make build-agent-deploy-arm64` → `aarch64-unknown-linux-musl` (uses `cross`)

Each arch produces `agent-host`, `agent-trace`, and `agentd` (built with
`onaccess,network,ids` so `agentd guard` ships the full sensor set; pcap and
eBPF are intentionally excluded from deploy binaries). The analyzer selects the
arch automatically per the target's `uname -m`.

**CI.** Push/PR runs per-component build+test jobs (`agent`, `analyzer`,
`admin`), the eBPF kernel build, two musl deploy builds (x86_64 / aarch64),
schema/contract drift checks, a non-blocking dependency audit, secret/image/SAST
scans, and the `e2e` (Playwright) job. See
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## 8. Doc map

| Document | Scope |
| --- | --- |
| [`README.md`](README.md) | Project intro, three-component overview, data flow, quick start. |
| **`ARCHITECTURE.md`** (this file) | Repo-level synthesis: domain model, components, data flow, invariants. |
| [`agent/README.md`](agent/README.md) | Agent usage: three capabilities, run modes, deploy builds, features. |
| [`agent/docs/ARCHITECTURE.md`](agent/docs/ARCHITECTURE.md) | Component-level agent architecture: crate DAG, guard pipeline, eBPF. |
| [`analyzer/README.md`](analyzer/README.md) | Analyzer: API reference, detection engine, correlation, remote scan. |
| [`analyzer/schemas-json/README.md`](analyzer/schemas-json/README.md) | The generated JSON Schema contract (do not hand-edit). |
| [`admin/README.md`](admin/README.md) | Admin console: routes, contract generation, dev/build. |
| [`SECURITY.md`](SECURITY.md) · [`GOVERNANCE.md`](GOVERNANCE.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) | Security policy, governance, contribution + DCO. |
