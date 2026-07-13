//! agent-respond library: real-time protection engine.
//!
//! A long-running endpoint daemon that **detects, responds, and reports** in
//! real time — the capability that intentionally crosses the otherwise
//! collect-only agent boundary. Sensors feed [`Detection`]s through a
//! detect → decide → respond → report [`Pipeline`]; events (and any response
//! action taken) are reported to analyzer as `agent_contract::GuardEventBatch`
//! and to a local NDJSON audit log.
//!
//! # Safety by default
//!
//! [`GuardConfig`] ships [`Mode::Monitor`] with every active-response gate off:
//! out of the box the daemon observes and reports but performs no destructive
//! action. Enforcement requires a deliberate mode + per-action opt-in, and every
//! action passes a safety veto (critical paths, system binaries, PID 1 / self,
//! files mapped by running processes) plus an idempotency ledger.
//!
//! # Sensors
//!
//! - `fim` — Linux inotify / Windows ReadDirectoryChangesW via `notify` (default)
//! - `behavior` — Linux `/proc` process-behavior rules (default feature)
//! - `onaccess` — fanotify + built-in signature scanner (reuses
//!   `agent-detect`'s malware engine; needs `CAP_SYS_ADMIN`)
//! - `network` / `ids` — `agent-collect-trace` capture + `agent-detect` IOC/IDS
//!
//! OS access goes through safe wrappers (`nix` on Linux, `notify` / `ctrlc` on
//! Windows), so the crate builds under the workspace `unsafe_code = "deny"` lint.

mod audit;
pub mod cli;
mod config;
mod context;
mod decide;
mod pipeline;
mod report;
mod respond;
mod safety;
mod sensors;
mod supervisor;

/// Kernel eBPF egress-blocking backend (feature `ebpf`).
#[cfg(feature = "ebpf")]
pub mod ebpf_block;

pub use agent_contract::Detection;
pub use config::{
    BehaviorConfig, FimConfig, GuardConfig, Mode, NetworkConfig, OnAccessConfig, ReportConfig,
    ResponsePolicy,
};
pub use context::GuardContext;
pub use decide::Action;
pub use pipeline::Pipeline;
pub use report::{NdjsonSink, ReportSink, Reporter, StdoutSink};
pub use respond::Responder;
pub use supervisor::Supervisor;
