//! Flow data contract — re-exported from the shared `agent-contract` crate.
//!
//! The flow envelope (`TraceBatch` / `TraceEvent` / …) lives in `agent-contract`
//! alongside the host `AssetReport` contract so a single crate mirrors
//! `analyzer/schemas-json/` (the `agentd` umbrella's built-in ingest serializes
//! both). This module preserves the `agent_trace::contract::*` path used
//! across capture and intel.

pub use agent_contract::{
    IndicatorType, Severity, ThreatMatch, TraceBatch, TraceEvent, TraceProto,
};
