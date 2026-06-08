//! Flow data contract — re-exported from the shared `agent-contract` crate.
//!
//! The flow envelope (`FlowBatch` / `FlowEvent` / …) lives in `agent-contract`
//! alongside the host `AssetReport` contract so the shared `agent-ingest`
//! client can serialize both. This module preserves the historical
//! `agent_flow::contract::*` path used across capture and intel.

pub use agent_contract::{FlowBatch, FlowEvent, FlowProto, IndicatorType, Severity, ThreatMatch};
