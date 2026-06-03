//! Flow data contract — re-exported from the shared `probe-contract` crate.
//!
//! The flow envelope (`FlowBatch` / `FlowEvent` / …) lives in `probe-contract`
//! alongside the host `AssetReport` contract so the shared `probe-ingest`
//! client can serialize both. This module preserves the historical
//! `probe_flow::contract::*` path used across capture and intel.

pub use probe_contract::{FlowBatch, FlowEvent, FlowProto, IndicatorType, Severity, ThreatMatch};
