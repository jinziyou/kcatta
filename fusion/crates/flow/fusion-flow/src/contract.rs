//! Flow data contract — re-exported from the shared `fusion-contract` crate.
//!
//! The flow envelope (`FlowBatch` / `FlowEvent` / …) lives in `fusion-contract`
//! alongside the host `AssetReport` contract so the shared `fusion-ingest`
//! client can serialize both. This module preserves the historical
//! `fusion_flow::contract::*` path used across capture and intel.

pub use fusion_contract::{FlowBatch, FlowEvent, FlowProto, IndicatorType, Severity, ThreatMatch};
