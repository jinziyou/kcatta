//! Rust mirror of the cyber-posture flow data contract.
//!
//! The authoritative source of these models is the Pydantic package at
//! `form/src/form/schemas/`. The JSON Schema artifacts under
//! `form/schemas-json/` are derived from there, and these Rust types
//! must serialize to JSON that validates against those schemas.
//!
//! Cross-language conformance is enforced by
//! `collector-core/tests/contract.rs`.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowProto {
    Tcp,
    Udp,
    Icmp,
    Other,
}

/// Severity of a finding. Mirrors `form.schemas.common.Severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Kind of IOC an indicator represents. Mirrors
/// `form.schemas.threat.IndicatorType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorType {
    Ip,
    Domain,
    Ja3,
}

/// One IOC hit observed on a flow (collector-side preliminary
/// processing). Mirrors `form.schemas.threat.ThreatMatch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatMatch {
    pub indicator: String,
    pub indicator_type: IndicatorType,
    pub category: String,
    pub severity: Severity,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    pub flow_id: String,
    pub host_id: String,

    pub start_ts: DateTime<Utc>,
    pub end_ts: DateTime<Utc>,

    pub proto: FlowProto,
    pub src_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_ip: IpAddr,
    pub dst_port: Option<u16>,

    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,

    pub app_proto: Option<String>,
    pub dns_query: Option<String>,
    pub tls_sni: Option<String>,
    pub ja3: Option<String>,

    /// IOC matches found by collector-side preliminary processing.
    /// Serialized as `[]` when empty so the field is always present.
    #[serde(default)]
    pub threat_intel: Vec<ThreatMatch>,
}

/// collector -> form: a batch of flow events from one collector instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowBatch {
    pub batch_id: String,
    pub collected_at: DateTime<Utc>,
    pub collector_id: String,
    pub collector_version: String,
    pub flows: Vec<FlowEvent>,
}
