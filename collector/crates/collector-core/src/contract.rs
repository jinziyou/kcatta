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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowProto {
    Tcp,
    Udp,
    Icmp,
    Other,
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
