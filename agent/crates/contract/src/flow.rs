//! Network flow contract — the `agent-flow` (network collector) envelope.
//!
//! Mirrors `analyzer.schemas.flow` / `analyzer.schemas.threat`. These types live here
//! alongside the host [`AssetReport`](crate::AssetReport) contract so a single
//! crate is the Rust mirror of `analyzer/schemas-json/` and the `agent` umbrella's
//! built-in ingest can serialize both host and network telemetry.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Severity;

/// Transport / application protocol class of an observed flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowProto {
    /// TCP flow.
    Tcp,
    /// UDP flow.
    Udp,
    /// ICMP flow.
    Icmp,
    /// Any other / unclassified protocol.
    Other,
}

/// Kind of IOC an indicator represents. Mirrors
/// `analyzer.schemas.threat.IndicatorType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorType {
    /// IP address indicator (matched against flow `src_ip` / `dst_ip`).
    Ip,
    /// Domain indicator (matched against `dns_query` / `tls_sni`, parent-domain aware).
    Domain,
    /// JA3 TLS fingerprint indicator (matched against `ja3`).
    Ja3,
}

/// One IOC hit observed on a flow by agent-flow's preliminary processing.
/// Mirrors `analyzer.schemas.threat.ThreatMatch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatMatch {
    /// The matched indicator value (the IP, domain, or JA3 hash).
    pub indicator: String,
    /// Which kind of indicator matched.
    pub indicator_type: IndicatorType,
    /// Free-text category from the feed (e.g. `c2`, `malware`, `phishing`).
    pub category: String,
    /// Severity carried by the matching indicator.
    pub severity: Severity,
    /// Feed / source that supplied the indicator.
    pub source: String,
    /// Optional human-readable context for the match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A single observed network flow (5-tuple aggregate) with optional
/// application-layer metadata and any IOC matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    /// Stable id for this flow within the batch.
    pub flow_id: String,
    /// Host / sensor id that observed the flow.
    pub host_id: String,

    /// First-seen timestamp for the flow.
    pub start_ts: DateTime<Utc>,
    /// Last-seen timestamp for the flow.
    pub end_ts: DateTime<Utc>,

    /// Protocol class.
    pub proto: FlowProto,
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Source port (absent for ICMP).
    pub src_port: Option<u16>,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Destination port (absent for ICMP).
    pub dst_port: Option<u16>,

    /// Bytes sent from source to destination.
    pub bytes_sent: u64,
    /// Bytes received from destination to source.
    pub bytes_recv: u64,
    /// Packets sent from source to destination.
    pub packets_sent: u64,
    /// Packets received from destination to source.
    pub packets_recv: u64,

    /// Detected application protocol (e.g. `SSH`) when known.
    pub app_proto: Option<String>,
    /// DNS query name when the flow carried one.
    pub dns_query: Option<String>,
    /// TLS SNI server name when present in a ClientHello.
    pub tls_sni: Option<String>,
    /// JA3 TLS fingerprint when computed.
    pub ja3: Option<String>,

    /// IOC matches found by agent-flow's preliminary processing.
    /// Serialized as `[]` when empty so the field is always present.
    #[serde(default)]
    pub threat_intel: Vec<ThreatMatch>,
}

/// agent-flow -> analyzer: a batch of flow events from one collector instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowBatch {
    /// Unique id for this batch instance.
    pub batch_id: String,
    /// UTC timestamp when the batch was assembled.
    pub collected_at: DateTime<Utc>,
    /// Id of the collector instance that produced the batch.
    pub collector_id: String,
    /// Version string of the collector that produced the batch.
    pub collector_version: String,
    /// The observed flows.
    pub flows: Vec<FlowEvent>,
}
