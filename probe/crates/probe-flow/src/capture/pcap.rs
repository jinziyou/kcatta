//! Live packet capture via libpcap with 5-tuple flow aggregation.
//!
//! Opens a network interface, applies a BPF filter, reads packets for a
//! fixed duration, aggregates them into `FlowEvent`s, and enriches each
//! flow with DNS / TLS metadata parsed from payloads.
//!
//! Requires the `pcap` feature and libpcap at build time. Typically needs
//! root or `CAP_NET_RAW` to capture on real interfaces.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeZone, Utc};
use pcap::{Capture, Device};

use crate::contract::{FlowEvent, FlowProto};

use super::parse::{self, ParsedPacket};

/// Configuration for a pcap capture cycle.
#[derive(Debug, Clone)]
pub struct PcapConfig {
    /// Network interface name (`any`, `eth0`, `lo`, ...).
    pub iface: String,
    /// How long to capture before returning the aggregated batch.
    pub duration: Duration,
    /// BPF filter expression passed to libpcap.
    pub bpf: String,
}

impl Default for PcapConfig {
    fn default() -> Self {
        Self {
            iface: "any".to_string(),
            duration: Duration::from_secs(5),
            bpf: "tcp or udp or icmp".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: FlowProto,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

struct FlowAccumulator {
    key: FlowKey,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    bytes_sent: u64,
    packets_sent: u64,
    app_proto: Option<String>,
    dns_query: Option<String>,
    tls_sni: Option<String>,
    ja3: Option<String>,
}

/// Capture and aggregate flows from a live interface.
pub fn capture(host_id: &str, config: &PcapConfig) -> anyhow::Result<Vec<FlowEvent>> {
    let device = resolve_device(&config.iface)?;
    let mut cap = Capture::from_device(device)
        .map_err(|e| anyhow::anyhow!("open device {}: {e}", config.iface))?
        .promisc(true)
        .snaplen(65535)
        .timeout(500)
        .immediate_mode(true)
        .open()
        .map_err(|e| anyhow::anyhow!("activate capture on {}: {e}", config.iface))?;

    cap.filter(&config.bpf, true)
        .map_err(|e| anyhow::anyhow!("apply bpf {:?}: {e}", config.bpf))?;

    let deadline = Instant::now() + config.duration;
    let mut flows: HashMap<FlowKey, FlowAccumulator> = HashMap::new();

    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                let ts = packet.header.ts;
                let ts_secs = ts.tv_sec;
                let ts_subsec_micros = ts.tv_usec as u32;
                if let Some(mut parsed) = parse::parse_frame(packet.data) {
                    parsed.ts_secs = ts_secs;
                    parsed.ts_subsec_micros = ts_subsec_micros;
                    ingest(&mut flows, parsed);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(anyhow::anyhow!("read packet: {e}")),
        }
    }

    Ok(finish(host_id, flows))
}

fn resolve_device(iface: &str) -> anyhow::Result<Device> {
    let devices = Device::list().map_err(|e| anyhow::anyhow!("list devices: {e}"))?;
    if iface == "any" {
        if let Some(d) = devices.iter().find(|d| d.name == "any") {
            return Ok(d.clone());
        }
        return Device::lookup()
            .map_err(|e| anyhow::anyhow!("lookup default device: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("no default capture device found"));
    }
    devices
        .into_iter()
        .find(|d| d.name == iface)
        .ok_or_else(|| anyhow::anyhow!("interface {iface} not found (use --list-devices to list)"))
}

fn ingest(flows: &mut HashMap<FlowKey, FlowAccumulator>, pkt: ParsedPacket) {
    let key = FlowKey {
        proto: pkt.proto,
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
    };
    let ts = packet_ts(pkt.ts_secs, pkt.ts_subsec_micros);

    flows
        .entry(key.clone())
        .and_modify(|acc| {
            acc.end_ts = ts;
            acc.bytes_sent += u64::from(pkt.ip_total_len);
            acc.packets_sent += 1;
            merge_metadata(acc, &pkt);
        })
        .or_insert_with(|| FlowAccumulator {
            key,
            start_ts: ts,
            end_ts: ts,
            bytes_sent: u64::from(pkt.ip_total_len),
            packets_sent: 1,
            app_proto: pkt.app_proto.clone(),
            dns_query: pkt.dns_query.clone(),
            tls_sni: pkt.tls_sni.clone(),
            ja3: pkt.ja3.clone(),
        });
}

fn merge_metadata(acc: &mut FlowAccumulator, pkt: &ParsedPacket) {
    if acc.app_proto.is_none() {
        acc.app_proto = pkt.app_proto.clone();
    }
    if acc.dns_query.is_none() {
        acc.dns_query = pkt.dns_query.clone();
    }
    if acc.tls_sni.is_none() {
        acc.tls_sni = pkt.tls_sni.clone();
    }
    if acc.ja3.is_none() {
        acc.ja3 = pkt.ja3.clone();
    }
}

fn packet_ts(secs: i64, micros: u32) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, micros.saturating_mul(1_000))
        .single()
        .unwrap_or_else(Utc::now)
}

fn finish(host_id: &str, flows: HashMap<FlowKey, FlowAccumulator>) -> Vec<FlowEvent> {
    let mut events: Vec<FlowEvent> = flows
        .into_values()
        .map(|acc| FlowEvent {
            flow_id: flow_id(&acc.key),
            host_id: host_id.to_string(),
            start_ts: acc.start_ts,
            end_ts: acc.end_ts,
            proto: acc.key.proto,
            src_ip: acc.key.src_ip,
            src_port: acc.key.src_port,
            dst_ip: acc.key.dst_ip,
            dst_port: acc.key.dst_port,
            bytes_sent: acc.bytes_sent,
            bytes_recv: 0,
            packets_sent: acc.packets_sent,
            packets_recv: 0,
            app_proto: acc.app_proto,
            dns_query: acc.dns_query,
            tls_sni: acc.tls_sni,
            ja3: acc.ja3,
            threat_intel: Vec::new(),
        })
        .collect();
    events.sort_by(|a, b| a.start_ts.cmp(&b.start_ts));
    events
}

fn flow_id(key: &FlowKey) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    format!("flow-pcap-{:016x}", hasher.finish())
}

/// List capture-capable interfaces (for CLI diagnostics).
pub fn list_devices() -> anyhow::Result<Vec<String>> {
    Ok(Device::list()
        .map_err(|e| anyhow::anyhow!("list devices: {e}"))?
        .into_iter()
        .map(|d| d.name)
        .collect())
}
