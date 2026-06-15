//! Live packet capture via libpcap with 5-tuple flow aggregation.
//!
//! Opens a network interface, applies a BPF filter, reads packets for a
//! fixed duration, aggregates them into `TraceEvent`s, and enriches each
//! flow with DNS / TLS metadata parsed from payloads.
//!
//! Requires the `pcap` feature and libpcap at build time. Typically needs
//! root or `CAP_NET_RAW` to capture on real interfaces.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeZone, Utc};
use pcap::{Capture, Device};

use crate::contract::{TraceEvent, TraceProto};

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

/// A network endpoint (address + optional port) used to canonicalize flow keys.
type Endpoint = (IpAddr, Option<u16>);

/// Direction-independent flow identity: the two endpoints are stored in sorted
/// order so a connection's two packet directions (A→B and B→A) map to the *same*
/// flow instead of two separate one-directional flows (C10).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: TraceProto,
    ep_lo: Endpoint,
    ep_hi: Endpoint,
}

impl FlowKey {
    fn canonical(proto: TraceProto, a: Endpoint, b: Endpoint) -> Self {
        let (ep_lo, ep_hi) = if a <= b { (a, b) } else { (b, a) };
        Self {
            proto,
            ep_lo,
            ep_hi,
        }
    }
}

struct FlowAccumulator {
    key: FlowKey,
    proto: TraceProto,
    // First-seen orientation: the flow's `src` is whoever sent the first packet
    // (≈ the client, which usually sends first). Subsequent packets matching this
    // orientation count as "sent"; the reverse direction counts as "recv".
    src_ip: IpAddr,
    src_port: Option<u16>,
    dst_ip: IpAddr,
    dst_port: Option<u16>,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    bytes_sent: u64,
    packets_sent: u64,
    bytes_recv: u64,
    packets_recv: u64,
    app_proto: Option<String>,
    dns_query: Option<String>,
    tls_sni: Option<String>,
    ja3: Option<String>,
}

/// Capture and aggregate events from a live interface.
pub fn capture(host_id: &str, config: &PcapConfig) -> anyhow::Result<Vec<TraceEvent>> {
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
    let mut events: HashMap<FlowKey, FlowAccumulator> = HashMap::new();

    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                let ts = packet.header.ts;
                let ts_secs = ts.tv_sec;
                let ts_subsec_micros = ts.tv_usec as u32;
                // Authoritative on-wire length from the capture header, not the
                // packet's self-reported IP total_length (which is attacker-
                // controllable and wrong for truncation / IPv6 jumbograms).
                let wire_len = u64::from(packet.header.len);
                if let Some(mut parsed) = parse::parse_frame(packet.data) {
                    parsed.ts_secs = ts_secs;
                    parsed.ts_subsec_micros = ts_subsec_micros;
                    ingest(&mut events, parsed, wire_len);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(anyhow::anyhow!("read packet: {e}")),
        }
    }

    Ok(finish(host_id, events))
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

fn ingest(events: &mut HashMap<FlowKey, FlowAccumulator>, pkt: ParsedPacket, wire_len: u64) {
    let src: Endpoint = (pkt.src_ip, pkt.src_port);
    let dst: Endpoint = (pkt.dst_ip, pkt.dst_port);
    let key = FlowKey::canonical(pkt.proto, src, dst);
    let ts = packet_ts(pkt.ts_secs, pkt.ts_subsec_micros);

    events
        .entry(key.clone())
        .and_modify(|acc| {
            acc.end_ts = ts;
            // Forward = matches the first-seen orientation; reverse = the other way.
            if src == (acc.src_ip, acc.src_port) {
                acc.bytes_sent += wire_len;
                acc.packets_sent += 1;
            } else {
                acc.bytes_recv += wire_len;
                acc.packets_recv += 1;
            }
            merge_metadata(acc, &pkt);
        })
        .or_insert_with(|| FlowAccumulator {
            key,
            proto: pkt.proto,
            src_ip: pkt.src_ip,
            src_port: pkt.src_port,
            dst_ip: pkt.dst_ip,
            dst_port: pkt.dst_port,
            start_ts: ts,
            end_ts: ts,
            bytes_sent: wire_len,
            packets_sent: 1,
            bytes_recv: 0,
            packets_recv: 0,
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

fn finish(host_id: &str, events: HashMap<FlowKey, FlowAccumulator>) -> Vec<TraceEvent> {
    let mut events: Vec<TraceEvent> = events
        .into_values()
        .map(|acc| TraceEvent {
            trace_id: trace_id(&acc.key),
            host_id: host_id.to_string(),
            start_ts: acc.start_ts,
            end_ts: acc.end_ts,
            proto: acc.proto,
            src_ip: acc.src_ip,
            src_port: acc.src_port,
            dst_ip: acc.dst_ip,
            dst_port: acc.dst_port,
            bytes_sent: acc.bytes_sent,
            bytes_recv: acc.bytes_recv,
            packets_sent: acc.packets_sent,
            packets_recv: acc.packets_recv,
            app_proto: acc.app_proto,
            dns_query: acc.dns_query,
            tls_sni: acc.tls_sni,
            ja3: acc.ja3,
            threat_intel: Vec::new(),
        })
        .collect();
    events.sort_by_key(|a| a.start_ts);
    events
}

fn trace_id(key: &FlowKey) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    format!("trace-pcap-{:016x}", hasher.finish())
}

/// List capture-capable interfaces (for CLI diagnostics).
pub fn list_devices() -> anyhow::Result<Vec<String>> {
    Ok(Device::list()
        .map_err(|e| anyhow::anyhow!("list devices: {e}"))?
        .into_iter()
        .map(|d| d.name)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(src: &str, sp: u16, dst: &str, dp: u16) -> ParsedPacket {
        ParsedPacket {
            ts_secs: 1,
            ts_subsec_micros: 0,
            ip_total_len: 0,
            proto: TraceProto::Tcp,
            src_ip: src.parse().unwrap(),
            dst_ip: dst.parse().unwrap(),
            src_port: Some(sp),
            dst_port: Some(dp),
            app_proto: None,
            dns_query: None,
            tls_sni: None,
            ja3: None,
        }
    }

    #[test]
    fn both_directions_fold_into_one_bidirectional_flow() {
        let mut flows = HashMap::new();
        // client -> server (first packet sets the flow orientation)
        ingest(&mut flows, pkt("10.0.0.1", 5000, "93.184.216.34", 443), 100);
        ingest(&mut flows, pkt("10.0.0.1", 5000, "93.184.216.34", 443), 40);
        // server -> client (reverse direction folds into the SAME flow)
        ingest(
            &mut flows,
            pkt("93.184.216.34", 443, "10.0.0.1", 5000),
            1500,
        );

        assert_eq!(flows.len(), 1, "both directions are one bidirectional flow");
        let out = finish("h-1", flows);
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(
            f.src_ip.to_string(),
            "10.0.0.1",
            "src = first-seen (client)"
        );
        assert_eq!(f.dst_ip.to_string(), "93.184.216.34");
        assert_eq!(f.bytes_sent, 140);
        assert_eq!(f.packets_sent, 2);
        assert_eq!(
            f.bytes_recv, 1500,
            "reverse-direction bytes counted (was hardcoded 0)"
        );
        assert_eq!(f.packets_recv, 1);
    }

    #[test]
    fn first_packet_direction_sets_orientation() {
        let mut flows = HashMap::new();
        ingest(&mut flows, pkt("93.184.216.34", 443, "10.0.0.1", 5000), 200);
        ingest(&mut flows, pkt("10.0.0.1", 5000, "93.184.216.34", 443), 60);
        let out = finish("h", flows);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].src_ip.to_string(),
            "93.184.216.34",
            "server spoke first"
        );
        assert_eq!(out[0].bytes_sent, 200);
        assert_eq!(out[0].bytes_recv, 60);
    }
}
