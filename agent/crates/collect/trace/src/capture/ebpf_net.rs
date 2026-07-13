//! eBPF network capture backend (feature `ebpf`).
//!
//! Loads the `trace-ebpf` object's `cgroup_skb` programs, attaches them to the
//! cgroup-v2 root (host-wide egress+ingress), drains the per-packet [`NetEvent`]
//! records the kernel emits into the shared ring buffer for a bounded window, and
//! folds the two directions of each connection into one bidirectional
//! [`TraceEvent`].
//!
//! This backend is **L4-only**: accurate 5-tuple + byte/direction telemetry with
//! a small fixed per-packet record, but no L7 metadata (JA3 / TLS SNI / DNS) —
//! for those, use the `pcap` backend. IP-based IOC enrichment still applies
//! downstream; domain/JA3 IOC matching does not (no L7 fields). Under very high
//! packet rates the shared ring buffer can overflow; lost packets are counted by
//! the kernel drop counter (surfaced by the tracepoint loader).
//!
//! Requires `CAP_BPF` + cgroup-v2 at runtime. The caller may fall back to live
//! pcap when that feature is compiled; without pcap, load/attach failure remains
//! an error and never produces synthetic mock events.

use std::collections::HashMap;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use agent_contract::{TraceEvent, TraceProto};
use agent_ebpf::{kind, NetEvent};
use anyhow::Context as _;
use aya::maps::RingBuf;
use aya::programs::{cgroup_skb::CgroupSkbAttachType, CgroupAttachMode, CgroupSkb};
use aya::Ebpf;
use chrono::{DateTime, Utc};

/// The bpf object built and embedded by `build.rs` (shared with the tracepoint loader).
static TRACE_EBPF: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/trace-ebpf"));

/// Default cgroup-v2 root that scopes host-wide flow accounting.
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// How often to poll the ring buffer when it is momentarily empty.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Capture network flows for `duration` via the cgroup-skb backend.
pub fn capture(host_id: &str, duration: Duration) -> anyhow::Result<Vec<TraceEvent>> {
    let mut ebpf =
        Ebpf::load(TRACE_EBPF).context("load trace-ebpf object (needs CAP_BPF + cgroup-v2)")?;
    let cgroup = File::open(CGROUP_V2_ROOT)
        .with_context(|| format!("open cgroup-v2 root {CGROUP_V2_ROOT}"))?;
    attach(
        &mut ebpf,
        "net_egress",
        &cgroup,
        CgroupSkbAttachType::Egress,
    )?;
    attach(
        &mut ebpf,
        "net_ingress",
        &cgroup,
        CgroupSkbAttachType::Ingress,
    )?;

    let mut packets: Vec<NetEvent> = Vec::new();
    {
        let map = ebpf
            .map_mut("EVENTS")
            .context("`EVENTS` ring buffer missing from object")?;
        let mut ring = RingBuf::try_from(map).context("open EVENTS ring buffer")?;
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            let mut drained_any = false;
            while let Some(item) = ring.next() {
                drained_any = true;
                let bytes: &[u8] = &item;
                if bytes.len() < 4 {
                    continue;
                }
                let kind = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if kind == kind::NET && bytes.len() >= size_of::<NetEvent>() {
                    packets.push(bytemuck::pod_read_unaligned(
                        &bytes[..size_of::<NetEvent>()],
                    ));
                }
            }
            if !drained_any {
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }

    Ok(fold_flows(host_id, packets, Utc::now()))
}

fn attach(
    ebpf: &mut Ebpf,
    name: &str,
    cgroup: &File,
    attach_type: CgroupSkbAttachType,
) -> anyhow::Result<()> {
    let program: &mut CgroupSkb = ebpf
        .program_mut(name)
        .with_context(|| format!("program `{name}` missing from object"))?
        .try_into()
        .with_context(|| format!("`{name}` is not a cgroup_skb program"))?;
    program.load().with_context(|| format!("load `{name}`"))?;
    program
        .attach(cgroup, attach_type, CgroupAttachMode::Single)
        .with_context(|| format!("attach `{name}` to {CGROUP_V2_ROOT}"))?;
    Ok(())
}

/// A network endpoint used to canonicalize bidirectional flows.
type Endpoint = (IpAddr, Option<u16>);

/// Fold per-packet kernel records into bidirectional [`TraceEvent`]s.
///
/// Each record is one packet in one direction; A→B and B→A are merged into a
/// single flow. Orientation: the lexicographically-lower endpoint is taken as
/// `src` (the per-packet records carry no ordering, so the first-seen/initiator
/// heuristic the pcap backend uses is unavailable here).
fn fold_flows(host_id: &str, packets: Vec<NetEvent>, ts: DateTime<Utc>) -> Vec<TraceEvent> {
    struct Bidir {
        proto: TraceProto,
        src: Endpoint,
        dst: Endpoint,
        bytes_sent: u64,
        packets_sent: u64,
        bytes_recv: u64,
        packets_recv: u64,
    }
    let mut flows: HashMap<(u8, Endpoint, Endpoint), Bidir> = HashMap::new();

    for ev in packets {
        let src = endpoint(ev.family, &ev.src_addr, ev.src_port);
        let dst = endpoint(ev.family, &ev.dst_addr, ev.dst_port);
        // Canonical orientation: lower endpoint is the flow's src.
        let (canon_src, canon_dst, forward) = if src <= dst {
            (src, dst, true)
        } else {
            (dst, src, false)
        };
        let entry = flows
            .entry((ev.proto, canon_src, canon_dst))
            .or_insert_with(|| Bidir {
                proto: proto_of(ev.proto),
                src: canon_src,
                dst: canon_dst,
                bytes_sent: 0,
                packets_sent: 0,
                bytes_recv: 0,
                packets_recv: 0,
            });
        if forward {
            entry.bytes_sent += u64::from(ev.bytes);
            entry.packets_sent += 1;
        } else {
            entry.bytes_recv += u64::from(ev.bytes);
            entry.packets_recv += 1;
        }
    }

    let mut events: Vec<TraceEvent> = flows
        .into_values()
        .map(|b| TraceEvent {
            trace_id: trace_id(&b.proto, &b.src, &b.dst),
            host_id: host_id.to_string(),
            start_ts: ts,
            end_ts: ts,
            proto: b.proto,
            src_ip: b.src.0,
            src_port: b.src.1,
            dst_ip: b.dst.0,
            dst_port: b.dst.1,
            bytes_sent: b.bytes_sent,
            bytes_recv: b.bytes_recv,
            packets_sent: b.packets_sent,
            packets_recv: b.packets_recv,
            // L4-only backend: no L7 enrichment (use pcap for JA3/SNI/DNS).
            app_proto: None,
            dns_query: None,
            tls_sni: None,
            ja3: None,
            threat_intel: Vec::new(),
        })
        .collect();
    events.sort_by(|a, b| a.src_ip.cmp(&b.src_ip).then(a.dst_ip.cmp(&b.dst_ip)));
    events
}

fn endpoint(family: u8, addr: &[u8; 16], port: [u8; 2]) -> Endpoint {
    let ip = if family == 6 {
        IpAddr::V6(Ipv6Addr::from(*addr))
    } else {
        IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
    };
    let port = u16::from_be_bytes(port);
    (ip, (port != 0).then_some(port))
}

fn proto_of(proto: u8) -> TraceProto {
    match proto {
        6 => TraceProto::Tcp,
        17 => TraceProto::Udp,
        1 | 58 => TraceProto::Icmp,
        _ => TraceProto::Other,
    }
}

fn trace_id(proto: &TraceProto, src: &Endpoint, dst: &Endpoint) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    (*proto as u8).hash(&mut hasher);
    src.hash(&mut hasher);
    dst.hash(&mut hasher);
    format!("trace-ebpf-net-{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: [u8; 4]) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&a);
        b
    }

    fn pkt(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, proto: u8, bytes: u32) -> NetEvent {
        NetEvent {
            kind: kind::NET,
            bytes,
            family: 4,
            proto,
            src_port: sp.to_be_bytes(),
            dst_port: dp.to_be_bytes(),
            _pad: [0; 2],
            src_addr: v4(src),
            dst_addr: v4(dst),
        }
    }

    #[test]
    fn folds_both_directions_into_one_flow() {
        let packets = vec![
            pkt([10, 0, 0, 1], 5000, [93, 184, 216, 34], 443, 6, 100),
            pkt([10, 0, 0, 1], 5000, [93, 184, 216, 34], 443, 6, 40),
            pkt([93, 184, 216, 34], 443, [10, 0, 0, 1], 5000, 6, 1500),
        ];
        let out = fold_flows("h-1", packets, Utc::now());
        assert_eq!(out.len(), 1, "two directions fold into one flow");
        let f = &out[0];
        // Canonical orientation: 10.0.0.1:5000 sorts lower than 93.184.216.34:443.
        assert_eq!(f.src_ip.to_string(), "10.0.0.1");
        assert_eq!(f.dst_ip.to_string(), "93.184.216.34");
        assert_eq!(f.src_port, Some(5000));
        assert_eq!(f.dst_port, Some(443));
        assert_eq!(f.proto, TraceProto::Tcp);
        assert_eq!(f.bytes_sent, 140);
        assert_eq!(f.packets_sent, 2);
        assert_eq!(f.bytes_recv, 1500);
        assert_eq!(f.packets_recv, 1);
        assert!(f.tls_sni.is_none() && f.ja3.is_none() && f.dns_query.is_none());
    }

    #[test]
    fn proto_and_icmp_mapping() {
        assert_eq!(proto_of(6), TraceProto::Tcp);
        assert_eq!(proto_of(17), TraceProto::Udp);
        assert_eq!(proto_of(1), TraceProto::Icmp);
        assert_eq!(proto_of(58), TraceProto::Icmp);
        assert_eq!(proto_of(132), TraceProto::Other);
    }

    #[test]
    fn icmp_has_no_ports() {
        let packets = vec![pkt([10, 0, 0, 1], 0, [10, 0, 0, 2], 0, 1, 84)];
        let out = fold_flows("h", packets, Utc::now());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].proto, TraceProto::Icmp);
        assert_eq!(out[0].src_port, None);
        assert_eq!(out[0].dst_port, None);
    }
}
