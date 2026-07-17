//! eBPF network capture backend (feature `ebpf`).
//!
//! Loads the `trace-ebpf` object's `cgroup_skb` programs, attaches them to the
//! cgroup-v2 root (host-wide egress+ingress), snapshots directional five-tuple
//! aggregates from a bounded kernel LRU map, and folds the two directions of
//! each connection into one bidirectional [`TraceEvent`].
//!
//! This backend is **L4-only**: accurate 5-tuple + byte/direction telemetry with
//! a fixed-size per-flow aggregate, but no L7 metadata (JA3 / TLS SNI / DNS) —
//! for those, use the `pcap` backend. IP-based IOC enrichment still applies
//! downstream; domain/JA3 IOC matching does not (no L7 fields). Packet rate no
//! longer directly consumes ring-buffer space. LRU evictions and map-update
//! failures are counted in-kernel and surfaced after every capture window.
//!
//! Requires `CAP_BPF` + cgroup-v2 at runtime. The caller may fall back to live
//! pcap when that feature is compiled; without pcap, load/attach failure remains
//! an error and never produces synthetic mock events.

use std::collections::HashMap as StdHashMap;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use agent_contract::{TraceEvent, TraceProto};
use agent_ebpf::{FlowKey, FlowValue};
use anyhow::Context as _;
use aya::maps::{PerCpuArray, PerCpuHashMap as AyaPerCpuHashMap};
use aya::programs::{
    cgroup_skb::{CgroupSkbAttachType, CgroupSkbLinkId},
    CgroupAttachMode, CgroupSkb,
};
use aya::Ebpf;
use chrono::{DateTime, Utc};
use rustix::time::{clock_gettime, ClockId};

/// The bpf object built and embedded by `build.rs` (shared with the tracepoint loader).
static TRACE_EBPF: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/trace-ebpf"));

/// Default cgroup-v2 root that scopes host-wide flow accounting.
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// Capture network flows for `duration` via the cgroup-skb backend.
pub fn capture(host_id: &str, duration: Duration) -> anyhow::Result<Vec<TraceEvent>> {
    let mut ebpf =
        Ebpf::load(TRACE_EBPF).context("load trace-ebpf object (needs CAP_BPF + cgroup-v2)")?;
    let cgroup = File::open(CGROUP_V2_ROOT)
        .with_context(|| format!("open cgroup-v2 root {CGROUP_V2_ROOT}"))?;
    let egress_link = attach(
        &mut ebpf,
        "net_egress",
        &cgroup,
        CgroupSkbAttachType::Egress,
    )?;
    let ingress_link = attach(
        &mut ebpf,
        "net_ingress",
        &cgroup,
        CgroupSkbAttachType::Ingress,
    )?;

    std::thread::sleep(duration);

    // Freeze accounting before walking the LRU map so iteration sees one
    // coherent capture boundary rather than racing new inserts/evictions.
    detach(&mut ebpf, "net_ingress", ingress_link)?;
    detach(&mut ebpf, "net_egress", egress_link)?;
    let anchor_monotonic_ns = monotonic_ns();
    let anchor_utc = Utc::now();

    let flows = read_flows(&ebpf)?;
    let inserts = read_counter(&ebpf, "FLOW_INSERTS")?;
    let update_errors = read_counter(&ebpf, "FLOW_UPDATE_ERRORS")?;
    let evictions = inserts.saturating_sub(flows.len() as u64);
    if evictions > 0 {
        eprintln!(
            "agent-collect-trace: eBPF flow LRU capacity pressure — {evictions} aggregate(s) \
             evicted during this capture window; shorten the window or increase map capacity"
        );
    }
    if update_errors > 0 {
        eprintln!(
            "agent-collect-trace: eBPF flow map rejected {update_errors} packet update(s); \
             captured counters are partial"
        );
    }

    Ok(fold_flows(host_id, flows, anchor_monotonic_ns, anchor_utc))
}

fn attach(
    ebpf: &mut Ebpf,
    name: &str,
    cgroup: &File,
    attach_type: CgroupSkbAttachType,
) -> anyhow::Result<CgroupSkbLinkId> {
    let program: &mut CgroupSkb = ebpf
        .program_mut(name)
        .with_context(|| format!("program `{name}` missing from object"))?
        .try_into()
        .with_context(|| format!("`{name}` is not a cgroup_skb program"))?;
    program.load().with_context(|| format!("load `{name}`"))?;
    let link = program
        .attach(cgroup, attach_type, CgroupAttachMode::Single)
        .with_context(|| format!("attach `{name}` to {CGROUP_V2_ROOT}"))?;
    Ok(link)
}

fn detach(ebpf: &mut Ebpf, name: &str, link: CgroupSkbLinkId) -> anyhow::Result<()> {
    let program: &mut CgroupSkb = ebpf
        .program_mut(name)
        .with_context(|| format!("program `{name}` missing while detaching"))?
        .try_into()
        .with_context(|| format!("`{name}` is not a cgroup_skb program"))?;
    program
        .detach(link)
        .with_context(|| format!("detach `{name}` from {CGROUP_V2_ROOT}"))
}

fn read_flows(ebpf: &Ebpf) -> anyhow::Result<Vec<(FlowKey, FlowValue)>> {
    let map = ebpf
        .map("FLOWS")
        .context("`FLOWS` per-CPU LRU hash map missing from object")?;
    // Aya's public Pod trait is intentionally not implemented by the shared
    // crate. Read fixed byte arrays and decode with bytemuck so userspace stays
    // unsafe-free while still enforcing the exact kernel layout sizes.
    let flows: AyaPerCpuHashMap<_, [u8; size_of::<FlowKey>()], [u8; size_of::<FlowValue>()]> =
        AyaPerCpuHashMap::try_from(map).context("open FLOWS per-CPU LRU hash map")?;
    let mut merged = Vec::new();
    for entry in flows.iter() {
        let (key, per_cpu) = entry.context("iterate FLOWS per-CPU LRU hash map")?;
        if let Some(value) =
            merge_cpu_values(per_cpu.iter().map(|raw| bytemuck::pod_read_unaligned(raw)))
        {
            merged.push((bytemuck::pod_read_unaligned(&key), value));
        }
    }
    Ok(merged)
}

fn merge_cpu_values(per_cpu: impl IntoIterator<Item = FlowValue>) -> Option<FlowValue> {
    let mut merged = FlowValue {
        bytes: 0,
        packets: 0,
        first_seen_ns: 0,
        last_seen_ns: 0,
    };
    for value in per_cpu {
        // A key created on one CPU has zero-initialized slots on all others.
        if value.first_seen_ns == 0 {
            continue;
        }
        merged.bytes = merged.bytes.saturating_add(value.bytes);
        merged.packets = merged.packets.saturating_add(value.packets);
        merged.first_seen_ns = if merged.first_seen_ns == 0 {
            value.first_seen_ns
        } else {
            merged.first_seen_ns.min(value.first_seen_ns)
        };
        merged.last_seen_ns = merged.last_seen_ns.max(value.last_seen_ns);
    }
    (merged.first_seen_ns != 0).then_some(merged)
}

/// Sum a named per-CPU single-element counter.
fn read_counter(ebpf: &Ebpf, name: &str) -> anyhow::Result<u64> {
    let map = ebpf
        .map(name)
        .with_context(|| format!("`{name}` counter missing from object"))?;
    let counters: PerCpuArray<_, u64> = PerCpuArray::try_from(map)?;
    let per_cpu = counters.get(&0, 0)?;
    Ok(per_cpu.iter().copied().sum())
}

fn monotonic_ns() -> u64 {
    let now = clock_gettime(ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(now.tv_nsec).unwrap_or(0))
}

/// A network endpoint used to canonicalize bidirectional flows.
type Endpoint = (IpAddr, Option<u16>);

/// Fold directional kernel aggregates into bidirectional [`TraceEvent`]s.
///
/// A→B and B→A are merged into a single flow. Orientation: the
/// lexicographically-lower endpoint is taken as `src` because cgroup-skb does
/// not expose a reliable connection initiator.
fn fold_flows(
    host_id: &str,
    directional: Vec<(FlowKey, FlowValue)>,
    anchor_monotonic_ns: u64,
    anchor_utc: DateTime<Utc>,
) -> Vec<TraceEvent> {
    struct Bidir {
        proto: TraceProto,
        src: Endpoint,
        dst: Endpoint,
        bytes_sent: u64,
        packets_sent: u64,
        bytes_recv: u64,
        packets_recv: u64,
        first_seen_ns: u64,
        last_seen_ns: u64,
    }
    let mut flows: StdHashMap<(u8, Endpoint, Endpoint), Bidir> = StdHashMap::new();

    for (key, value) in directional {
        let src = endpoint(key.family, &key.src_addr, key.src_port);
        let dst = endpoint(key.family, &key.dst_addr, key.dst_port);
        // Canonical orientation: lower endpoint is the flow's src.
        let (canon_src, canon_dst, forward) = if src <= dst {
            (src, dst, true)
        } else {
            (dst, src, false)
        };
        let entry = flows
            .entry((key.proto, canon_src, canon_dst))
            .or_insert_with(|| Bidir {
                proto: proto_of(key.proto),
                src: canon_src,
                dst: canon_dst,
                bytes_sent: 0,
                packets_sent: 0,
                bytes_recv: 0,
                packets_recv: 0,
                first_seen_ns: value.first_seen_ns,
                last_seen_ns: value.last_seen_ns,
            });
        entry.first_seen_ns = entry.first_seen_ns.min(value.first_seen_ns);
        entry.last_seen_ns = entry.last_seen_ns.max(value.last_seen_ns);
        if forward {
            entry.bytes_sent = entry.bytes_sent.saturating_add(value.bytes);
            entry.packets_sent = entry.packets_sent.saturating_add(value.packets);
        } else {
            entry.bytes_recv = entry.bytes_recv.saturating_add(value.bytes);
            entry.packets_recv = entry.packets_recv.saturating_add(value.packets);
        }
    }

    let mut events: Vec<TraceEvent> = flows
        .into_values()
        .map(|b| TraceEvent {
            trace_id: trace_id(&b.proto, &b.src, &b.dst),
            host_id: host_id.to_string(),
            start_ts: monotonic_to_utc(b.first_seen_ns, anchor_monotonic_ns, &anchor_utc),
            end_ts: monotonic_to_utc(b.last_seen_ns, anchor_monotonic_ns, &anchor_utc),
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
    events.sort_by(|a, b| {
        a.src_ip
            .cmp(&b.src_ip)
            .then(a.src_port.cmp(&b.src_port))
            .then(a.dst_ip.cmp(&b.dst_ip))
            .then(a.dst_port.cmp(&b.dst_port))
            .then((a.proto as u8).cmp(&(b.proto as u8)))
    });
    events
}

fn monotonic_to_utc(
    timestamp_ns: u64,
    anchor_monotonic_ns: u64,
    anchor_utc: &DateTime<Utc>,
) -> DateTime<Utc> {
    let age_ns = anchor_monotonic_ns.saturating_sub(timestamp_ns);
    let age_ns = i64::try_from(age_ns).unwrap_or(i64::MAX);
    *anchor_utc - chrono::Duration::nanoseconds(age_ns)
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

    fn flow(
        src: [u8; 4],
        sp: u16,
        dst: [u8; 4],
        dp: u16,
        proto: u8,
        bytes: u64,
        packets: u64,
        first_seen_ns: u64,
        last_seen_ns: u64,
    ) -> (FlowKey, FlowValue) {
        (
            FlowKey {
                family: 4,
                proto,
                src_port: sp.to_be_bytes(),
                dst_port: dp.to_be_bytes(),
                _pad: [0; 2],
                src_addr: v4(src),
                dst_addr: v4(dst),
            },
            FlowValue {
                bytes,
                packets,
                first_seen_ns,
                last_seen_ns,
            },
        )
    }

    #[test]
    fn folds_both_directions_into_one_flow() {
        let directional = vec![
            flow(
                [10, 0, 0, 1],
                5000,
                [93, 184, 216, 34],
                443,
                6,
                140,
                2,
                8_000_000_000,
                9_000_000_000,
            ),
            flow(
                [93, 184, 216, 34],
                443,
                [10, 0, 0, 1],
                5000,
                6,
                1500,
                1,
                8_500_000_000,
                9_500_000_000,
            ),
        ];
        let anchor = DateTime::parse_from_rfc3339("2026-07-17T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let out = fold_flows("h-1", directional, 10_000_000_000, anchor);
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
        assert_eq!(f.start_ts.to_rfc3339(), "2026-07-17T11:59:58+00:00");
        assert_eq!(f.end_ts.to_rfc3339(), "2026-07-17T11:59:59.500+00:00");
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
        let directional = vec![flow([10, 0, 0, 1], 0, [10, 0, 0, 2], 0, 1, 84, 1, 1, 1)];
        let out = fold_flows("h", directional, 1, Utc::now());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].proto, TraceProto::Icmp);
        assert_eq!(out[0].src_port, None);
        assert_eq!(out[0].dst_port, None);
    }

    #[test]
    fn future_monotonic_value_is_clamped_to_anchor() {
        let anchor = Utc::now();
        assert_eq!(monotonic_to_utc(11, 10, &anchor), anchor);
    }

    #[test]
    fn merges_non_empty_per_cpu_slots() {
        let merged = merge_cpu_values([
            FlowValue {
                bytes: 100,
                packets: 2,
                first_seen_ns: 20,
                last_seen_ns: 30,
            },
            FlowValue {
                bytes: 0,
                packets: 0,
                first_seen_ns: 0,
                last_seen_ns: 0,
            },
            FlowValue {
                bytes: 50,
                packets: 1,
                first_seen_ns: 10,
                last_seen_ns: 40,
            },
        ])
        .unwrap();
        assert_eq!(merged.bytes, 150);
        assert_eq!(merged.packets, 3);
        assert_eq!(merged.first_seen_ns, 10);
        assert_eq!(merged.last_seen_ns, 40);
        assert!(merge_cpu_values([]).is_none());
    }
}
