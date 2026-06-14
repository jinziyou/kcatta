//! Mock flow event generator for v0.
//!
//! Synthesizes a small, deterministic set of flow events representing
//! the most common observable patterns:
//!   * outbound HTTPS (TLS SNI)
//!   * outbound DNS query (UDP)
//!   * inbound SSH session (TCP)
//!   * ICMP echo
//!
//! Real capture backends (pcap / AF_PACKET / eBPF) will replace this
//! without touching the call site in `lib.rs`.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{Duration, Utc};

use crate::contract::{TraceEvent, TraceProto};

/// Synthesize the deterministic v0 mock flow set attributed to `host_id`.
pub fn capture(host_id: &str) -> Vec<TraceEvent> {
    let now = Utc::now();
    let local: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42));
    let dns_resolver: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let example_https: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let admin_jumphost: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));

    vec![
        TraceEvent {
            trace_id: "trace-mock-https-1".to_string(),
            host_id: host_id.to_string(),
            start_ts: now - Duration::seconds(12),
            end_ts: now - Duration::seconds(11),
            proto: TraceProto::Tcp,
            src_ip: local,
            src_port: Some(54321),
            dst_ip: example_https,
            dst_port: Some(443),
            bytes_sent: 512,
            bytes_recv: 4096,
            packets_sent: 6,
            packets_recv: 8,
            app_proto: Some("TLS".to_string()),
            dns_query: None,
            tls_sni: Some("example.com".to_string()),
            ja3: Some("e7d705a3286e19ea42f587b344ee6865".to_string()),
            threat_intel: Vec::new(),
        },
        TraceEvent {
            trace_id: "trace-mock-dns-1".to_string(),
            host_id: host_id.to_string(),
            start_ts: now - Duration::seconds(13),
            end_ts: now - Duration::seconds(13),
            proto: TraceProto::Udp,
            src_ip: local,
            src_port: Some(43210),
            dst_ip: dns_resolver,
            dst_port: Some(53),
            bytes_sent: 56,
            bytes_recv: 96,
            packets_sent: 1,
            packets_recv: 1,
            app_proto: Some("DNS".to_string()),
            dns_query: Some("example.com".to_string()),
            tls_sni: None,
            ja3: None,
            threat_intel: Vec::new(),
        },
        TraceEvent {
            trace_id: "trace-mock-ssh-1".to_string(),
            host_id: host_id.to_string(),
            start_ts: now - Duration::seconds(300),
            end_ts: now - Duration::seconds(5),
            proto: TraceProto::Tcp,
            src_ip: admin_jumphost,
            src_port: Some(40000),
            dst_ip: local,
            dst_port: Some(22),
            bytes_sent: 18_432,
            bytes_recv: 32_768,
            packets_sent: 144,
            packets_recv: 192,
            app_proto: Some("SSH".to_string()),
            dns_query: None,
            tls_sni: None,
            ja3: None,
            threat_intel: Vec::new(),
        },
        TraceEvent {
            trace_id: "trace-mock-icmp-1".to_string(),
            host_id: host_id.to_string(),
            start_ts: now - Duration::seconds(2),
            end_ts: now - Duration::seconds(2),
            proto: TraceProto::Icmp,
            src_ip: local,
            src_port: None,
            dst_ip: dns_resolver,
            dst_port: None,
            bytes_sent: 64,
            bytes_recv: 64,
            packets_sent: 1,
            packets_recv: 1,
            app_proto: None,
            dns_query: None,
            tls_sni: None,
            ja3: None,
            threat_intel: Vec::new(),
        },
    ]
}
