//! Flow capture backends.
//!
//! Backends include explicit `mock` telemetry for tests/dev and feature-gated
//! live pcap, eBPF, and OS connection-table capture. All return the same
//! `Vec<TraceEvent>` so source composition does not depend on the backend.

pub mod mock;
pub mod parse;

#[cfg(feature = "pcap")]
pub mod pcap;

#[cfg(feature = "ebpf")]
pub mod ebpf_net;

use crate::contract::TraceEvent;

/// eBPF (cgroup-skb) network backend config: L4 flow telemetry. `iface`/`bpf`
/// are used only when the `pcap` feature provides a real live-capture fallback.
#[cfg(feature = "ebpf")]
#[derive(Debug, Clone)]
pub struct EbpfNetConfig {
    /// Flow accounting window.
    pub duration: std::time::Duration,
    /// Interface for the optional pcap fallback (`any`, `eth0`, …).
    pub iface: String,
    /// BPF filter for the optional pcap fallback.
    pub bpf: String,
}

/// Connection-table polling backend config (feature `winnet`).
#[cfg(feature = "winnet")]
#[derive(Debug, Clone)]
pub struct WinNetConfig {
    /// How long to poll the connection table for.
    pub duration: std::time::Duration,
    /// Interval between connection-table snapshots.
    pub poll_interval: std::time::Duration,
}

/// Which capture backend to use for one cycle.
#[derive(Debug, Clone, Default)]
pub enum CaptureBackend {
    /// Synthetic events for testing and CI.
    #[default]
    Mock,
    /// Live libpcap capture (requires `pcap` feature + libpcap). Userspace L7
    /// parsing yields JA3 / TLS SNI / DNS.
    #[cfg(feature = "pcap")]
    Pcap(pcap::PcapConfig),
    /// In-kernel eBPF cgroup-skb flow telemetry (requires `ebpf` feature +
    /// CAP_BPF + cgroup-v2). L4-only (no JA3/SNI/DNS). Falls back only to live
    /// pcap when that feature is present; otherwise an unavailable backend is an
    /// error and never silently becomes synthetic mock telemetry.
    #[cfg(feature = "ebpf")]
    Ebpf(EbpfNetConfig),
    /// OS connection-table snapshot polling (feature `winnet`): IP Helper on
    /// Windows / `/proc` on Linux, via the safe `netstat2` wrapper. Emits one
    /// `TraceEvent` per distinct TCP connection (dst_ip/port for IOC matching);
    /// no byte/packet counters and no admin/libpcap/eBPF requirement.
    #[cfg(feature = "winnet")]
    WinNet(WinNetConfig),
}

/// Options passed to [`capture`].
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Which capture backend this cycle uses.
    pub backend: CaptureBackend,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            backend: CaptureBackend::Mock,
        }
    }
}

impl CaptureConfig {
    /// Config for the default mock backend (synthetic events; no privileges).
    pub fn mock() -> Self {
        Self::default()
    }

    /// Build a pcap capture config: capture on `iface` for `duration_secs`
    /// seconds, filtering with the BPF expression `bpf`.
    #[cfg(feature = "pcap")]
    pub fn pcap(iface: impl Into<String>, duration_secs: u64, bpf: impl Into<String>) -> Self {
        use std::time::Duration;

        Self {
            backend: CaptureBackend::Pcap(pcap::PcapConfig {
                iface: iface.into(),
                duration: Duration::from_secs(duration_secs),
                bpf: bpf.into(),
            }),
        }
    }

    /// Build an eBPF (cgroup-skb) flow-telemetry config (L4-only). `iface`/`bpf`
    /// parameterize the optional pcap fallback used when eBPF is unavailable.
    #[cfg(feature = "ebpf")]
    pub fn ebpf(iface: impl Into<String>, duration_secs: u64, bpf: impl Into<String>) -> Self {
        Self {
            backend: CaptureBackend::Ebpf(EbpfNetConfig {
                duration: std::time::Duration::from_secs(duration_secs),
                iface: iface.into(),
                bpf: bpf.into(),
            }),
        }
    }

    /// Build a connection-table polling config: snapshot the OS connection table
    /// for `duration_secs` seconds (IP Helper on Windows, `/proc` on Linux).
    #[cfg(feature = "winnet")]
    pub fn win_net(duration_secs: u64) -> Self {
        use std::time::Duration;

        Self {
            backend: CaptureBackend::WinNet(WinNetConfig {
                duration: Duration::from_secs(duration_secs),
                poll_interval: Duration::from_millis(500),
            }),
        }
    }
}

/// Run one capture cycle and return observed events.
pub fn capture(host_id: &str, config: &CaptureConfig) -> anyhow::Result<Vec<TraceEvent>> {
    match &config.backend {
        CaptureBackend::Mock => Ok(mock::capture(host_id)),
        #[cfg(feature = "pcap")]
        CaptureBackend::Pcap(cfg) => pcap::capture(host_id, cfg),
        #[cfg(feature = "ebpf")]
        CaptureBackend::Ebpf(cfg) => match ebpf_net::capture(host_id, cfg.duration) {
            Ok(events) => Ok(events),
            Err(e) => {
                #[cfg(feature = "pcap")]
                {
                    eprintln!(
                        "agent-collect-trace: eBPF network capture unavailable ({e}); falling back \
                         to live pcap (which also restores L7 JA3/SNI/DNS)"
                    );
                    ebpf_fallback(host_id, cfg)
                }
                #[cfg(not(feature = "pcap"))]
                {
                    Err(ebpf_without_live_fallback_error(e))
                }
            }
        },
        #[cfg(feature = "winnet")]
        CaptureBackend::WinNet(cfg) => win_net_capture(host_id, cfg),
    }
}

/// Live fallback path when the eBPF backend cannot load or attach. Synthetic
/// mock events are deliberately excluded from this path.
#[cfg(all(feature = "ebpf", feature = "pcap"))]
fn ebpf_fallback(host_id: &str, cfg: &EbpfNetConfig) -> anyhow::Result<Vec<TraceEvent>> {
    let pcfg = pcap::PcapConfig {
        iface: cfg.iface.clone(),
        duration: cfg.duration,
        bpf: cfg.bpf.clone(),
    };
    pcap::capture(host_id, &pcfg)
}

#[cfg(all(feature = "ebpf", not(feature = "pcap")))]
fn ebpf_without_live_fallback_error(error: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(
        "eBPF network capture unavailable and no live pcap fallback is compiled: {error}"
    )
}

#[cfg(all(test, feature = "ebpf", not(feature = "pcap")))]
mod ebpf_fallback_tests {
    use super::*;

    #[test]
    fn unavailable_ebpf_without_pcap_is_an_error_not_mock_telemetry() {
        let error = ebpf_without_live_fallback_error("load failed");
        let message = error.to_string();
        assert!(message.contains("no live pcap fallback"));
        assert!(message.contains("load failed"));
    }
}

// ----------------------------------------------- winnet (connection-table) backend

/// Poll the OS connection table for `cfg.duration`, emitting one `TraceEvent` per
/// distinct TCP connection observed (deduped by 5-tuple; first/last-seen become
/// start/end). IP Helper on Windows, `/proc` on Linux — via the safe `netstat2`
/// wrapper, so this stays `unsafe_code = "deny"`-clean.
#[cfg(feature = "winnet")]
fn win_net_capture(host_id: &str, cfg: &WinNetConfig) -> anyhow::Result<Vec<TraceEvent>> {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::time::Instant;

    use chrono::{DateTime, Utc};
    use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

    type Key = (IpAddr, u16, IpAddr, u16);
    let mut seen: HashMap<Key, (DateTime<Utc>, DateTime<Utc>)> = HashMap::new();
    let mut successful_snapshots = 0usize;
    let mut last_error = None;
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let deadline = Instant::now() + cfg.duration;
    loop {
        // A transient read error (race on the table) is non-fatal, but a whole
        // window with no successful snapshot means the live source is dead and
        // must be surfaced to Respond rather than masquerading as an empty set.
        match get_sockets_info(af, ProtocolFlags::TCP) {
            Ok(socks) => {
                successful_snapshots += 1;
                let now = Utc::now();
                for si in socks {
                    if let ProtocolSocketInfo::Tcp(t) = si.protocol_socket_info {
                        if !is_capturable(&t.remote_addr, t.remote_port) {
                            continue; // listeners / no peer
                        }
                        let key = (t.local_addr, t.local_port, t.remote_addr, t.remote_port);
                        seen.entry(key)
                            .and_modify(|(_, last)| *last = now)
                            .or_insert((now, now));
                    }
                }
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(cfg.poll_interval);
    }

    require_live_snapshots(successful_snapshots, last_error.as_deref())?;

    Ok(seen
        .into_iter()
        .map(|((sip, sport, dip, dport), (start, end))| {
            flow_to_event(host_id, sip, sport, dip, dport, start, end)
        })
        .collect())
}

#[cfg(feature = "winnet")]
fn require_live_snapshots(
    successful_snapshots: usize,
    last_error: Option<&str>,
) -> anyhow::Result<()> {
    if successful_snapshots == 0 {
        anyhow::bail!(
            "OS connection-table capture failed for the entire window: {}",
            last_error.unwrap_or("no snapshot was returned")
        );
    }
    Ok(())
}

/// A connection is capturable if it has a real peer (excludes LISTEN sockets,
/// which carry an unspecified remote address / port 0).
#[cfg(feature = "winnet")]
fn is_capturable(remote: &std::net::IpAddr, remote_port: u16) -> bool {
    !remote.is_unspecified() && remote_port != 0
}

/// Map one observed TCP connection to a `TraceEvent`. Byte/packet counters are
/// unknown for the connection-table backend (left 0); the IOC matcher in
/// `lib.rs` enriches `dst_ip` afterwards.
#[cfg(feature = "winnet")]
fn flow_to_event(
    host_id: &str,
    src_ip: std::net::IpAddr,
    src_port: u16,
    dst_ip: std::net::IpAddr,
    dst_port: u16,
    start_ts: chrono::DateTime<chrono::Utc>,
    end_ts: chrono::DateTime<chrono::Utc>,
) -> TraceEvent {
    TraceEvent {
        trace_id: format!("trace-net-{}", uuid::Uuid::new_v4()),
        host_id: host_id.to_string(),
        start_ts,
        end_ts,
        proto: crate::contract::TraceProto::Tcp,
        src_ip,
        src_port: Some(src_port),
        dst_ip,
        dst_port: Some(dst_port),
        bytes_sent: 0,
        bytes_recv: 0,
        packets_sent: 0,
        packets_recv: 0,
        app_proto: None,
        dns_query: None,
        tls_sni: None,
        ja3: None,
        threat_intel: Vec::new(),
    }
}

#[cfg(all(test, feature = "winnet"))]
mod winnet_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::contract::TraceProto;

    use super::*;

    #[test]
    fn capturable_skips_listeners_keeps_peers() {
        // LISTEN sockets: unspecified remote or port 0 → skipped.
        assert!(!is_capturable(&IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        assert!(!is_capturable(&IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443));
        assert!(!is_capturable(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0));
        // Real peers (including loopback) → kept; IOC matcher decides relevance.
        assert!(is_capturable(
            &IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443
        ));
        assert!(is_capturable(&IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
    }

    #[test]
    fn flow_maps_to_trace_event() {
        let now = chrono::Utc::now();
        let ev = flow_to_event(
            "h1",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            50000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            now,
            now,
        );
        assert_eq!(ev.host_id, "h1");
        assert_eq!(ev.proto, TraceProto::Tcp);
        assert_eq!(ev.src_port, Some(50000));
        assert_eq!(ev.dst_port, Some(443));
        assert_eq!(ev.bytes_sent, 0);
        assert!(ev.threat_intel.is_empty());
        assert!(ev.trace_id.starts_with("trace-net-"));
    }

    #[test]
    fn an_entire_window_of_snapshot_errors_is_fatal() {
        let error = require_live_snapshots(0, Some("permission denied"))
            .expect_err("zero successful snapshots must fail");
        assert!(error.to_string().contains("permission denied"));
        require_live_snapshots(1, Some("later transient error"))
            .expect("one successful snapshot keeps transient errors non-fatal");
    }

    // Smoke: a real loopback TCP connection must show up as a TraceEvent. Works on
    // Linux (/proc) and Windows (IP Helper); needs no admin / external network.
    #[test]
    fn winnet_smoke_observes_loopback_connection() {
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping winnet smoke: sandbox forbids loopback sockets");
                return;
            }
            Err(error) => panic!("bind loopback smoke listener: {error}"),
        };
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        // Hold both ends open across the capture window so the connection is
        // ESTABLISHED for at least one poll.
        let _client = TcpStream::connect(addr).unwrap();
        let (_server, _) = listener.accept().unwrap();

        let cfg = WinNetConfig {
            duration: Duration::from_secs(2),
            poll_interval: Duration::from_millis(150),
        };
        let events = win_net_capture("smoke-host", &cfg).expect("read connection table");

        let found = events
            .iter()
            .any(|e| e.dst_port == Some(port) || e.src_port == Some(port));
        assert!(
            found,
            "expected a TraceEvent for the loopback connection on port {port}; got {} events",
            events.len()
        );
    }
}
