//! Flow capture backends.
//!
//! v0 ships a `mock` backend (synthetic events) and an optional `pcap`
//! backend (live libpcap capture with 5-tuple aggregation). Both return
//! the same `Vec<TraceEvent>` so callers in `lib.rs` need not change.

pub mod mock;
pub mod parse;

#[cfg(feature = "pcap")]
pub mod pcap;

#[cfg(feature = "ebpf")]
pub mod ebpf_net;

use crate::contract::TraceEvent;

/// eBPF (cgroup-skb) network backend config: L4 flow telemetry. `iface`/`bpf`
/// are only used to build the pcap fallback when eBPF is unavailable at runtime.
#[cfg(feature = "ebpf")]
#[derive(Debug, Clone)]
pub struct EbpfNetConfig {
    /// Flow accounting window.
    pub duration: std::time::Duration,
    /// Interface for the pcap fallback (`any`, `eth0`, …).
    pub iface: String,
    /// BPF filter for the pcap fallback.
    pub bpf: String,
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
    /// CAP_BPF + cgroup-v2). L4-only (no JA3/SNI/DNS); falls back to pcap/mock
    /// when unavailable at runtime.
    #[cfg(feature = "ebpf")]
    Ebpf(EbpfNetConfig),
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
    /// parameterize the pcap fallback used when eBPF is unavailable at runtime.
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
                eprintln!(
                    "agent-trace: eBPF network capture unavailable ({e}); falling back \
                     (eBPF backend is L4-only — pcap fallback also restores L7 JA3/SNI/DNS)"
                );
                ebpf_fallback(host_id, cfg)
            }
        },
    }
}

/// Fallback path when the eBPF backend can't load/attach: prefer pcap (restores
/// L7), else synthetic mock.
#[cfg(feature = "ebpf")]
fn ebpf_fallback(host_id: &str, cfg: &EbpfNetConfig) -> anyhow::Result<Vec<TraceEvent>> {
    #[cfg(feature = "pcap")]
    {
        let pcfg = pcap::PcapConfig {
            iface: cfg.iface.clone(),
            duration: cfg.duration,
            bpf: cfg.bpf.clone(),
        };
        pcap::capture(host_id, &pcfg)
    }
    #[cfg(not(feature = "pcap"))]
    {
        let _ = cfg;
        Ok(mock::capture(host_id))
    }
}
