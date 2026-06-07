//! Flow capture backends.
//!
//! v0 ships a `mock` backend (synthetic flows) and an optional `pcap`
//! backend (live libpcap capture with 5-tuple aggregation). Both return
//! the same `Vec<FlowEvent>` so callers in `lib.rs` need not change.

pub mod mock;
pub mod parse;

#[cfg(feature = "pcap")]
pub mod pcap;

use crate::contract::FlowEvent;

/// Which capture backend to use for one cycle.
#[derive(Debug, Clone, Default)]
pub enum CaptureBackend {
    /// Synthetic flows for testing and CI.
    #[default]
    Mock,
    /// Live libpcap capture (requires `pcap` feature + libpcap).
    #[cfg(feature = "pcap")]
    Pcap(pcap::PcapConfig),
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
    /// Config for the default mock backend (synthetic flows; no privileges).
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
}

/// Run one capture cycle and return observed flows.
pub fn capture(host_id: &str, config: &CaptureConfig) -> anyhow::Result<Vec<FlowEvent>> {
    match &config.backend {
        CaptureBackend::Mock => Ok(mock::capture(host_id)),
        #[cfg(feature = "pcap")]
        CaptureBackend::Pcap(cfg) => pcap::capture(host_id, cfg),
    }
}
