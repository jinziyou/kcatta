//! Network trace source.

use crate::source::{Source, SourceResult};
use crate::{CaptureBackend, CaptureConfig};

/// A network source backed by one [`CaptureConfig`].
#[derive(Debug, Clone)]
pub struct NetworkSource {
    config: CaptureConfig,
}

impl NetworkSource {
    /// Create a network source for the selected capture backend.
    pub fn new(config: CaptureConfig) -> Self {
        Self { config }
    }

    /// Return this source's capture configuration.
    pub fn config(&self) -> &CaptureConfig {
        &self.config
    }
}

impl From<CaptureConfig> for NetworkSource {
    fn from(config: CaptureConfig) -> Self {
        Self::new(config)
    }
}

impl Source for NetworkSource {
    fn id(&self) -> &'static str {
        match &self.config.backend {
            CaptureBackend::Mock => "mock",
            #[cfg(feature = "pcap")]
            CaptureBackend::Pcap(_) => "pcap",
            #[cfg(feature = "ebpf")]
            CaptureBackend::Ebpf(_) => "ebpf-network",
            #[cfg(feature = "winnet")]
            CaptureBackend::WinNet(_) => "winnet",
        }
    }

    fn collect(&self, collector_id: &str) -> anyhow::Result<Vec<SourceResult>> {
        let events = crate::capture::capture(collector_id, &self.config)?;
        if events.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(vec![SourceResult::NetworkEvents(events)])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_id_names_the_selected_backend() {
        assert_eq!(NetworkSource::new(CaptureConfig::mock()).id(), "mock");

        #[cfg(feature = "winnet")]
        assert_eq!(NetworkSource::new(CaptureConfig::win_net(1)).id(), "winnet");

        #[cfg(feature = "pcap")]
        assert_eq!(
            NetworkSource::new(CaptureConfig::pcap("any", 1, "tcp")).id(),
            "pcap"
        );

        #[cfg(feature = "ebpf")]
        assert_eq!(
            NetworkSource::new(CaptureConfig::ebpf("any", 1, "tcp")).id(),
            "ebpf-network"
        );
    }
}
