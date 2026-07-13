//! eBPF process and file-event source.

use std::time::Duration;

use crate::source::{Source, SourceResult};

/// A bounded eBPF tracepoint collection source.
#[derive(Debug, Clone, Copy)]
pub struct EbpfSource {
    duration: Duration,
}

impl EbpfSource {
    /// Create an eBPF source that collects for `duration`.
    pub fn new(duration: Duration) -> Self {
        Self { duration }
    }

    /// Return the configured collection duration.
    pub fn duration(&self) -> Duration {
        self.duration
    }
}

impl Source for EbpfSource {
    fn id(&self) -> &'static str {
        "ebpf"
    }

    fn collect(&self, collector_id: &str) -> anyhow::Result<Vec<SourceResult>> {
        let (processes, files) = crate::ebpf::capture(collector_id, self.duration)?;
        let mut results = Vec::new();
        if !files.is_empty() {
            results.push(SourceResult::FileEvents(files));
        }
        if !processes.is_empty() {
            results.push(SourceResult::ProcessEvents(processes));
        }
        Ok(results)
    }
}
