//! scanner-vuln: CVE / package vulnerability scanning.
//!
//! v0 ships a no-op [`VulnCollector`] so the orchestration wiring is in place.
//! Next step: bridge trivy or similar and emit [`scanner_contract::Vulnerability`].

use scanner_runtime::{Collector, CollectorOutput, ScanContext};

pub struct VulnCollector;

impl Collector for VulnCollector {
    fn id(&self) -> &'static str {
        "vuln"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        if ctx.host_id.is_none() {
            anyhow::bail!("host collector must run before vuln");
        }
        Ok(CollectorOutput::Vulnerabilities(Vec::new()))
    }
}
