//! Host security-posture collector: sshd_config / shadow / SUID misconfig
//! findings emitted as host-attributed `source = "posture"` vulnerabilities.
//!
//! Registered for HOST (top-level root) scans only — never for `--image`
//! assembled rootfs or nested container scans — so a finding's `host_id`
//! attribution is always correct (see `cli::build_plan` / `agentd` `collect_host`).

use crate::sources;
use crate::{Collector, CollectorOutput, ScanContext};

/// Emits posture misconfiguration findings (sshd_config, /etc/shadow, SUID/SGID).
pub struct PostureCollector;

impl Collector for PostureCollector {
    fn id(&self) -> &'static str {
        "posture"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "posture")?;
        let host_id = ctx
            .host_id
            .clone()
            .expect("require_host_id guarantees host_id is set");
        Ok(CollectorOutput::Vulnerabilities(sources::posture::collect(
            ctx, &host_id,
        )))
    }
}
