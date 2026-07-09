//! Secret/credential-leak collector: plaintext private keys, cloud keys, and
//! provider tokens on the host, emitted as host-attributed `source="secret"`
//! vulnerabilities.
//!
//! Registered for HOST (top-level root) scans only — never for `--image`
//! assembled rootfs or nested container scans — so `host_id` attribution is
//! always correct (see `cli::build_plan` / `agentd` `collect_host`).

use crate::sources;
use crate::{Collector, CollectorOutput, ScanContext};

/// Emits secret-leak findings (private keys, cloud/provider tokens, credential files).
pub struct SecretsCollector;

impl Collector for SecretsCollector {
    fn id(&self) -> &'static str {
        "secret"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "secret")?;
        let host_id = ctx
            .host_id
            .clone()
            .expect("require_host_id guarantees host_id is set");
        Ok(CollectorOutput::Vulnerabilities(sources::secrets::collect(
            ctx, &host_id,
        )))
    }
}
