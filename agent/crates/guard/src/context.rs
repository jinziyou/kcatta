//! Runtime identity shared by every emitted event.

/// Stable per-run identity attached to every [`crate::Detection`] turned into a
/// reported event: which host, which agent version.
#[derive(Debug, Clone)]
pub struct GuardContext {
    /// Host id (from config, or auto-resolved from the hostname).
    pub host_id: String,
    /// Version string of the guard agent producing the events.
    pub agent_version: String,
}

impl GuardContext {
    /// Build a context, resolving `host_id` from config or the system hostname.
    pub fn new(host_id: Option<String>, agent_version: impl Into<String>) -> Self {
        let host_id = host_id
            .filter(|h| !h.trim().is_empty())
            .unwrap_or_else(resolve_host_id);
        Self {
            host_id,
            agent_version: agent_version.into(),
        }
    }
}

/// Best-effort hostname → host id, falling back to `unknown-host`.
fn resolve_host_id() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".to_string())
}
