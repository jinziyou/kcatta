//! HTTP ingest client — push agent telemetry JSON to fusion.
//!
//! This is the ingest capability, **owned by the `agent` umbrella**: the lean
//! capability binaries (`agent-host`/`agent-flow`/`agent-guard`) only
//! produce results locally; uploading to fusion happens only when run via
//! `agent <cap> --upload`.
//!
//! One blocking client for all three envelopes:
//! - [`upload_report`]      — host [`AssetReport`] -> `/ingest/asset-report`
//! - [`upload_batch`]       — network [`FlowBatch`] -> `/ingest/flow-batch`
//! - [`upload_guard_batch`] — guard [`GuardEventBatch`] -> `/ingest/guard-event`
//!
//! Every endpoint expects fusion to respond `202 Accepted`; a bearer token is
//! read from `FUSION_API_TOKEN` when present.

use std::time::Duration;

use agent_contract::{AssetReport, FlowBatch, GuardEventBatch};
use serde::Serialize;

/// HTTP upload timeout (seconds) when `FUSION_UPLOAD_TIMEOUT` is unset.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Upload a host asset report to fusion's `/ingest/asset-report` endpoint.
pub fn upload_report(report: &AssetReport, base_url: &str) -> anyhow::Result<()> {
    post_json(report, base_url, "/ingest/asset-report")
}

/// Upload a network flow batch to fusion's `/ingest/flow-batch` endpoint.
pub fn upload_batch(batch: &FlowBatch, base_url: &str) -> anyhow::Result<()> {
    post_json(batch, base_url, "/ingest/flow-batch")
}

/// Upload a real-time protection event batch to fusion's `/ingest/guard-event`.
pub fn upload_guard_batch(batch: &GuardEventBatch, base_url: &str) -> anyhow::Result<()> {
    post_json(batch, base_url, "/ingest/guard-event")
}

/// Resolve the request timeout, overridable via `FUSION_UPLOAD_TIMEOUT` (seconds).
fn upload_timeout() -> Duration {
    let secs = std::env::var("FUSION_UPLOAD_TIMEOUT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Read the bearer token from `FUSION_API_TOKEN`, treating an empty/whitespace
/// value as unset so a stray `export FUSION_API_TOKEN=` doesn't send an empty
/// `Authorization: Bearer` header (which would fail auth for the wrong reason).
fn bearer_token() -> Option<String> {
    std::env::var("FUSION_API_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// POST a serializable payload to `<base_url><path>`, attaching the
/// `FUSION_API_TOKEN` bearer when set and treating `202 Accepted` as success.
fn post_json<T: Serialize>(payload: &T, base_url: &str, path: &str) -> anyhow::Result<()> {
    let url = ingest_url(base_url, path);
    let client = reqwest::blocking::Client::builder()
        .timeout(upload_timeout())
        .build()
        .map_err(|e| anyhow::anyhow!("build HTTP client: {e}"))?;

    let mut request = client.post(&url).json(payload);
    if let Some(token) = bearer_token() {
        request = request.header("Authorization", format!("Bearer {token}"));
    }

    let response = request
        .send()
        .map_err(|e| anyhow::anyhow!("POST {url}: {e}"))?;

    let status = response.status();
    if status == reqwest::StatusCode::ACCEPTED {
        return Ok(());
    }

    let body = response
        .text()
        .unwrap_or_else(|_| String::from("<unreadable body>"));
    anyhow::bail!("fusion ingest failed ({status}): {body}")
}

fn ingest_url(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim().trim_end_matches('/'), path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ingest_url() {
        assert_eq!(
            ingest_url("http://127.0.0.1:8000", "/ingest/asset-report"),
            "http://127.0.0.1:8000/ingest/asset-report"
        );
        assert_eq!(
            ingest_url("http://127.0.0.1:8000/", "/ingest/flow-batch"),
            "http://127.0.0.1:8000/ingest/flow-batch"
        );
    }
}
