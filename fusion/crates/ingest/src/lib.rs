//! fusion-ingest: push fusion telemetry JSON to form over HTTP.
//!
//! One blocking client shared by both fusion envelopes:
//! - [`upload_report`] — host [`AssetReport`] -> `/ingest/asset-report`
//! - [`upload_batch`]  — network [`FlowBatch`] -> `/ingest/flow-batch`
//!
//! Used by the `fusion` orchestrator for both the `host` and `flow` subcommands'
//! `--upload`. Both endpoints expect form to respond with `202 Accepted` on
//! success, and pick up a bearer token from `FORM_API_TOKEN` when present.

use std::time::Duration;

use fusion_contract::{AssetReport, FlowBatch};
use serde::Serialize;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Upload a host asset report to form's `/ingest/asset-report` endpoint.
///
/// `form_base_url` is the form API root (e.g. `http://127.0.0.1:8000`).
pub fn upload_report(report: &AssetReport, form_base_url: &str) -> anyhow::Result<()> {
    post_json(report, form_base_url, "/ingest/asset-report")
}

/// Upload a network flow batch to form's `/ingest/flow-batch` endpoint.
///
/// `form_base_url` is the form API root (e.g. `http://127.0.0.1:8000`).
pub fn upload_batch(batch: &FlowBatch, form_base_url: &str) -> anyhow::Result<()> {
    post_json(batch, form_base_url, "/ingest/flow-batch")
}

/// POST a serializable payload to `<form_base_url><path>`, attaching the
/// `FORM_API_TOKEN` bearer when set and treating `202 Accepted` as success.
fn post_json<T: Serialize>(payload: &T, form_base_url: &str, path: &str) -> anyhow::Result<()> {
    let url = ingest_url(form_base_url, path);
    let client = reqwest::blocking::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .map_err(|e| anyhow::anyhow!("build HTTP client: {e}"))?;

    let mut request = client.post(&url).json(payload);
    if let Ok(token) = std::env::var("FORM_API_TOKEN") {
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
    anyhow::bail!("form ingest failed ({status}): {body}")
}

fn ingest_url(form_base_url: &str, path: &str) -> String {
    format!("{}{}", form_base_url.trim().trim_end_matches('/'), path)
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
