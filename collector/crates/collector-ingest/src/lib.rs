//! collector-ingest: push [`FlowBatch`] JSON to form (`/ingest/flow-batch`).
//!
//! Used by `collector-cli --upload`. Expects form to respond with
//! `202 Accepted` on success. Mirrors the scanner's `scanner-ingest`.

use std::time::Duration;

use collector_core::FlowBatch;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Upload a batch to form's `/ingest/flow-batch` endpoint.
///
/// `form_base_url` is the form API root (e.g. `http://127.0.0.1:8000`).
pub fn upload_batch(batch: &FlowBatch, form_base_url: &str) -> anyhow::Result<()> {
    let url = ingest_url(form_base_url);
    let client = reqwest::blocking::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .map_err(|e| anyhow::anyhow!("build HTTP client: {e}"))?;

    let mut request = client.post(&url).json(batch);
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

fn ingest_url(form_base_url: &str) -> String {
    format!(
        "{}/ingest/flow-batch",
        form_base_url.trim().trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ingest_url() {
        assert_eq!(
            ingest_url("http://127.0.0.1:8000"),
            "http://127.0.0.1:8000/ingest/flow-batch"
        );
        assert_eq!(
            ingest_url("http://127.0.0.1:8000/"),
            "http://127.0.0.1:8000/ingest/flow-batch"
        );
    }
}
