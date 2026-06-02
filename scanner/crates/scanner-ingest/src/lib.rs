//! scanner-ingest: push [`AssetReport`] JSON to form (`/ingest/asset-report`).
//!
//! Used by `scanner-cli --upload` and `scanner-remote --upload`. Expects form
//! to respond with `202 Accepted` on success.

use std::time::Duration;

use scanner_contract::AssetReport;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Upload a report to form's `/ingest/asset-report` endpoint.
///
/// `form_base_url` is the form API root (e.g. `http://127.0.0.1:8000`).
pub fn upload_report(report: &AssetReport, form_base_url: &str) -> anyhow::Result<()> {
    let url = ingest_url(form_base_url);
    let client = reqwest::blocking::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .map_err(|e| anyhow::anyhow!("build HTTP client: {e}"))?;

    let mut request = client.post(&url).json(report);
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
        "{}/ingest/asset-report",
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
            "http://127.0.0.1:8000/ingest/asset-report"
        );
        assert_eq!(
            ingest_url("http://127.0.0.1:8000/"),
            "http://127.0.0.1:8000/ingest/asset-report"
        );
    }
}
