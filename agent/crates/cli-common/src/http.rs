//! Blocking HTTP client shared by the agent binaries.
//!
//! Used by `posture-flow intel-sync` to download IOC feeds. fusion *uploads*
//! (`AssetReport` / `FlowBatch` / `GuardEventBatch`) live in `agent-ingest`,
//! which keeps its own bearer-auth POST path.

use std::time::Duration;

use anyhow::Context;

/// User-agent sent by the shared blocking client.
pub const USER_AGENT: &str = concat!("posture-agent/", env!("CARGO_PKG_VERSION"));

/// Build a blocking reqwest client with `timeout` and the posture user-agent.
pub fn blocking_client(timeout: Duration) -> anyhow::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(USER_AGENT)
        .build()
        .context("build HTTP client")
}

/// GET `url` and return the response body as text, erroring on a non-success
/// status.
pub fn get_text(url: &str, timeout: Duration) -> anyhow::Result<String> {
    let client = blocking_client(timeout)?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("GET {url} failed ({status})");
    }

    response
        .text()
        .with_context(|| format!("read body from {url}"))
}
