//! HTTP ingest client — push agent telemetry JSON to analyzer.
//!
//! This is the ingest capability, **owned by the `agentd` umbrella**: the lean
//! capability binaries (`agent-collect-host`/`agent-collect-trace`/`agent-respond`) only
//! produce results locally; uploading to analyzer happens only when run via
//! `agentd <cap> --upload`.
//!
//! One blocking client for all three envelopes:
//! - [`upload_report`]      — host [`AssetReport`] -> `/ingest/asset-report`
//! - [`upload_batch`]       — network [`TraceBatch`] -> `/ingest/trace-batch`
//! - [`upload_guard_batch`] — guard [`GuardEventBatch`] -> `/ingest/guard-event`
//!
//! Every endpoint expects analyzer to respond `202 Accepted`; a bearer token is
//! read from `ANALYZER_API_TOKEN` when present.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_contract::{AssetReport, GuardEventBatch, TraceBatch};
use serde::Serialize;

use crate::spool::{DrainStep, Spool};

/// HTTP upload timeout (seconds) when `ANALYZER_UPLOAD_TIMEOUT` is unset.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Total upload attempts (1 try + retries) when `ANALYZER_UPLOAD_RETRIES` is unset.
const DEFAULT_ATTEMPTS: u32 = 4;

/// Outcome classification for a single POST attempt.
enum PostOutcome {
    /// Accepted (202) — done.
    Accepted,
    /// Transient failure (network error, timeout, 5xx, 429) — worth retrying.
    Transient(anyhow::Error),
    /// Permanent failure (4xx such as 422 validation, 401 auth) — do not retry.
    Permanent(anyhow::Error),
}

/// What became of an upload that did not fail permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOutcome {
    /// analyzer accepted the payload (202) — possibly after also flushing spool.
    Delivered,
    /// analyzer was unreachable; the payload was durably spooled for later retry.
    Spooled,
}

/// Upload a host asset report to analyzer's `/ingest/asset-report` endpoint.
pub fn upload_report(report: &AssetReport, base_url: &str) -> anyhow::Result<UploadOutcome> {
    post_json(report, base_url, "/ingest/asset-report")
}

/// Upload a network trace batch to analyzer's `/ingest/trace-batch` endpoint.
pub fn upload_batch(batch: &TraceBatch, base_url: &str) -> anyhow::Result<UploadOutcome> {
    post_json(batch, base_url, "/ingest/trace-batch")
}

/// Upload a real-time protection event batch to analyzer's `/ingest/guard-event`.
pub fn upload_guard_batch(
    batch: &GuardEventBatch,
    base_url: &str,
) -> anyhow::Result<UploadOutcome> {
    post_json(batch, base_url, "/ingest/guard-event")
}

/// Resolve the request timeout, overridable via `ANALYZER_UPLOAD_TIMEOUT` (seconds).
fn upload_timeout() -> Duration {
    let secs = std::env::var("ANALYZER_UPLOAD_TIMEOUT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Read the bearer token from `ANALYZER_API_TOKEN`, treating an empty/whitespace
/// value as unset so a stray `export ANALYZER_API_TOKEN=` doesn't send an empty
/// `Authorization: Bearer` header (which would fail auth for the wrong reason).
fn bearer_token() -> Option<String> {
    std::env::var("ANALYZER_API_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Total upload attempts, overridable via `ANALYZER_UPLOAD_RETRIES` (number of
/// *retries*; total attempts = retries + 1). Clamped to at least one attempt.
fn upload_attempts() -> u32 {
    std::env::var("ANALYZER_UPLOAD_RETRIES")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|retries| retries.saturating_add(1))
        .unwrap_or(DEFAULT_ATTEMPTS)
        .max(1)
}

/// POST a serializable payload to `<base_url><path>`, attaching the
/// `ANALYZER_API_TOKEN` bearer when set and treating `202 Accepted` as success.
///
/// Order of operations:
///   1. **Flush the spool first** — replay any envelopes a prior cycle left
///      queued during an outage, oldest-first, so delivery order is preserved
///      and the backlog drains as analyzer recovers.
///   2. **Deliver this payload**, retrying transient failures (network errors,
///      timeouts, 5xx, 429) with jittered exponential backoff.
///   3. On transient exhaustion, **spool** the payload durably instead of
///      dropping it (returns [`UploadOutcome::Spooled`]). Permanent failures
///      (4xx — validation/auth) still fail fast: they would never succeed on
///      replay, so they are surfaced as an error rather than spooled.
///
/// If no spool directory is available the call degrades to the prior behaviour:
/// transient exhaustion returns an error (the batch is dropped).
fn post_json<T: Serialize>(
    payload: &T,
    base_url: &str,
    path: &str,
) -> anyhow::Result<UploadOutcome> {
    let value = serde_json::to_value(payload)
        .map_err(|e| anyhow::anyhow!("serialize ingest payload: {e}"))?;
    let client = shared_client()?;
    // Refuse to leak the analyzer credential silently: warn (once) when a bearer
    // token would ride a plaintext http:// channel where it is exposed on the wire.
    if bearer_token().is_some()
        && base_url
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
    {
        warn_plaintext_token_once();
    }
    let spool = Spool::from_env();

    // 1. Best-effort flush of any previously-spooled backlog.
    if let Some(spool) = spool.as_ref() {
        drain_spool(spool, &client, base_url);
    }

    // 2. Deliver this payload.
    match post_with_retries(&client, base_url, path, &value) {
        PostOutcome::Accepted => Ok(UploadOutcome::Delivered),
        // Validation / auth: re-sending can never help — surface it.
        PostOutcome::Permanent(e) => Err(e),
        // 3. analyzer unreachable after every retry: queue durably rather than drop.
        PostOutcome::Transient(e) => match spool.as_ref() {
            Some(spool) => match spool.enqueue(path, &value) {
                Ok(()) => {
                    eprintln!(
                        "agentd: analyzer unreachable; spooled upload to {path} for later \
                         delivery ({e}); spool depth now {}",
                        spool.len()
                    );
                    Ok(UploadOutcome::Spooled)
                }
                Err(se) => Err(anyhow::anyhow!(
                    "upload failed ({e}); spooling also failed ({se})"
                )),
            },
            None => Err(e),
        },
    }
}

/// Build the shared blocking HTTP client with the configured upload timeout.
fn build_client() -> anyhow::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(upload_timeout())
        .build()
        .map_err(|e| anyhow::anyhow!("build HTTP client: {e}"))
}

/// Process-wide reqwest client, built once and reused so its connection pool /
/// TLS keep-alive survives across upload batches. Rebuilding per batch forced a
/// fresh TCP+TLS handshake every time, which is costly on the real-time guard
/// path that uploads frequently. `Client` is internally reference-counted, so the
/// clone is cheap and shares the pool.
fn shared_client() -> anyhow::Result<reqwest::blocking::Client> {
    static CLIENT: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let client = build_client()?;
    // On a race the first setter wins; we still return our freshly built clone.
    let _ = CLIENT.set(client.clone());
    Ok(client)
}

/// Deliver one already-serialized payload to `<base_url><path>`, retrying
/// transient failures with jittered backoff. Returns the final [`PostOutcome`].
fn post_with_retries(
    client: &reqwest::blocking::Client,
    base_url: &str,
    path: &str,
    value: &serde_json::Value,
) -> PostOutcome {
    let url = ingest_url(base_url, path);
    let attempts = upload_attempts();
    let mut last_err = None;
    for attempt in 1..=attempts {
        match try_post(client, &url, value) {
            PostOutcome::Accepted => return PostOutcome::Accepted,
            PostOutcome::Permanent(e) => return PostOutcome::Permanent(e),
            PostOutcome::Transient(e) => {
                last_err = Some(e);
                if attempt < attempts {
                    let backoff = jittered_backoff(attempt);
                    eprintln!(
                        "agentd: upload to {url} failed (attempt {attempt}/{attempts}), retrying in {backoff:?}"
                    );
                    std::thread::sleep(backoff);
                }
            }
        }
    }
    PostOutcome::Transient(last_err.unwrap_or_else(|| anyhow::anyhow!("upload to {url} failed")))
}

/// Replay the spooled backlog through a single (no per-item retry) POST each,
/// reconstructing the URL against the *current* `base_url`. Returns how many were
/// delivered.
fn drain_spool(spool: &Spool, client: &reqwest::blocking::Client, base_url: &str) -> usize {
    let delivered = spool.drain(|route, body| {
        let url = ingest_url(base_url, route);
        match try_post(client, &url, body) {
            PostOutcome::Accepted => DrainStep::Delivered,
            PostOutcome::Permanent(_) => DrainStep::Permanent,
            PostOutcome::Transient(_) => DrainStep::Transient,
        }
    });
    if delivered > 0 {
        eprintln!(
            "agentd: flushed {delivered} spooled upload(s) to {base_url} ({} still queued)",
            spool.len()
        );
    }
    delivered
}

/// Best-effort: flush any spooled backlog once, returning how many were
/// delivered. Intended for graceful shutdown — `agentd run` calls this so a
/// queued backlog is pushed before exit instead of waiting for the next cycle.
/// Does nothing (returns 0) when no spool is configured or it is empty.
pub fn flush_spool(base_url: &str) -> usize {
    let Some(spool) = Spool::from_env() else {
        return 0;
    };
    if spool.is_empty() {
        return 0;
    }
    let Ok(client) = build_client() else {
        return 0;
    };
    drain_spool(&spool, &client, base_url)
}

/// Bounded exponential backoff (200ms, 400ms, … capped at 5s) with ±25% jitter,
/// so a fleet of agents retrying after one analyzer restart does not synchronise
/// into a thundering herd. Jitter is drawn from the clock — no rng dependency.
fn jittered_backoff(attempt: u32) -> Duration {
    // Clamp the shift so a large ANALYZER_UPLOAD_RETRIES can't overflow it.
    let shift = (attempt - 1).min(20);
    let base = 200u64.saturating_mul(1u64 << shift).min(5_000);
    let span = base / 4; // ±25%
    if span == 0 {
        return Duration::from_millis(base);
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0);
    let delta = (nanos % (2 * span + 1)) as i64 - span as i64;
    let ms = (base as i64 + delta).max(0) as u64;
    Duration::from_millis(ms)
}

/// Warn exactly once per process that the API token is being sent over plaintext.
fn warn_plaintext_token_once() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "[agentd] warning: sending API bearer token over plaintext http:// — \
             the analyzer credential is exposed on the wire; use https://"
        );
    });
}

/// One POST attempt, classified for the retry loop.
fn try_post<T: Serialize>(
    client: &reqwest::blocking::Client,
    url: &str,
    payload: &T,
) -> PostOutcome {
    let mut request = client.post(url).json(payload);
    if let Some(token) = bearer_token() {
        request = request.header("Authorization", format!("Bearer {token}"));
    }

    let response = match request.send() {
        Ok(r) => r,
        // Connection refused / DNS / timeout — analyzer may just be (re)starting.
        Err(e) => return PostOutcome::Transient(anyhow::anyhow!("POST {url}: {e}")),
    };

    let status = response.status();
    if status == reqwest::StatusCode::ACCEPTED {
        return PostOutcome::Accepted;
    }

    let body = response
        .text()
        .unwrap_or_else(|_| String::from("<unreadable body>"));
    let err = anyhow::anyhow!("analyzer ingest failed ({status}): {body}");
    // 5xx and 429 are worth retrying; other 4xx (422 validation, 401 auth) are not.
    if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        PostOutcome::Transient(err)
    } else {
        PostOutcome::Permanent(err)
    }
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
            ingest_url("http://127.0.0.1:10068", "/ingest/asset-report"),
            "http://127.0.0.1:10068/ingest/asset-report"
        );
        assert_eq!(
            ingest_url("http://127.0.0.1:10068/", "/ingest/trace-batch"),
            "http://127.0.0.1:10068/ingest/trace-batch"
        );
    }

    #[test]
    fn jittered_backoff_stays_within_25_percent() {
        // Sample each attempt's backoff repeatedly; every draw must land inside
        // the ±25% band around the bounded exponential base.
        for attempt in 1..=6u32 {
            let shift = (attempt - 1).min(20);
            let base = 200u64.saturating_mul(1u64 << shift).min(5_000);
            let lo = base - base / 4;
            let hi = base + base / 4;
            for _ in 0..50 {
                let ms = jittered_backoff(attempt).as_millis() as u64;
                assert!(
                    ms >= lo && ms <= hi,
                    "attempt {attempt}: {ms} not in [{lo},{hi}]"
                );
            }
        }
    }
}
