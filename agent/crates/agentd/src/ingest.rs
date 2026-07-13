//! HTTP ingest client — push agent telemetry JSON to Form.
//!
//! This is the ingest capability, **owned by the `agentd` umbrella**: the lean
//! capability binaries (`agent-collect-host`/`agent-collect-trace`/`agent-respond`) only
//! produce results locally; uploading to Form happens only when run via
//! `agentd <cap> --upload`.
//!
//! One blocking client for all three envelopes:
//! - [`upload_report`]      — host [`AssetReport`] -> `/ingest/asset-report`
//! - [`upload_batch`]       — network [`TraceBatch`] -> `/ingest/trace-batch`
//! - [`spool_guard_batch`] — guard [`GuardEventBatch`] -> durable outbox when available
//! - [`upload_guard_batch_live_while`] — bounded live fallback when durable storage is unavailable
//!
//! Every endpoint expects Form to respond `202 Accepted`. A bearer token is
//! read from `FORM_AGENT_TOKEN` when present, with `FORM_INGEST_TOKEN` retained
//! as a deprecated compatibility fallback. Optional per-Agent mTLS identity is
//! loaded from `FORM_AGENT_CERT`, `FORM_AGENT_KEY`, and `FORM_AGENT_CA`.

use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use agent_contract::{
    bounded_correlation_id, AssetReport, FileTraceEvent, GuardEventBatch, ProcessTraceEvent,
    ThreatMatch, TraceBatch, TraceEvent, CORRELATION_IDENTIFIER_MAX_CHARS,
};
use serde::Serialize;

use crate::spool::{DrainStep, Spool};

/// HTTP upload timeout (seconds) when `FORM_UPLOAD_TIMEOUT` is unset.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Total upload attempts (1 try + retries) when `FORM_UPLOAD_RETRIES` is unset.
const DEFAULT_ATTEMPTS: u32 = 4;

/// Upper bound for each PEM input. Certificates and keys are normally only a
/// few KiB; this prevents an accidental device/huge file path from being read
/// without bound on every upload cycle.
const MAX_TLS_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Keep every request comfortably below Form's 10 MiB request-body ceiling.
/// The size is measured from the exact compact JSON bytes produced by serde.
const MAX_INGEST_BODY_BYTES: usize = 9 * 1024 * 1024;

/// Form schema limits for the top-level telemetry arrays.
const MAX_SCHEMA_ITEMS: usize = 4_096;

/// Form schema limit for IOC matches attached to one trace event.
const MAX_THREAT_INTEL_ITEMS: usize = 64;

/// Outcome classification for a single POST attempt.
enum PostOutcome {
    /// Accepted (202) — done.
    Accepted,
    /// Transient failure (network error, timeout, 408, 429, 5xx) — worth retrying.
    Transient(anyhow::Error),
    /// Authentication is temporarily blocked (401/403). Retain queued data so
    /// a token or certificate rotation can recover delivery.
    AuthBlocked(anyhow::Error),
    /// Permanent failure (4xx such as 400/413/422 validation) — do not retry.
    Permanent(anyhow::Error),
}

/// What became of an upload that did not fail permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOutcome {
    /// Form accepted the payload (202) — possibly after also flushing spool.
    Delivered,
    /// Delivery is temporarily unavailable or authentication is blocked; the
    /// payload was durably spooled for later retry.
    Spooled,
}

/// Whether a guard batch reached the durable outbox or needs immediate live upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardSpoolOutcome {
    /// The batch is durable; the background worker may upload it asynchronously.
    Spooled,
    /// No safe spool exists on this platform/path; upload synchronously now.
    LiveRequired,
}

/// Result of one bounded live-upload cycle for an in-memory guard batch.
pub(crate) enum GuardLiveOutcome {
    /// Form accepted the batch.
    Delivered,
    /// A retryable outage exhausted this cycle; retain the batch in memory.
    Transient(anyhow::Error),
    /// Form rejected the batch permanently (for example 422); do not retry.
    Permanent(anyhow::Error),
}

/// Upload a host asset report to Form's `/ingest/asset-report` endpoint.
pub fn upload_report(report: &AssetReport, base_url: &str) -> anyhow::Result<UploadOutcome> {
    let chunks = split_asset_report(report)?;
    upload_chunks(&chunks, base_url, "/ingest/asset-report")
}

/// Upload a network trace batch to Form's `/ingest/trace-batch` endpoint.
pub fn upload_batch(batch: &TraceBatch, base_url: &str) -> anyhow::Result<UploadOutcome> {
    let chunks = split_trace_batch(batch)?;
    upload_chunks(&chunks, base_url, "/ingest/trace-batch")
}

/// POST every schema/body-bounded child and merge their durable-delivery state.
/// Chunking completes before the first POST, so an unrepresentable single item
/// cannot leave a partially-delivered logical report.
fn upload_chunks<T: Serialize>(
    chunks: &[T],
    base_url: &str,
    path: &str,
) -> anyhow::Result<UploadOutcome> {
    let mut merged = UploadOutcome::Delivered;
    for chunk in chunks {
        if post_json(chunk, base_url, path)? == UploadOutcome::Spooled {
            merged = UploadOutcome::Spooled;
        }
    }
    Ok(merged)
}

fn serialized_len<T: Serialize>(value: &T, context: &str) -> anyhow::Result<usize> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| anyhow::anyhow!("serialize {context} for ingest sizing: {error}"))
}

fn child_correlation_id(parent: &str, kind: &str, index: usize) -> String {
    bounded_correlation_id(&format!("{parent}~{kind}-part-{index}"))
}

fn added_array_item_bytes(existing_items: usize, item_bytes: usize) -> anyhow::Result<usize> {
    item_bytes
        .checked_add(usize::from(existing_items != 0))
        .ok_or_else(|| anyhow::anyhow!("ingest JSON size overflow"))
}

fn fits_body(current_bytes: usize, added_bytes: usize) -> bool {
    current_bytes
        .checked_add(added_bytes)
        .is_some_and(|bytes| bytes <= MAX_INGEST_BODY_BYTES)
}

fn empty_asset_child(report: &AssetReport, index: usize) -> AssetReport {
    AssetReport {
        report_id: child_correlation_id(&report.report_id, "report", index),
        collected_at: report.collected_at,
        scanner_version: report.scanner_version.clone(),
        source_agent_id: report.source_agent_id.clone(),
        source_target_id: report.source_target_id.clone(),
        host: report.host.clone(),
        assets: Vec::new(),
        vulnerabilities: Vec::new(),
    }
}

fn asset_child_has_items(report: &AssetReport) -> bool {
    !report.assets.is_empty() || !report.vulnerabilities.is_empty()
}

fn start_asset_child(report: &AssetReport, index: usize) -> anyhow::Result<(AssetReport, usize)> {
    let child = empty_asset_child(report, index);
    let bytes = serialized_len(&child, "empty asset-report child")?;
    if bytes > MAX_INGEST_BODY_BYTES {
        anyhow::bail!(
            "asset report {} metadata alone serializes to {bytes} bytes, exceeding the {}-byte ingest body limit",
            report.report_id,
            MAX_INGEST_BODY_BYTES
        );
    }
    Ok((child, bytes))
}

/// Split both independent AssetReport streams without dropping or truncating
/// entries. Ordering is preserved within `assets` and within `vulnerabilities`.
fn split_asset_report(report: &AssetReport) -> anyhow::Result<Vec<AssetReport>> {
    let mut normalized = report.clone();
    normalized.normalize_wire_fields()?;
    let report = &normalized;
    let original_bytes = serialized_len(report, "asset report")?;
    if report.assets.len() <= MAX_SCHEMA_ITEMS
        && report.vulnerabilities.len() <= MAX_SCHEMA_ITEMS
        && original_bytes <= MAX_INGEST_BODY_BYTES
    {
        return Ok(vec![report.clone()]);
    }

    let mut chunks = Vec::new();
    let (mut current, mut current_bytes) = start_asset_child(report, 0)?;

    for asset in &report.assets {
        let item_bytes = serialized_len(asset, "asset item")?;
        loop {
            let added_bytes = added_array_item_bytes(current.assets.len(), item_bytes)?;
            if current.assets.len() < MAX_SCHEMA_ITEMS && fits_body(current_bytes, added_bytes) {
                current.assets.push(asset.clone());
                current_bytes += added_bytes;
                break;
            }
            if !asset_child_has_items(&current) {
                anyhow::bail!(
                    "asset report {} contains one asset item that cannot fit in the {}-byte ingest body limit (serialized item: {item_bytes} bytes)",
                    report.report_id,
                    MAX_INGEST_BODY_BYTES
                );
            }
            let next_index = chunks.len() + 1;
            let (next, next_bytes) = start_asset_child(report, next_index)?;
            chunks.push(std::mem::replace(&mut current, next));
            current_bytes = next_bytes;
        }
    }

    for vulnerability in &report.vulnerabilities {
        let item_bytes = serialized_len(vulnerability, "vulnerability item")?;
        loop {
            let added_bytes = added_array_item_bytes(current.vulnerabilities.len(), item_bytes)?;
            if current.vulnerabilities.len() < MAX_SCHEMA_ITEMS
                && fits_body(current_bytes, added_bytes)
            {
                current.vulnerabilities.push(vulnerability.clone());
                current_bytes += added_bytes;
                break;
            }
            if !asset_child_has_items(&current) {
                anyhow::bail!(
                    "asset report {} contains one vulnerability item that cannot fit in the {}-byte ingest body limit (serialized item: {item_bytes} bytes)",
                    report.report_id,
                    MAX_INGEST_BODY_BYTES
                );
            }
            let next_index = chunks.len() + 1;
            let (next, next_bytes) = start_asset_child(report, next_index)?;
            chunks.push(std::mem::replace(&mut current, next));
            current_bytes = next_bytes;
        }
    }

    chunks.push(current);
    finalize_asset_chunks(report, chunks)
}

fn finalize_asset_chunks(
    source: &AssetReport,
    mut chunks: Vec<AssetReport>,
) -> anyhow::Result<Vec<AssetReport>> {
    if chunks.len() == 1 {
        chunks[0].report_id.clone_from(&source.report_id);
    }
    let mut ids = std::collections::HashSet::with_capacity(chunks.len());
    for chunk in &chunks {
        if chunk.assets.len() > MAX_SCHEMA_ITEMS || chunk.vulnerabilities.len() > MAX_SCHEMA_ITEMS {
            anyhow::bail!(
                "asset-report child {} exceeds the {MAX_SCHEMA_ITEMS}-item schema limit",
                chunk.report_id
            );
        }
        ensure_bounded_id(&chunk.report_id, "asset-report child report_id")?;
        ensure_bounded_id(&chunk.scanner_version, "asset-report scanner_version")?;
        ensure_bounded_id(&chunk.host.host_id, "asset-report host_id")?;
        for vulnerability in &chunk.vulnerabilities {
            ensure_bounded_id(&vulnerability.vuln_id, "vulnerability vuln_id")?;
            ensure_bounded_id(&vulnerability.source, "vulnerability source")?;
        }
        let bytes = serialized_len(chunk, "asset-report child")?;
        if bytes > MAX_INGEST_BODY_BYTES {
            anyhow::bail!(
                "asset-report child {} serializes to {bytes} bytes, exceeding the {}-byte ingest body limit",
                chunk.report_id,
                MAX_INGEST_BODY_BYTES
            );
        }
        if chunks.len() > 1 && !ids.insert(&chunk.report_id) {
            anyhow::bail!("duplicate asset-report child id: {}", chunk.report_id);
        }
    }
    Ok(chunks)
}

trait ThreatChunkEvent: Clone + Serialize {
    fn trace_id(&self) -> &str;
    fn set_trace_id(&mut self, trace_id: String);
    fn threat_intel(&self) -> &[ThreatMatch];
    fn threat_intel_mut(&mut self) -> &mut Vec<ThreatMatch>;
}

macro_rules! impl_threat_chunk_event {
    ($event:ty) => {
        impl ThreatChunkEvent for $event {
            fn trace_id(&self) -> &str {
                &self.trace_id
            }

            fn set_trace_id(&mut self, trace_id: String) {
                self.trace_id = trace_id;
            }

            fn threat_intel(&self) -> &[ThreatMatch] {
                &self.threat_intel
            }

            fn threat_intel_mut(&mut self) -> &mut Vec<ThreatMatch> {
                &mut self.threat_intel
            }
        }
    };
}

impl_threat_chunk_event!(TraceEvent);
impl_threat_chunk_event!(FileTraceEvent);
impl_threat_chunk_event!(ProcessTraceEvent);

fn split_event_threat_intel<T: ThreatChunkEvent>(events: &[T], stream: &str) -> Vec<T> {
    let extra = events
        .iter()
        .map(|event| event.threat_intel().len().div_ceil(MAX_THREAT_INTEL_ITEMS))
        .sum::<usize>()
        .saturating_sub(events.len());
    let mut split = Vec::with_capacity(events.len().saturating_add(extra));

    for (event_index, event) in events.iter().enumerate() {
        if event.threat_intel().len() <= MAX_THREAT_INTEL_ITEMS {
            split.push(event.clone());
            continue;
        }

        let original_trace_id = event.trace_id().to_owned();
        let mut base = event.clone();
        base.threat_intel_mut().clear();
        for (intel_index, intel) in event
            .threat_intel()
            .chunks(MAX_THREAT_INTEL_ITEMS)
            .enumerate()
        {
            let mut child = base.clone();
            child.set_trace_id(bounded_correlation_id(&format!(
                "{original_trace_id}~{stream}-{event_index}-intel-part-{intel_index}"
            )));
            child.threat_intel_mut().extend_from_slice(intel);
            split.push(child);
        }
    }
    split
}

fn empty_trace_child(batch: &TraceBatch, index: usize) -> TraceBatch {
    TraceBatch {
        batch_id: child_correlation_id(&batch.batch_id, "batch", index),
        collected_at: batch.collected_at,
        collector_id: batch.collector_id.clone(),
        collector_version: batch.collector_version.clone(),
        source_agent_id: batch.source_agent_id.clone(),
        source_target_id: batch.source_target_id.clone(),
        events: Vec::new(),
        file_events: Vec::new(),
        process_events: Vec::new(),
    }
}

fn trace_child_has_items(batch: &TraceBatch) -> bool {
    !batch.events.is_empty() || !batch.file_events.is_empty() || !batch.process_events.is_empty()
}

fn start_trace_child(batch: &TraceBatch, index: usize) -> anyhow::Result<(TraceBatch, usize)> {
    let child = empty_trace_child(batch, index);
    let bytes = serialized_len(&child, "empty trace-batch child")?;
    if bytes > MAX_INGEST_BODY_BYTES {
        anyhow::bail!(
            "trace batch {} metadata alone serializes to {bytes} bytes, exceeding the {}-byte ingest body limit",
            batch.batch_id,
            MAX_INGEST_BODY_BYTES
        );
    }
    Ok((child, bytes))
}

struct TracePacker<'a> {
    source: &'a TraceBatch,
    chunks: Vec<TraceBatch>,
    current: TraceBatch,
    current_bytes: usize,
}

impl<'a> TracePacker<'a> {
    fn new(source: &'a TraceBatch) -> anyhow::Result<Self> {
        let (current, current_bytes) = start_trace_child(source, 0)?;
        Ok(Self {
            source,
            chunks: Vec::new(),
            current,
            current_bytes,
        })
    }

    fn push_item<T: Clone + Serialize>(
        &mut self,
        item: &T,
        stream: &str,
        stream_len: fn(&TraceBatch) -> usize,
        push: fn(&mut TraceBatch, T),
    ) -> anyhow::Result<()> {
        let item_bytes = serialized_len(item, &format!("{stream} item"))?;
        loop {
            let count = stream_len(&self.current);
            let added_bytes = added_array_item_bytes(count, item_bytes)?;
            if count < MAX_SCHEMA_ITEMS && fits_body(self.current_bytes, added_bytes) {
                push(&mut self.current, item.clone());
                self.current_bytes += added_bytes;
                return Ok(());
            }
            if !trace_child_has_items(&self.current) {
                anyhow::bail!(
                    "trace batch {} contains one {stream} item that cannot fit in the {}-byte ingest body limit (serialized item: {item_bytes} bytes)",
                    self.source.batch_id,
                    MAX_INGEST_BODY_BYTES
                );
            }
            let next_index = self.chunks.len() + 1;
            let (next, next_bytes) = start_trace_child(self.source, next_index)?;
            self.chunks.push(std::mem::replace(&mut self.current, next));
            self.current_bytes = next_bytes;
        }
    }

    fn finish(mut self) -> anyhow::Result<Vec<TraceBatch>> {
        self.chunks.push(self.current);
        finalize_trace_chunks(self.source, self.chunks)
    }
}

/// Normalize per-event IOC lists, then split all three independent TraceBatch
/// streams while preserving their order and every original IOC match.
fn split_trace_batch(batch: &TraceBatch) -> anyhow::Result<Vec<TraceBatch>> {
    let mut bounded = batch.clone();
    bounded.normalize_wire_fields()?;
    let normalized = TraceBatch {
        batch_id: bounded.batch_id.clone(),
        collected_at: bounded.collected_at,
        collector_id: bounded.collector_id.clone(),
        collector_version: bounded.collector_version.clone(),
        source_agent_id: bounded.source_agent_id.clone(),
        source_target_id: bounded.source_target_id.clone(),
        events: split_event_threat_intel(&bounded.events, "network"),
        file_events: split_event_threat_intel(&bounded.file_events, "file"),
        process_events: split_event_threat_intel(&bounded.process_events, "process"),
    };

    let normalized_bytes = serialized_len(&normalized, "trace batch")?;
    if normalized.events.len() <= MAX_SCHEMA_ITEMS
        && normalized.file_events.len() <= MAX_SCHEMA_ITEMS
        && normalized.process_events.len() <= MAX_SCHEMA_ITEMS
        && normalized_bytes <= MAX_INGEST_BODY_BYTES
    {
        return Ok(vec![normalized]);
    }

    let mut packer = TracePacker::new(&normalized)?;
    for event in &normalized.events {
        packer.push_item(
            event,
            "network trace",
            |batch| batch.events.len(),
            |batch, event| batch.events.push(event),
        )?;
    }
    for event in &normalized.file_events {
        packer.push_item(
            event,
            "file trace",
            |batch| batch.file_events.len(),
            |batch, event| batch.file_events.push(event),
        )?;
    }
    for event in &normalized.process_events {
        packer.push_item(
            event,
            "process trace",
            |batch| batch.process_events.len(),
            |batch, event| batch.process_events.push(event),
        )?;
    }
    packer.finish()
}

fn finalize_trace_chunks(
    source: &TraceBatch,
    mut chunks: Vec<TraceBatch>,
) -> anyhow::Result<Vec<TraceBatch>> {
    if chunks.len() == 1 {
        chunks[0].batch_id.clone_from(&source.batch_id);
    }
    let mut ids = std::collections::HashSet::with_capacity(chunks.len());
    for chunk in &chunks {
        if chunk.events.len() > MAX_SCHEMA_ITEMS
            || chunk.file_events.len() > MAX_SCHEMA_ITEMS
            || chunk.process_events.len() > MAX_SCHEMA_ITEMS
        {
            anyhow::bail!(
                "trace-batch child {} exceeds the {MAX_SCHEMA_ITEMS}-item per-stream schema limit",
                chunk.batch_id
            );
        }
        ensure_bounded_id(&chunk.batch_id, "trace-batch child batch_id")?;
        ensure_bounded_id(&chunk.collector_id, "trace-batch collector_id")?;
        ensure_bounded_id(&chunk.collector_version, "trace-batch collector_version")?;
        validate_trace_stream(&chunk.events, "network trace")?;
        validate_trace_stream(&chunk.file_events, "file trace")?;
        validate_trace_stream(&chunk.process_events, "process trace")?;
        chunk.validate_nested_wire_bounds()?;
        let bytes = serialized_len(chunk, "trace-batch child")?;
        if bytes > MAX_INGEST_BODY_BYTES {
            anyhow::bail!(
                "trace-batch child {} serializes to {bytes} bytes, exceeding the {}-byte ingest body limit",
                chunk.batch_id,
                MAX_INGEST_BODY_BYTES
            );
        }
        if chunks.len() > 1 && !ids.insert(&chunk.batch_id) {
            anyhow::bail!("duplicate trace-batch child id: {}", chunk.batch_id);
        }
    }
    Ok(chunks)
}

fn ensure_bounded_id(value: &str, field: &str) -> anyhow::Result<()> {
    if value.chars().count() > CORRELATION_IDENTIFIER_MAX_CHARS {
        anyhow::bail!(
            "{field} exceeds the {CORRELATION_IDENTIFIER_MAX_CHARS}-character correlation-id limit"
        );
    }
    Ok(())
}

fn validate_trace_stream<T: ThreatChunkEvent>(events: &[T], stream: &str) -> anyhow::Result<()> {
    for event in events {
        ensure_bounded_id(event.trace_id(), &format!("{stream} trace_id"))?;
        if event.threat_intel().len() > MAX_THREAT_INTEL_ITEMS {
            anyhow::bail!(
                "{stream} {} exceeds the {MAX_THREAT_INTEL_ITEMS}-item threat_intel schema limit",
                event.trace_id()
            );
        }
        for threat in event.threat_intel() {
            ensure_bounded_id(&threat.indicator, "threat indicator")?;
            ensure_bounded_id(&threat.category, "threat category")?;
            ensure_bounded_id(&threat.source, "threat source")?;
        }
    }
    Ok(())
}

/// Persist a guard batch directly to the durable upload spool.
///
/// The asynchronous guard uploader uses the spool as a durable FIFO outbox:
/// report emission commits here first, and a background worker later drains the
/// route to Form. A crash or shutdown therefore leaves accepted batches for
/// replay by the next process.
pub(crate) fn spool_guard_batch(batch: &GuardEventBatch) -> anyhow::Result<GuardSpoolOutcome> {
    let Some(spool) = Spool::from_env() else {
        return Ok(GuardSpoolOutcome::LiveRequired);
    };
    let value = serde_json::to_value(batch)
        .map_err(|e| anyhow::anyhow!("serialize guard batch for spool: {e}"))?;
    match spool.enqueue("/ingest/guard-event", &value) {
        Ok(()) => Ok(GuardSpoolOutcome::Spooled),
        Err(error) => {
            eprintln!(
                "agentd: durable guard spool rejected batch {} ({error}); falling back to bounded live upload",
                batch.batch_id
            );
            Ok(GuardSpoolOutcome::LiveRequired)
        }
    }
}

/// Upload one guard batch directly with the same timeout, bearer token, and
/// bounded retry policy as host/trace uploads. This deliberately does not try
/// to spool again: it is the fail-closed fallback for platforms where a private
/// on-disk spool cannot be proven safe.
/// Shutdown-aware variant used by the background guard worker. It checks
/// `keep_going` between attempts/backoff sleeps; only an already in-flight HTTP
/// request can delay shutdown, and that request has `FORM_UPLOAD_TIMEOUT`.
pub(crate) fn upload_guard_batch_live_while(
    batch: &GuardEventBatch,
    base_url: &str,
    keep_going: impl FnMut() -> bool,
) -> GuardLiveOutcome {
    let value = match serde_json::to_value(batch) {
        Ok(value) => value,
        Err(error) => {
            return GuardLiveOutcome::Permanent(anyhow::anyhow!(
                "serialize guard batch for live upload: {error}"
            ));
        }
    };
    let client = match shared_client(base_url) {
        Ok(client) => client,
        Err(error) => return GuardLiveOutcome::Transient(error),
    };
    warn_if_plaintext_token(base_url);
    match post_with_retries_while(&client, base_url, "/ingest/guard-event", &value, keep_going) {
        PostOutcome::Accepted => GuardLiveOutcome::Delivered,
        PostOutcome::Transient(error) => GuardLiveOutcome::Transient(error),
        PostOutcome::AuthBlocked(error) => GuardLiveOutcome::Transient(error),
        PostOutcome::Permanent(error) => GuardLiveOutcome::Permanent(error),
    }
}

/// One final, non-retrying live attempt used during graceful shutdown. The
/// request is still bounded by `FORM_UPLOAD_TIMEOUT`; limiting shutdown to one
/// item avoids multiplying that timeout by the whole in-memory queue.
pub(crate) fn upload_guard_batch_live_once(
    batch: &GuardEventBatch,
    base_url: &str,
) -> GuardLiveOutcome {
    let value = match serde_json::to_value(batch) {
        Ok(value) => value,
        Err(error) => {
            return GuardLiveOutcome::Permanent(anyhow::anyhow!(
                "serialize guard batch for final live upload: {error}"
            ));
        }
    };
    let client = match shared_client(base_url) {
        Ok(client) => client,
        Err(error) => return GuardLiveOutcome::Transient(error),
    };
    warn_if_plaintext_token(base_url);
    match try_post(
        &client,
        &ingest_url(base_url, "/ingest/guard-event"),
        &value,
    ) {
        PostOutcome::Accepted => GuardLiveOutcome::Delivered,
        PostOutcome::Transient(error) => GuardLiveOutcome::Transient(error),
        PostOutcome::AuthBlocked(error) => GuardLiveOutcome::Transient(error),
        PostOutcome::Permanent(error) => GuardLiveOutcome::Permanent(error),
    }
}

/// Resolve the request timeout, overridable via `FORM_UPLOAD_TIMEOUT` (seconds).
fn upload_timeout() -> Duration {
    let secs = std::env::var("FORM_UPLOAD_TIMEOUT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileGeneration {
    path: PathBuf,
    len: u64,
    modified: Option<Duration>,
    file_id: Option<(u64, u64)>,
    content_fingerprint: u64,
}

struct LoadedTlsFile {
    bytes: Vec<u8>,
    generation: FileGeneration,
}

struct TlsMaterial {
    cert: LoadedTlsFile,
    key: LoadedTlsFile,
    ca: LoadedTlsFile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TlsGeneration {
    cert: FileGeneration,
    key: FileGeneration,
    ca: FileGeneration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClientGeneration {
    timeout: Duration,
    tls: Option<TlsGeneration>,
}

struct ClientSettings {
    timeout: Duration,
    tls: Option<TlsMaterial>,
    generation: ClientGeneration,
}

impl ClientSettings {
    /// Snapshot the three TLS files for one upload cycle. Reading their content
    /// here, instead of only remembering paths, makes an atomic certificate
    /// replacement observable without restarting a resident Guard process.
    fn from_env() -> anyhow::Result<Self> {
        let cert_path = nonempty_env_path("FORM_AGENT_CERT");
        let key_path = nonempty_env_path("FORM_AGENT_KEY");
        let ca_path = nonempty_env_path("FORM_AGENT_CA");
        let tls = match (cert_path, key_path, ca_path) {
            (None, None, None) => None,
            (Some(cert_path), Some(key_path), Some(ca_path)) => {
                Some(read_stable_tls_material(&cert_path, &key_path, &ca_path)?)
            }
            _ => {
                anyhow::bail!(
                    "FORM_AGENT_CERT, FORM_AGENT_KEY, and FORM_AGENT_CA must be configured together"
                )
            }
        };
        let timeout = upload_timeout();
        let generation = ClientGeneration {
            timeout,
            tls: tls.as_ref().map(TlsMaterial::generation),
        };
        Ok(Self {
            timeout,
            tls,
            generation,
        })
    }

    fn validate_base_url(&self, base_url: &str) -> anyhow::Result<()> {
        if self.tls.is_none() {
            return Ok(());
        }
        validate_mtls_base_url(base_url)
    }
}

impl TlsMaterial {
    fn generation(&self) -> TlsGeneration {
        TlsGeneration {
            cert: self.cert.generation.clone(),
            key: self.key.generation.clone(),
            ca: self.ca.generation.clone(),
        }
    }
}

fn validate_mtls_base_url(base_url: &str) -> anyhow::Result<()> {
    let origin = base_url.trim();
    let url = reqwest::Url::parse(origin)
        .map_err(|error| anyhow::anyhow!("invalid Form upload URL {base_url:?}: {error}"))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        anyhow::bail!("per-Agent TLS identity requires an absolute https:// Form upload URL");
    }

    // Inspect the original text as well as `Url`: WHATWG parsing normalizes
    // dot-segments and backslashes, while this value must be a literal origin
    // before trusted ingest paths are appended.
    let Some(authority_start) = origin.find("://").map(|index| index + 3) else {
        anyhow::bail!("per-Agent TLS identity requires a pure https:// Form origin");
    };
    let remainder = &origin[authority_start..];
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let suffix = &remainder[authority_end..];
    let path_end = suffix.find(['?', '#']).unwrap_or(suffix.len());
    let literal_path = &suffix[..path_end];

    if authority.contains('@') || !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("per-Agent TLS Form upload origin must not contain userinfo");
    }
    if authority.ends_with(':') {
        anyhow::bail!("per-Agent TLS Form upload origin must not contain an empty port");
    }
    if !matches!(literal_path, "" | "/") {
        anyhow::bail!(
            "per-Agent TLS Form upload URL must be a pure origin with an empty or '/' path"
        );
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("per-Agent TLS Form upload origin must not contain a query or fragment");
    }
    if origin.contains('\\') {
        anyhow::bail!("per-Agent TLS Form upload origin must not contain backslashes");
    }
    Ok(())
}

fn nonempty_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn read_stable_tls_material(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> anyhow::Result<TlsMaterial> {
    // The three configured paths normally live below one atomically-switched
    // `current` symlink. The switch is atomic, but three independent opens are
    // not: a rotation between them could otherwise combine an old certificate
    // with a new key. Confirm the complete tuple with a second snapshot and
    // retry once before rejecting the upload cycle.
    // In the deployed layout all three paths share the `current` parent. Resolve
    // that parent once so one upload cycle opens every file from exactly one
    // generation even if the symlink is switched immediately afterwards.
    let (cert_path, key_path, ca_path) = resolved_tls_snapshot_paths(cert_path, key_path, ca_path)?;
    let mut last_error = None;
    for _ in 0..2 {
        let material = match read_tls_material_once(&cert_path, &key_path, &ca_path) {
            Ok(material) => material,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let confirmed = match read_tls_material_once(&cert_path, &key_path, &ca_path) {
            Ok(material) => material,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        if material.generation() == confirmed.generation() {
            return Ok(material);
        }
        last_error = Some(anyhow::anyhow!(
            "TLS identity generation changed between complete snapshots"
        ));
    }
    Err(last_error.unwrap_or_else(|| {
        anyhow::anyhow!(
            "FORM_AGENT_CERT, FORM_AGENT_KEY, or FORM_AGENT_CA changed while the TLS identity was being snapshotted; retry the upload cycle"
        )
    }))
}

fn resolved_tls_snapshot_paths(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
    let cert_parent = cert_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("FORM_AGENT_CERT has no parent directory"))?;
    let key_parent = key_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("FORM_AGENT_KEY has no parent directory"))?;
    let ca_parent = ca_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("FORM_AGENT_CA has no parent directory"))?;
    let resolved_cert_parent = fs::canonicalize(cert_parent).map_err(|error| {
        anyhow::anyhow!(
            "resolve FORM_AGENT_CERT parent {}: {error}",
            cert_parent.display()
        )
    })?;
    let resolved_key_parent = fs::canonicalize(key_parent).map_err(|error| {
        anyhow::anyhow!(
            "resolve FORM_AGENT_KEY parent {}: {error}",
            key_parent.display()
        )
    })?;
    let resolved_ca_parent = fs::canonicalize(ca_parent).map_err(|error| {
        anyhow::anyhow!(
            "resolve FORM_AGENT_CA parent {}: {error}",
            ca_parent.display()
        )
    })?;
    if resolved_cert_parent == resolved_key_parent && resolved_key_parent == resolved_ca_parent {
        let file_name = |path: &Path, variable: &str| {
            path.file_name()
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("{variable} has no file name"))
        };
        return Ok((
            resolved_cert_parent.join(file_name(cert_path, "FORM_AGENT_CERT")?),
            resolved_key_parent.join(file_name(key_path, "FORM_AGENT_KEY")?),
            resolved_ca_parent.join(file_name(ca_path, "FORM_AGENT_CA")?),
        ));
    }
    // Custom layouts may keep the files in separate directories. The two full
    // snapshots below still detect a rename/change between independent opens.
    Ok((
        cert_path.to_path_buf(),
        key_path.to_path_buf(),
        ca_path.to_path_buf(),
    ))
}

fn read_tls_material_once(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> anyhow::Result<TlsMaterial> {
    Ok(TlsMaterial {
        cert: read_stable_tls_file(cert_path, "FORM_AGENT_CERT")?,
        key: read_stable_tls_file(key_path, "FORM_AGENT_KEY")?,
        ca: read_stable_tls_file(ca_path, "FORM_AGENT_CA")?,
    })
}

fn read_stable_tls_file(path: &Path, variable: &str) -> anyhow::Result<LoadedTlsFile> {
    // A certificate manager normally publishes with rename. Retry once if a
    // generation changes while it is being read, and never cache a torn read.
    for _ in 0..2 {
        let before = fs::metadata(path).map_err(|error| {
            anyhow::anyhow!("read {variable} metadata at {}: {error}", path.display())
        })?;
        if !before.is_file() {
            anyhow::bail!("{variable} path {} is not a regular file", path.display());
        }
        if before.len() > MAX_TLS_FILE_BYTES {
            anyhow::bail!(
                "{variable} file {} exceeds the {MAX_TLS_FILE_BYTES}-byte limit",
                path.display()
            );
        }
        let bytes = fs::read(path)
            .map_err(|error| anyhow::anyhow!("read {variable} at {}: {error}", path.display()))?;
        let after = fs::metadata(path).map_err(|error| {
            anyhow::anyhow!("re-read {variable} metadata at {}: {error}", path.display())
        })?;
        if same_file_generation(&before, &after) && after.len() == bytes.len() as u64 {
            if bytes.is_empty() {
                anyhow::bail!("{variable} file {} is empty", path.display());
            }
            return Ok(LoadedTlsFile {
                generation: FileGeneration {
                    path: path.to_path_buf(),
                    len: after.len(),
                    modified: modified_stamp(&after),
                    file_id: metadata_file_id(&after),
                    content_fingerprint: content_fingerprint(&bytes),
                },
                bytes,
            });
        }
    }
    anyhow::bail!(
        "{variable} file {} changed while it was being read; retry the upload cycle",
        path.display()
    )
}

fn same_file_generation(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && modified_stamp(left) == modified_stamp(right)
        && metadata_file_id(left) == metadata_file_id(right)
}

fn modified_stamp(metadata: &fs::Metadata) -> Option<Duration> {
    metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()
}

#[cfg(unix)]
fn metadata_file_id(metadata: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn metadata_file_id(_metadata: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

fn content_fingerprint(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn nonempty_env_token(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

fn select_bearer_token(
    agent_token: Option<String>,
    legacy_token: Option<String>,
) -> Option<String> {
    agent_token.or(legacy_token)
}

/// Read the Agent-scoped bearer token, preferring `FORM_AGENT_TOKEN`. The old
/// fleet-wide `FORM_INGEST_TOKEN` remains a compatibility fallback. Empty or
/// whitespace-only values are treated as unset.
fn bearer_token() -> Option<String> {
    select_bearer_token(
        nonempty_env_token("FORM_AGENT_TOKEN"),
        nonempty_env_token("FORM_INGEST_TOKEN"),
    )
}

/// Total upload attempts, overridable via `FORM_UPLOAD_RETRIES` (number of
/// *retries*; total attempts = retries + 1). Clamped to at least one attempt.
fn upload_attempts() -> u32 {
    std::env::var("FORM_UPLOAD_RETRIES")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|retries| retries.saturating_add(1))
        .unwrap_or(DEFAULT_ATTEMPTS)
        .max(1)
}

/// POST a serializable payload to `<base_url><path>`, attaching the preferred
/// Agent bearer when set and treating `202 Accepted` as success.
///
/// Order of operations:
///   1. **Flush the spool first** — replay any envelopes a prior cycle left
///      queued during an outage, oldest-first, so delivery order is preserved
///      and the backlog drains as Form recovers.
///   2. **Deliver this payload**, retrying transient failures (network errors,
///      timeouts, 408, 429, 5xx) with jittered exponential backoff.
///   3. On transient exhaustion or an authentication block, **spool** the
///      payload durably instead of dropping it (returns
///      [`UploadOutcome::Spooled`]). Permanent contract failures still fail
///      fast because replaying the same invalid JSON cannot repair them.
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
    let spool = Spool::from_env();
    let client = match shared_client(base_url) {
        Ok(client) => client,
        Err(error) => {
            return spool_retryable_upload(
                spool.as_ref(),
                path,
                &value,
                error,
                "upload client unavailable",
            );
        }
    };
    warn_if_plaintext_token(base_url);

    // 1. Best-effort flush of any previously-spooled backlog.
    if let Some(spool) = spool.as_ref() {
        drain_spool(spool, &client, base_url);
    }

    // 2. Deliver this payload.
    match post_with_retries(&client, base_url, path, &value) {
        PostOutcome::Accepted => Ok(UploadOutcome::Delivered),
        // Invalid data cannot be repaired by credentials or a later retry.
        PostOutcome::Permanent(e) => Err(e),
        // A token/certificate may be rotated by the operator. Keep the payload
        // durable so the current credential generation never destroys it.
        PostOutcome::AuthBlocked(e) => {
            spool_retryable_upload(spool.as_ref(), path, &value, e, "authentication blocked")
        }
        // 3. Form unreachable after every retry: queue durably rather than drop.
        PostOutcome::Transient(e) => {
            spool_retryable_upload(spool.as_ref(), path, &value, e, "form unreachable")
        }
    }
}

fn spool_retryable_upload(
    spool: Option<&Spool>,
    path: &str,
    value: &serde_json::Value,
    error: anyhow::Error,
    reason: &str,
) -> anyhow::Result<UploadOutcome> {
    let Some(spool) = spool else {
        return Err(error);
    };
    spool.enqueue(path, value).map_err(|spool_error| {
        anyhow::anyhow!("upload failed ({error}); spooling also failed ({spool_error})")
    })?;
    eprintln!(
        "agentd: {reason}; spooled upload to {path} for later delivery ({error}); spool depth now {}",
        spool.len()
    );
    Ok(UploadOutcome::Spooled)
}

/// Build a blocking HTTP client for one immutable credential generation.
fn build_client(settings: &ClientSettings) -> anyhow::Result<reqwest::blocking::Client> {
    // Ingest POST bodies and credentials must never be replayed to a redirect
    // target. This is safe for legacy bearer mode too and makes the transport
    // invariant independent of which authentication mode is active.
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(settings.timeout)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(tls) = settings.tls.as_ref() {
        // reqwest's rustls backend accepts a combined PEM identity. Keep the
        // files separate at rest, combine only this in-memory snapshot, and let
        // rustls validate that the certificate and private key form one identity.
        let mut identity_pem = Vec::with_capacity(tls.cert.bytes.len() + tls.key.bytes.len() + 1);
        identity_pem.extend_from_slice(&tls.cert.bytes);
        identity_pem.push(b'\n');
        identity_pem.extend_from_slice(&tls.key.bytes);
        let identity = reqwest::Identity::from_pem(&identity_pem).map_err(|error| {
            anyhow::anyhow!(
                "parse FORM_AGENT_CERT and FORM_AGENT_KEY as a rustls client identity: {error}"
            )
        })?;
        let roots = reqwest::Certificate::from_pem_bundle(&tls.ca.bytes)
            .map_err(|error| anyhow::anyhow!("parse FORM_AGENT_CA PEM bundle: {error}"))?;
        if roots.is_empty() {
            anyhow::bail!("FORM_AGENT_CA contains no certificates");
        }
        builder = builder
            .identity(identity)
            .https_only(true)
            // Identity mode trusts only the explicitly provisioned Form CA.
            .tls_built_in_root_certs(false);
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
    }
    builder
        .build()
        .map_err(|e| anyhow::anyhow!("build HTTP client: {e}"))
}

struct CachedClient {
    generation: ClientGeneration,
    client: reqwest::blocking::Client,
}

#[derive(Default)]
struct ClientCache {
    current: Option<CachedClient>,
}

impl ClientCache {
    fn client_for(
        &mut self,
        settings: &ClientSettings,
    ) -> anyhow::Result<reqwest::blocking::Client> {
        if let Some(cached) = self
            .current
            .as_ref()
            .filter(|cached| cached.generation == settings.generation)
        {
            return Ok(cached.client.clone());
        }

        // Build before replacing the entry. A partial/torn rotation therefore
        // cannot poison the last known-good cached generation.
        let client = match build_client(settings) {
            Ok(client) => client,
            Err(error) if settings.tls.is_some() => return self.last_good_tls_client(error),
            Err(error) => return Err(error),
        };
        self.current = Some(CachedClient {
            generation: settings.generation.clone(),
            client: client.clone(),
        });
        Ok(client)
    }

    fn last_good_tls_client(
        &self,
        rotation_error: anyhow::Error,
    ) -> anyhow::Result<reqwest::blocking::Client> {
        let Some(cached) = self
            .current
            .as_ref()
            .filter(|cached| cached.generation.tls.is_some())
        else {
            return Err(rotation_error);
        };
        eprintln!(
            "agentd: TLS identity reload failed; retaining the last known-good client ({rotation_error})"
        );
        Ok(cached.client.clone())
    }
}

/// Reloadable process-wide client cache. TLS files are snapshotted on every
/// upload cycle; an unchanged generation reuses the connection pool, while a
/// successful certificate/key/CA replacement atomically publishes a new client.
fn shared_client(base_url: &str) -> anyhow::Result<reqwest::blocking::Client> {
    static CACHE: OnceLock<Mutex<ClientCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(ClientCache::default()));
    let settings = match ClientSettings::from_env() {
        Ok(settings) => settings,
        Err(error) => {
            // A malformed URL is never made acceptable by a cached credential.
            // Validate before falling back so a rotation race cannot weaken the
            // HTTPS transport invariant.
            validate_mtls_base_url(base_url)?;
            return cache
                .lock()
                .map_err(|_| anyhow::anyhow!("HTTP client cache lock poisoned"))?
                .last_good_tls_client(error);
        }
    };
    settings.validate_base_url(base_url)?;
    cache
        .lock()
        .map_err(|_| anyhow::anyhow!("HTTP client cache lock poisoned"))?
        .client_for(&settings)
}

/// Deliver one already-serialized payload to `<base_url><path>`, retrying
/// transient failures with jittered backoff. Returns the final [`PostOutcome`].
fn post_with_retries(
    client: &reqwest::blocking::Client,
    base_url: &str,
    path: &str,
    value: &serde_json::Value,
) -> PostOutcome {
    post_with_retries_while(client, base_url, path, value, || true)
}

fn post_with_retries_while(
    client: &reqwest::blocking::Client,
    base_url: &str,
    path: &str,
    value: &serde_json::Value,
    mut keep_going: impl FnMut() -> bool,
) -> PostOutcome {
    let url = ingest_url(base_url, path);
    let attempts = upload_attempts();
    let mut last_err = None;
    for attempt in 1..=attempts {
        if !keep_going() {
            return PostOutcome::Transient(anyhow::anyhow!(
                "upload to {url} cancelled during shutdown"
            ));
        }
        match try_post(client, &url, value) {
            PostOutcome::Accepted => return PostOutcome::Accepted,
            PostOutcome::AuthBlocked(e) => return PostOutcome::AuthBlocked(e),
            PostOutcome::Permanent(e) => return PostOutcome::Permanent(e),
            PostOutcome::Transient(e) => {
                last_err = Some(e);
                if attempt < attempts {
                    let backoff = jittered_backoff(attempt);
                    eprintln!(
                        "agentd: upload to {url} failed (attempt {attempt}/{attempts}), retrying in {backoff:?}"
                    );
                    if !sleep_while(backoff, &mut keep_going) {
                        return PostOutcome::Transient(anyhow::anyhow!(
                            "upload to {url} cancelled during shutdown"
                        ));
                    }
                }
            }
        }
    }
    PostOutcome::Transient(last_err.unwrap_or_else(|| anyhow::anyhow!("upload to {url} failed")))
}

fn sleep_while(duration: Duration, keep_going: &mut impl FnMut() -> bool) -> bool {
    const SLICE: Duration = Duration::from_millis(100);
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        if !keep_going() {
            return false;
        }
        std::thread::sleep(
            SLICE.min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
    keep_going()
}

/// Replay the spooled backlog through a single (no per-item retry) POST each,
/// reconstructing the URL against the *current* `base_url`. Returns how many were
/// delivered.
fn drain_spool(spool: &Spool, client: &reqwest::blocking::Client, base_url: &str) -> usize {
    drain_spool_while(spool, client, base_url, || true)
}

/// Drain while `keep_going` remains true. The predicate is checked immediately
/// before every POST, allowing the guard uploader to stop after at most its
/// currently in-flight request when shutdown is requested.
fn drain_spool_while(
    spool: &Spool,
    client: &reqwest::blocking::Client,
    base_url: &str,
    mut keep_going: impl FnMut() -> bool,
) -> usize {
    let delivered = spool.drain(|route, body| {
        if !keep_going() {
            return DrainStep::Transient;
        }
        let url = ingest_url(base_url, route);
        match try_post(client, &url, body) {
            PostOutcome::Accepted => DrainStep::Delivered,
            PostOutcome::AuthBlocked(error) => {
                warn_spool_auth_blocked(&url, &error);
                // DrainStep::Transient deliberately retains this item and stops
                // before the next one. A later token/cert generation can replay
                // the untouched backlog.
                DrainStep::Transient
            }
            PostOutcome::Permanent(error) => {
                eprintln!(
                    "agentd: permanent upload failure for spooled route {route}; moving item to dead-letter: {error}"
                );
                DrainStep::Permanent
            }
            PostOutcome::Transient(error) => {
                warn_spool_outage(&url, &error);
                DrainStep::Transient
            }
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

fn warn_spool_auth_blocked(url: &str, error: &anyhow::Error) {
    use std::sync::atomic::{AtomicU64, Ordering};

    const WARN_INTERVAL_SECS: u64 = 60;
    static LAST_WARN: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let last = LAST_WARN.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= WARN_INTERVAL_SECS
        && LAST_WARN
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        eprintln!(
            "agentd: Form authentication blocked for {url}; telemetry remains in durable spool until credentials rotate: {error}"
        );
    }
}

fn warn_spool_outage(url: &str, error: &anyhow::Error) {
    use std::sync::atomic::{AtomicU64, Ordering};

    const WARN_INTERVAL_SECS: u64 = 60;
    static LAST_WARN: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let last = LAST_WARN.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= WARN_INTERVAL_SECS
        && LAST_WARN
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        eprintln!(
            "agentd: form upload unavailable for {url}; telemetry remains in durable spool: {error}"
        );
    }
}

/// Best-effort shutdown flush capped to `max_items` POST attempts. Remaining
/// items stay durable for the next worker/startup instead of making process
/// termination proportional to the full backlog.
pub(crate) fn flush_spool_bounded(base_url: &str, max_items: usize) -> usize {
    if max_items == 0 {
        return 0;
    }
    let Some(spool) = Spool::from_env() else {
        return 0;
    };
    if spool.is_empty() {
        return 0;
    }
    let Ok(client) = shared_client(base_url) else {
        return 0;
    };
    let mut remaining = max_items;
    drain_spool_while(&spool, &client, base_url, || {
        if remaining == 0 {
            return false;
        }
        remaining -= 1;
        true
    })
}

/// Worker spool drain that stops between items once `shutdown`
/// is set. A blocking request already in progress is allowed to finish.
pub(crate) fn flush_spool_until_shutdown(
    base_url: &str,
    shutdown: &std::sync::atomic::AtomicBool,
) -> usize {
    use std::sync::atomic::Ordering;

    let Some(spool) = Spool::from_env() else {
        return 0;
    };
    if spool.is_empty() || shutdown.load(Ordering::Acquire) {
        return 0;
    }
    let Ok(client) = shared_client(base_url) else {
        return 0;
    };
    drain_spool_while(&spool, &client, base_url, || {
        !shutdown.load(Ordering::Acquire)
    })
}

/// Bounded exponential backoff (200ms, 400ms, … capped at 5s) with ±25% jitter,
/// so a fleet of agents retrying after one Form restart does not synchronise
/// into a thundering herd. Jitter is drawn from the clock — no rng dependency.
fn jittered_backoff(attempt: u32) -> Duration {
    // Clamp the shift so a large FORM_UPLOAD_RETRIES can't overflow it.
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
fn warn_if_plaintext_token(base_url: &str) {
    if bearer_token().is_some()
        && base_url
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
    {
        warn_plaintext_token_once();
    }
}

fn warn_plaintext_token_once() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "[agentd] warning: sending API bearer token over plaintext http:// — \
             the Form credential is exposed on the wire; use https://"
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
        // Connection refused / DNS / timeout — Form may just be (re)starting.
        Err(e) => return PostOutcome::Transient(anyhow::anyhow!("POST {url}: {e}")),
    };

    let status = response.status();
    if status == reqwest::StatusCode::ACCEPTED {
        return PostOutcome::Accepted;
    }

    let body = response
        .text()
        .unwrap_or_else(|_| String::from("<unreadable body>"));
    let err = anyhow::anyhow!("Form ingest failed ({status}): {body}");
    // Form's body-read deadline returns 408 on a slow link; replaying that
    // payload later is safe. Authentication failures are also recoverable after
    // token/certificate rotation, but malformed contract payloads are not.
    if is_auth_blocked_status(status) {
        PostOutcome::AuthBlocked(err)
    } else if is_transient_status(status) {
        PostOutcome::Transient(err)
    } else {
        PostOutcome::Permanent(err)
    }
}

fn is_auth_blocked_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    )
}

fn is_transient_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || matches!(
            status,
            reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::TOO_MANY_REQUESTS
        )
}

fn ingest_url(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim().trim_end_matches('/'), path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        io::{Read, Write},
        net::TcpListener,
        sync::atomic::{AtomicU64, Ordering},
        thread::JoinHandle,
    };

    const TEST_AGENT_CA: &[u8] = include_bytes!("../tests/fixtures/agent-ca.pem");
    const TEST_AGENT_CERT: &[u8] = include_bytes!("../tests/fixtures/agent-client.pem");
    const TEST_AGENT_KEY: &[u8] = include_bytes!("../tests/fixtures/agent-client-key.pem");
    const AGENT_ENV: &[&str] = &[
        "FORM_AGENT_CERT",
        "FORM_AGENT_KEY",
        "FORM_AGENT_CA",
        "FORM_AGENT_TOKEN",
        "FORM_INGEST_TOKEN",
        "FORM_UPLOAD_TIMEOUT",
        "FORM_UPLOAD_RETRIES",
        "FORM_SPOOL_DIR",
    ];
    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());
    static TEST_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let sequence = TEST_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "kcatta-agentd-ingest-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct EnvRestore(Vec<(&'static str, Option<OsString>)>);

    impl EnvRestore {
        fn clear(names: &[&'static str]) -> Self {
            let previous = names
                .iter()
                .map(|name| (*name, std::env::var_os(name)))
                .collect();
            for name in names {
                std::env::remove_var(name);
            }
            Self(previous)
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (name, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    fn plain_client_settings() -> ClientSettings {
        let timeout = Duration::from_secs(2);
        ClientSettings {
            timeout,
            tls: None,
            generation: ClientGeneration { timeout, tls: None },
        }
    }

    fn write_test_identity(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let cert = dir.join("client.pem");
        let key = dir.join("client-key.pem");
        let ca = dir.join("ca.pem");
        fs::write(&cert, TEST_AGENT_CERT).expect("write test client certificate");
        fs::write(&key, TEST_AGENT_KEY).expect("write test client key");
        fs::write(&ca, TEST_AGENT_CA).expect("write test CA");
        (cert, key, ca)
    }

    fn spawn_status_server(
        status: reqwest::StatusCode,
        extra_headers: &str,
    ) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("read test server address");
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n{extra_headers}\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Test Status")
        );
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept test request");
            let mut request = [0u8; 4_096];
            let _ = stream.read(&mut request);
            stream
                .write_all(response.as_bytes())
                .expect("write test response");
        });
        (format!("http://{address}"), handle)
    }

    fn deadletter_payload_count(spool_root: &Path) -> usize {
        fs::read_dir(spool_root.join("deadletter"))
            .expect("read deadletter directory")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            .count()
    }

    fn sample_asset_report() -> AssetReport {
        serde_json::from_value(serde_json::json!({
            "report_id": "report-original",
            "collected_at": "2026-07-10T00:00:00Z",
            "scanner_version": "1.0.0",
            "source_agent_id": "agent-1",
            "source_target_id": "target-1",
            "host": {
                "host_id": "host-1",
                "hostname": "sensor-1",
                "os": "linux",
                "kernel": null,
                "arch": "x86_64",
                "ip_addrs": [],
                "mac_addrs": [],
                "boot_time": null
            },
            "assets": [],
            "vulnerabilities": []
        }))
        .expect("sample asset report must deserialize")
    }

    fn sample_asset(index: usize, name: String) -> agent_contract::Asset {
        serde_json::from_value(serde_json::json!({
            "kind": "package",
            "asset_id": format!("package-{index}"),
            "parent_asset_id": null,
            "name": name,
            "version": "1.0",
            "source": "test",
            "install_path": null,
            "ecosystem": null
        }))
        .expect("sample asset must deserialize")
    }

    fn sample_vulnerability(index: usize) -> agent_contract::Vulnerability {
        serde_json::from_value(serde_json::json!({
            "vuln_id": format!("CVE-TEST-{index}"),
            "severity": "medium",
            "cvss_score": 5.0,
            "affected_asset_id": format!("package-{index}"),
            "parent_asset_id": null,
            "source": "test",
            "evidence": null,
            "references": []
        }))
        .expect("sample vulnerability must deserialize")
    }

    fn sample_trace_batch() -> TraceBatch {
        serde_json::from_value(serde_json::json!({
            "batch_id": "batch-original",
            "collected_at": "2026-07-10T00:00:00Z",
            "collector_id": "collector-1",
            "collector_version": "1.0.0",
            "source_agent_id": "agent-1",
            "source_target_id": "target-1",
            "events": [],
            "file_events": [],
            "process_events": []
        }))
        .expect("sample trace batch must deserialize")
    }

    fn sample_threat(index: usize) -> ThreatMatch {
        serde_json::from_value(serde_json::json!({
            "indicator": format!("indicator-{index}"),
            "indicator_type": "domain",
            "category": "test",
            "severity": "high",
            "source": "test-feed",
            "description": null
        }))
        .expect("sample threat match must deserialize")
    }

    fn sample_network_event(index: usize, dns_query: String) -> TraceEvent {
        serde_json::from_value(serde_json::json!({
            "trace_id": format!("network-{index}"),
            "host_id": "host-1",
            "start_ts": "2026-07-10T00:00:00Z",
            "end_ts": "2026-07-10T00:00:01Z",
            "proto": "tcp",
            "src_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_ip": "10.0.0.2",
            "dst_port": 443,
            "bytes_sent": 10,
            "bytes_recv": 20,
            "packets_sent": 1,
            "packets_recv": 2,
            "app_proto": "TLS",
            "dns_query": dns_query,
            "tls_sni": null,
            "ja3": null,
            "threat_intel": []
        }))
        .expect("sample network trace must deserialize")
    }

    fn sample_file_event(index: usize) -> FileTraceEvent {
        serde_json::from_value(serde_json::json!({
            "trace_id": format!("file-{index}"),
            "host_id": "host-1",
            "ts": "2026-07-10T00:00:00Z",
            "pid": 10,
            "comm": "test",
            "uid": 1000,
            "op": "open",
            "path": "/tmp/test",
            "target_path": null,
            "ret": 3,
            "threat_intel": []
        }))
        .expect("sample file trace must deserialize")
    }

    fn sample_process_event(index: usize) -> ProcessTraceEvent {
        serde_json::from_value(serde_json::json!({
            "trace_id": format!("process-{index}"),
            "host_id": "host-1",
            "ts": "2026-07-10T00:00:00Z",
            "event_type": "exec",
            "pid": 10,
            "ppid": 1,
            "uid": 1000,
            "comm": "test",
            "exe": "/usr/bin/test",
            "argv": ["test"],
            "cgroup": null,
            "exit_code": null,
            "threat_intel": []
        }))
        .expect("sample process trace must deserialize")
    }

    #[test]
    fn builds_ingest_url() {
        assert_eq!(
            ingest_url("http://127.0.0.1:10067", "/ingest/asset-report"),
            "http://127.0.0.1:10067/ingest/asset-report"
        );
        assert_eq!(
            ingest_url("http://127.0.0.1:10067/", "/ingest/trace-batch"),
            "http://127.0.0.1:10067/ingest/trace-batch"
        );
    }

    #[test]
    fn mtls_base_url_must_be_a_pure_https_origin() {
        for origin in [
            "https://form.example",
            "https://form.example/",
            "https://form.example:10443",
            "https://[2001:db8::1]:10443/",
        ] {
            validate_mtls_base_url(origin)
                .unwrap_or_else(|error| panic!("expected {origin:?} to be accepted: {error}"));
        }

        for invalid in [
            "http://form.example",
            "form.example",
            "https://form.example/ingest",
            "https://form.example//",
            "https://form.example/%2e",
            "https://form.example?tenant=one",
            "https://form.example?",
            "https://form.example#fragment",
            "https://agent@form.example",
            "https://:secret@form.example",
            "https://@form.example",
            "https://form.example:",
            "https://form.example\\ingest",
        ] {
            assert!(
                validate_mtls_base_url(invalid).is_err(),
                "expected {invalid:?} to be rejected"
            );
        }
    }

    #[test]
    fn agent_token_precedes_legacy_ingest_token() {
        let _lock = TEST_ENV_LOCK.lock().expect("lock test environment");
        let _restore = EnvRestore::clear(AGENT_ENV);
        std::env::set_var("FORM_AGENT_TOKEN", " agent-scoped ");
        std::env::set_var("FORM_INGEST_TOKEN", "legacy-fleet-token");
        assert_eq!(bearer_token().as_deref(), Some("agent-scoped"));

        std::env::set_var("FORM_AGENT_TOKEN", "   ");
        assert_eq!(bearer_token().as_deref(), Some("legacy-fleet-token"));

        std::env::remove_var("FORM_INGEST_TOKEN");
        assert_eq!(bearer_token(), None);
    }

    #[test]
    fn tls_identity_variables_are_all_or_none() {
        let _lock = TEST_ENV_LOCK.lock().expect("lock test environment");
        let _restore = EnvRestore::clear(AGENT_ENV);
        std::env::set_var("FORM_AGENT_CERT", "/tmp/client.pem");

        let error = ClientSettings::from_env()
            .err()
            .expect("partial TLS identity must fail closed");
        assert!(
            error.to_string().contains(
                "FORM_AGENT_CERT, FORM_AGENT_KEY, and FORM_AGENT_CA must be configured together"
            ),
            "{error}"
        );
    }

    #[test]
    fn tls_identity_builds_reloads_and_requires_https() {
        let _lock = TEST_ENV_LOCK.lock().expect("lock test environment");
        let _restore = EnvRestore::clear(AGENT_ENV);
        let dir = TestDir::new("identity");
        let (cert, key, ca) = write_test_identity(dir.path());
        std::env::set_var("FORM_AGENT_CERT", &cert);
        std::env::set_var("FORM_AGENT_KEY", &key);
        std::env::set_var("FORM_AGENT_CA", &ca);
        std::env::set_var("FORM_UPLOAD_TIMEOUT", "7");

        let first = ClientSettings::from_env().expect("load complete TLS identity");
        assert_eq!(first.timeout, Duration::from_secs(7));
        assert!(first.tls.is_some());
        first
            .validate_base_url("https://form.example")
            .expect("identity mode accepts HTTPS");
        let http_error = first
            .validate_base_url("http://form.example")
            .expect_err("identity mode must reject plaintext HTTP");
        assert!(http_error
            .to_string()
            .contains("requires an absolute https://"));

        let mut cache = ClientCache::default();
        cache
            .client_for(&first)
            .expect("rustls client identity and private CA must build");
        let first_generation = first.generation.clone();
        assert_eq!(
            cache.current.as_ref().map(|entry| &entry.generation),
            Some(&first_generation)
        );

        let mut rotated_cert = TEST_AGENT_CERT.to_vec();
        rotated_cert.push(b'\n');
        fs::write(&cert, rotated_cert).expect("atomically published fixture surrogate");
        let rotated = ClientSettings::from_env().expect("reload rotated TLS files");
        assert_ne!(rotated.generation, first_generation);
        cache
            .client_for(&rotated)
            .expect("publish the new valid client generation");
        assert_eq!(
            cache.current.as_ref().map(|entry| &entry.generation),
            Some(&rotated.generation)
        );

        fs::write(&key, b"not a private key").expect("replace key with invalid generation");
        let invalid = ClientSettings::from_env().expect("snapshot invalid key bytes");
        let published = cache
            .current
            .as_ref()
            .expect("valid generation remains cached")
            .generation
            .clone();
        cache
            .client_for(&invalid)
            .expect("a malformed new generation falls back to the last known-good TLS client");
        assert_eq!(
            cache.current.as_ref().map(|entry| &entry.generation),
            Some(&published),
            "a failed rotation must not replace the last valid generation"
        );

        let mut empty_cache = ClientCache::default();
        assert!(
            empty_cache.client_for(&invalid).is_err(),
            "an invalid first generation must fail closed without a cached identity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn shared_current_parent_is_resolved_to_one_tls_generation() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new("identity-generation-snapshot");
        let first = dir.path().join("generation-first");
        let second = dir.path().join("generation-second");
        fs::create_dir(&first).expect("create first generation");
        fs::create_dir(&second).expect("create second generation");
        for (generation, suffix) in [(&first, "first"), (&second, "second")] {
            fs::write(generation.join("client-cert.pem"), format!("cert-{suffix}"))
                .expect("write certificate");
            fs::write(generation.join("client-key.pem"), format!("key-{suffix}"))
                .expect("write private key");
            fs::write(generation.join("ca-bundle.pem"), format!("ca-{suffix}"))
                .expect("write CA bundle");
        }
        let current = dir.path().join("current");
        symlink("generation-first", &current).expect("publish first generation");
        let resolved = resolved_tls_snapshot_paths(
            &current.join("client-cert.pem"),
            &current.join("client-key.pem"),
            &current.join("ca-bundle.pem"),
        )
        .expect("resolve one generation");

        fs::remove_file(&current).expect("remove old current link");
        symlink("generation-second", &current).expect("publish second generation");
        let snapshot = read_tls_material_once(&resolved.0, &resolved.1, &resolved.2)
            .expect("resolved first generation remains readable");

        assert_eq!(snapshot.cert.bytes, b"cert-first");
        assert_eq!(snapshot.key.bytes, b"key-first");
        assert_eq!(snapshot.ca.bytes, b"ca-first");
    }

    #[test]
    fn upload_client_initialization_failure_spools_current_payload() {
        let _lock = TEST_ENV_LOCK.lock().expect("lock test environment");
        let _restore = EnvRestore::clear(AGENT_ENV);
        let dir = TestDir::new("client-init-spool");
        let spool_root = dir.path().join("spool");
        std::env::set_var("FORM_SPOOL_DIR", &spool_root);
        std::env::set_var("FORM_AGENT_CERT", dir.path().join("missing-client.pem"));

        let outcome = post_json(
            &serde_json::json!({"batch_id": "client-init-failure"}),
            "https://form.example",
            "/ingest/guard-event",
        )
        .expect("client initialization failure must be recoverably spooled");

        assert_eq!(outcome, UploadOutcome::Spooled);
        let spool = Spool::at(&spool_root, 1 << 20).expect("reopen secure spool");
        assert_eq!(spool.len(), 1);
    }

    #[test]
    fn ingest_client_does_not_follow_redirects() {
        let (base_url, server) = spawn_status_server(
            reqwest::StatusCode::TEMPORARY_REDIRECT,
            "Location: http://127.0.0.1:9/redirected\r\n",
        );
        let client = build_client(&plain_client_settings()).expect("build test client");
        let outcome = try_post(
            &client,
            &format!("{base_url}/ingest/guard-event"),
            &serde_json::json!({"batch_id": "redirect-test"}),
        );
        server.join().expect("join redirect server");
        assert!(
            matches!(outcome, PostOutcome::Permanent(_)),
            "a followed redirect to the closed target would be transient"
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

    #[test]
    fn classifies_retryable_auth_and_permanent_statuses_separately() {
        for status in [
            reqwest::StatusCode::REQUEST_TIMEOUT,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::BAD_GATEWAY,
        ] {
            assert!(is_transient_status(status), "{status} must be replayable");
        }
        for status in [
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::FORBIDDEN,
        ] {
            assert!(
                is_auth_blocked_status(status),
                "{status} must remain recoverable after credential rotation"
            );
            assert!(!is_transient_status(status));
        }
        for status in [
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::PAYLOAD_TOO_LARGE,
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert!(
                !is_transient_status(status) && !is_auth_blocked_status(status),
                "{status} must fail permanently"
            );
        }
    }

    #[test]
    fn auth_blocked_spool_item_is_retained_but_422_is_dead_lettered() {
        for status in [
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::FORBIDDEN,
        ] {
            let dir = TestDir::new("auth-spool");
            let spool_root = dir.path().join("spool");
            let spool = Spool::at(&spool_root, 1 << 20).expect("create secure spool");
            spool
                .enqueue(
                    "/ingest/guard-event",
                    &serde_json::json!({"batch_id": "auth-blocked"}),
                )
                .expect("enqueue auth-blocked item");
            let (base_url, server) = spawn_status_server(status, "");
            let client = build_client(&plain_client_settings()).expect("build test client");

            assert_eq!(drain_spool(&spool, &client, &base_url), 0);
            server.join().expect("join auth server");
            assert_eq!(spool.len(), 1, "{status} must retain the queued payload");
            assert_eq!(deadletter_payload_count(&spool_root), 0);
        }

        let dir = TestDir::new("permanent-spool");
        let spool_root = dir.path().join("spool");
        let spool = Spool::at(&spool_root, 1 << 20).expect("create secure spool");
        spool
            .enqueue(
                "/ingest/guard-event",
                &serde_json::json!({"batch_id": "invalid-contract"}),
            )
            .expect("enqueue invalid item");
        let (base_url, server) = spawn_status_server(reqwest::StatusCode::UNPROCESSABLE_ENTITY, "");
        let client = build_client(&plain_client_settings()).expect("build test client");

        assert_eq!(drain_spool(&spool, &client, &base_url), 0);
        server.join().expect("join validation server");
        assert!(spool.is_empty(), "422 leaves the active queue");
        assert_eq!(deadletter_payload_count(&spool_root), 1);
    }

    #[test]
    fn newly_auth_blocked_payload_is_spooled_for_rotation() {
        let _lock = TEST_ENV_LOCK.lock().expect("lock test environment");
        let _restore = EnvRestore::clear(AGENT_ENV);
        let dir = TestDir::new("new-auth-spool");
        let spool_root = dir.path().join("spool");
        std::env::set_var("FORM_SPOOL_DIR", &spool_root);
        std::env::set_var("FORM_UPLOAD_RETRIES", "0");
        let (base_url, server) = spawn_status_server(reqwest::StatusCode::UNAUTHORIZED, "");

        let outcome = post_json(
            &serde_json::json!({"batch_id": "new-auth-blocked"}),
            &base_url,
            "/ingest/guard-event",
        )
        .expect("auth-blocked upload is recoverably spooled");
        server.join().expect("join auth server");
        assert_eq!(outcome, UploadOutcome::Spooled);
        let spool = Spool::at(&spool_root, 1 << 20).expect("reopen secure spool");
        assert_eq!(spool.len(), 1);
        assert_eq!(deadletter_payload_count(&spool_root), 0);
    }

    #[test]
    fn asset_report_chunks_both_schema_bounded_streams_losslessly() {
        let mut report = sample_asset_report();
        report.assets = (0..=MAX_SCHEMA_ITEMS)
            .map(|index| sample_asset(index, format!("asset-{index}")))
            .collect();
        report.vulnerabilities = (0..=MAX_SCHEMA_ITEMS).map(sample_vulnerability).collect();

        let chunks = split_asset_report(&report).expect("oversized report must split");
        assert!(chunks.len() > 1);
        assert!(chunks
            .iter()
            .all(|chunk| chunk.assets.len() <= MAX_SCHEMA_ITEMS));
        assert!(chunks
            .iter()
            .all(|chunk| chunk.vulnerabilities.len() <= MAX_SCHEMA_ITEMS));
        assert!(chunks.iter().all(|chunk| {
            chunk.source_agent_id.as_deref() == Some("agent-1")
                && chunk.source_target_id.as_deref() == Some("target-1")
        }));
        assert_eq!(
            chunks.iter().map(|chunk| chunk.assets.len()).sum::<usize>(),
            report.assets.len()
        );
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.vulnerabilities.len())
                .sum::<usize>(),
            report.vulnerabilities.len()
        );

        let ids = chunks
            .iter()
            .map(|chunk| chunk.report_id.clone())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), chunks.len());
        assert!(ids
            .iter()
            .all(|id| { id.chars().count() <= agent_contract::CORRELATION_IDENTIFIER_MAX_CHARS }));
        let again = split_asset_report(&report).expect("same report must split deterministically");
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| &chunk.report_id)
                .collect::<Vec<_>>(),
            again
                .iter()
                .map(|chunk| &chunk.report_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn trace_batch_chunks_all_three_schema_bounded_streams_losslessly() {
        let mut batch = sample_trace_batch();
        let network = sample_network_event(0, "example.test".into());
        let file = sample_file_event(0);
        let process = sample_process_event(0);
        batch.events = vec![network; MAX_SCHEMA_ITEMS + 1];
        batch.file_events = vec![file; MAX_SCHEMA_ITEMS + 1];
        batch.process_events = vec![process; MAX_SCHEMA_ITEMS + 1];

        let chunks = split_trace_batch(&batch).expect("oversized trace batch must split");
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|chunk| {
            chunk.events.len() <= MAX_SCHEMA_ITEMS
                && chunk.file_events.len() <= MAX_SCHEMA_ITEMS
                && chunk.process_events.len() <= MAX_SCHEMA_ITEMS
        }));
        assert!(chunks.iter().all(|chunk| {
            chunk.source_agent_id.as_deref() == Some("agent-1")
                && chunk.source_target_id.as_deref() == Some("target-1")
        }));
        assert_eq!(
            chunks.iter().map(|chunk| chunk.events.len()).sum::<usize>(),
            batch.events.len()
        );
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.file_events.len())
                .sum::<usize>(),
            batch.file_events.len()
        );
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.process_events.len())
                .sum::<usize>(),
            batch.process_events.len()
        );

        let ids = chunks
            .iter()
            .map(|chunk| chunk.batch_id.clone())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), chunks.len());
        assert!(ids
            .iter()
            .all(|id| { id.chars().count() <= agent_contract::CORRELATION_IDENTIFIER_MAX_CHARS }));
        let again = split_trace_batch(&batch).expect("same batch must split deterministically");
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| &chunk.batch_id)
                .collect::<Vec<_>>(),
            again
                .iter()
                .map(|chunk| &chunk.batch_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn threat_intel_is_split_for_every_trace_kind_with_unique_bounded_ids() {
        let mut batch = sample_trace_batch();
        let threats = (0..(MAX_THREAT_INTEL_ITEMS * 2 + 2))
            .map(sample_threat)
            .collect::<Vec<_>>();
        let mut network = sample_network_event(0, "example.test".into());
        network.trace_id = "same-trace".into();
        network.threat_intel.clone_from(&threats);
        let mut file = sample_file_event(0);
        file.trace_id = "same-trace".into();
        file.threat_intel.clone_from(&threats);
        let mut process = sample_process_event(0);
        process.trace_id = "same-trace".into();
        process.threat_intel.clone_from(&threats);
        batch.events.push(network);
        batch.file_events.push(file);
        batch.process_events.push(process);

        let chunks = split_trace_batch(&batch).expect("threat lists must split");
        assert_eq!(chunks.len(), 1, "small normalized payload stays one batch");
        assert_eq!(chunks[0].batch_id, batch.batch_id);
        assert_eq!(chunks[0].events.len(), 3);
        assert_eq!(chunks[0].file_events.len(), 3);
        assert_eq!(chunks[0].process_events.len(), 3);

        let all_ids = chunks[0]
            .events
            .iter()
            .map(|event| &event.trace_id)
            .chain(chunks[0].file_events.iter().map(|event| &event.trace_id))
            .chain(chunks[0].process_events.iter().map(|event| &event.trace_id))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(all_ids.len(), 9);
        assert!(all_ids
            .iter()
            .all(|id| { id.chars().count() <= agent_contract::CORRELATION_IDENTIFIER_MAX_CHARS }));

        for counts in [
            chunks[0]
                .events
                .iter()
                .map(|event| event.threat_intel.len())
                .collect::<Vec<_>>(),
            chunks[0]
                .file_events
                .iter()
                .map(|event| event.threat_intel.len())
                .collect::<Vec<_>>(),
            chunks[0]
                .process_events
                .iter()
                .map(|event| event.threat_intel.len())
                .collect::<Vec<_>>(),
        ] {
            assert_eq!(counts, vec![64, 64, 2]);
        }
        let recovered = chunks[0]
            .events
            .iter()
            .flat_map(|event| &event.threat_intel)
            .map(|intel| &intel.indicator)
            .collect::<Vec<_>>();
        assert_eq!(
            recovered,
            threats
                .iter()
                .map(|intel| &intel.indicator)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn exact_asset_body_limit_stays_single_and_one_byte_over_splits() {
        let mut report = sample_asset_report();
        let schema_sized_text = "x".repeat(4_096);
        let mut body_bytes = serialized_len(&report, "empty boundary report")
            .expect("serialize empty boundary report");
        loop {
            let index = report.assets.len();
            let asset = sample_asset(index, schema_sized_text.clone());
            let item_bytes = serialized_len(&asset, "boundary asset").expect("serialize asset");
            let added = added_array_item_bytes(report.assets.len(), item_bytes)
                .expect("boundary size addition");
            if !fits_body(body_bytes, added) {
                break;
            }
            report.assets.push(asset);
            body_bytes += added;
        }

        // Replace one full-width item with a flexible one, then distribute the
        // exact remaining bytes across ordinary <=4096-character string fields.
        report
            .assets
            .pop()
            .expect("at least one full item must fit");
        let flexible_index = report.assets.len();
        report
            .assets
            .push(sample_asset(flexible_index, String::new()));
        let current = serialized_len(&report, "flexible boundary report")
            .expect("serialize flexible boundary");
        let mut remaining = MAX_INGEST_BODY_BYTES - current;
        let agent_contract::Asset::Package(package) = report.assets.last_mut().expect("last asset")
        else {
            panic!("sample asset must be a package");
        };
        let name_bytes = remaining.min(4_096);
        package.name = "x".repeat(name_bytes);
        remaining -= name_bytes;
        let version_bytes = remaining.min(4_096 - package.version.len());
        package.version.push_str(&"x".repeat(version_bytes));
        remaining -= version_bytes;
        let source = package.source.as_mut().expect("sample package source");
        let source_bytes = remaining.min(4_096 - source.len());
        source.push_str(&"x".repeat(source_bytes));
        remaining -= source_bytes;
        assert_eq!(remaining, 0, "legal string fields must cover boundary gap");
        assert_eq!(
            serialized_len(&report, "exact boundary report").expect("serialize exact boundary"),
            MAX_INGEST_BODY_BYTES
        );

        let chunks = split_asset_report(&report).expect("exact-limit report must fit");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].report_id, report.report_id);

        let agent_contract::Asset::Package(package) = report.assets.last_mut().expect("last asset")
        else {
            panic!("sample asset must be a package");
        };
        if package.name.len() < 4_096 {
            package.name.push('x');
        } else {
            package.version.push('x');
        }
        let chunks = split_asset_report(&report).expect("one byte over must split losslessly");
        assert!(chunks.len() > 1);
        assert_eq!(
            chunks.iter().map(|chunk| chunk.assets.len()).sum::<usize>(),
            report.assets.len()
        );
        assert!(chunks.iter().all(|chunk| {
            serialized_len(chunk, "one-byte-over child").expect("serialize child")
                <= MAX_INGEST_BODY_BYTES
        }));
    }

    #[test]
    fn serialized_body_size_splits_asset_and_trace_payloads_below_nine_mib() {
        const LEGAL_ITEM_COUNT: usize = 3_000;
        let schema_sized_text = "x".repeat(4_096);

        let mut report = sample_asset_report();
        report.assets = (0..LEGAL_ITEM_COUNT)
            .map(|index| sample_asset(index, schema_sized_text.clone()))
            .collect();
        assert!(
            serialized_len(&report, "large valid report").expect("serialize report")
                > MAX_INGEST_BODY_BYTES
        );
        let report_chunks = split_asset_report(&report).expect("large assets must split");
        assert!(report_chunks.len() > 1);
        assert_eq!(
            report_chunks
                .iter()
                .map(|chunk| chunk.assets.len())
                .sum::<usize>(),
            LEGAL_ITEM_COUNT
        );
        assert!(report_chunks.iter().all(|chunk| {
            serialized_len(chunk, "asset body assertion").expect("serialize child")
                <= MAX_INGEST_BODY_BYTES
        }));

        let mut batch = sample_trace_batch();
        batch.events = (0..LEGAL_ITEM_COUNT)
            .map(|index| sample_network_event(index, schema_sized_text.clone()))
            .collect();
        assert!(
            serialized_len(&batch, "large valid trace batch").expect("serialize batch")
                > MAX_INGEST_BODY_BYTES
        );
        let batch_chunks = split_trace_batch(&batch).expect("large traces must split");
        assert!(batch_chunks.len() > 1);
        assert_eq!(
            batch_chunks
                .iter()
                .map(|chunk| chunk.events.len())
                .sum::<usize>(),
            LEGAL_ITEM_COUNT
        );
        assert!(batch_chunks.iter().all(|chunk| {
            serialized_len(chunk, "trace body assertion").expect("serialize child")
                <= MAX_INGEST_BODY_BYTES
        }));
    }

    #[test]
    fn oversized_dedicated_trace_path_returns_explicit_local_error() {
        let mut batch = sample_trace_batch();
        let mut event = sample_file_event(0);
        event.path = "x".repeat(MAX_INGEST_BODY_BYTES);
        batch.file_events.push(event);
        let error = split_trace_batch(&batch).expect_err("oversized path must fail locally");
        assert!(error.to_string().contains("file_trace.path"), "{error}");
    }
}
