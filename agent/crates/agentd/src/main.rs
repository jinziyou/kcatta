//! agentd: kcatta 的统一 CLI —— 把 collect / respond 能力聚合到单一 `agentd` 命令。
//!
//! 子命令在进程内分发到各能力库的 `cli` 模块
//! （`agent_collect_host::cli` / `agent_collect_trace::cli` / `agent_respond::cli`），与三个独立二进制
//! `agent-collect-host` / `agent-collect-trace` / `agent-respond` 共用同一套逻辑。
//!
//! **上报只发生在这里**：独立二进制只在本地产出结果文件；`agentd <cap> --upload <URL>` 才把
//! 结果上报 Form（ingest 能力内置于本 crate 的 [`ingest`] 模块）。Agent 不直接连接 analyzer。
//!
//! 主子命令：`collect-host` / `collect-trace` / `respond` / `run`。  
//! 兼容别名：`host` / `trace` / `guard`。

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod ingest;
mod run;
mod spool;

#[derive(Debug, Parser)]
#[command(
    name = "agentd",
    version,
    about = "kcatta agentd 统一入口：collect-host / collect-trace / respond / run（别名 host|trace|guard）"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// 主机静态文件检测（= agent-collect-host）；`--upload` 时把合并 AssetReport 上报 Form。
    #[command(name = "collect-host", visible_alias = "host")]
    CollectHost {
        #[command(flatten)]
        args: agent_collect_host::cli::ScanArgs,
        /// 上报合并 AssetReport 到 Form（`<URL>/ingest/asset-report`）。
        #[arg(long, value_name = "URL")]
        upload: Option<String>,
    },
    /// 网络追踪（= agent-collect-trace）；`--upload` 时把 TraceBatch 上报 Form。
    #[command(name = "collect-trace", visible_alias = "trace")]
    CollectTrace {
        #[command(subcommand)]
        command: agent_collect_trace::cli::TraceCommand,
        /// 上报 TraceBatch 到 Form（`<URL>/ingest/trace-batch`）。
        #[arg(long, value_name = "URL")]
        upload: Option<String>,
    },
    /// 实时防护守护进程（= agent-respond）；`--upload` 时把 GuardEventBatch 实时推送 Form。
    #[command(name = "respond", visible_alias = "guard")]
    Respond {
        #[command(flatten)]
        args: agent_respond::cli::GuardArgs,
        /// 实时推送 GuardEventBatch 到 Form（`<URL>/ingest/guard-event`）。
        #[arg(long, value_name = "URL")]
        upload: Option<String>,
    },
    /// 编排守护进程：按间隔调度 collect-host+collect-trace、可选常驻 respond，统一上报 Form。
    Run {
        /// JSON 编排配置（采集间隔、各阶段开关、Form 地址）。
        #[arg(long, value_name = "PATH", default_value = "/etc/kcatta/agentd.json")]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::CollectHost { args, upload } => {
            let report = agent_collect_host::cli::run(args)?;
            if let (Some(url), Some(report)) = (upload, report) {
                match ingest::upload_report(&report, &url)? {
                    ingest::UploadOutcome::Delivered => eprintln!("uploaded report to {url}"),
                    ingest::UploadOutcome::Spooled => {
                        eprintln!("form unreachable; report spooled for later delivery")
                    }
                }
            }
            Ok(())
        }
        Command::CollectTrace { command, upload } => {
            let batch = agent_collect_trace::cli::run(command)?;
            if let (Some(url), Some(batch)) = (upload, batch) {
                let hits: usize = batch.events.iter().map(|f| f.threat_intel.len()).sum();
                match ingest::upload_batch(&batch, &url)? {
                    ingest::UploadOutcome::Delivered => eprintln!(
                        "uploaded {} ({} trace(s), {} threat-intel hit(s)) to {url}",
                        batch.batch_id,
                        batch.events.len(),
                        hits,
                    ),
                    ingest::UploadOutcome::Spooled => eprintln!(
                        "form unreachable; trace batch {} spooled for later delivery",
                        batch.batch_id
                    ),
                }
            }
            Ok(())
        }
        Command::Respond { args, upload } => {
            let mut sinks: Vec<Box<dyn agent_respond::ReportSink>> = Vec::new();
            if let Some(url) = upload.as_ref() {
                eprintln!("respond: uploading GuardEventBatch to {url}");
                sinks.push(Box::new(FormGuardSink::new(url.clone())));
            }
            agent_respond::cli::run(args, sinks)?;
            if let Some(url) = upload {
                let flushed = ingest::flush_spool_bounded(&url, 1);
                eprintln!(
                    "respond: shutdown delivered {flushed} spooled upload(s); remaining items stay durable"
                );
            }
            Ok(())
        }
        Command::Run { config } => {
            let config = run::RunConfig::from_path(&config)?;
            run::orchestrate(config)
        }
    }
}

/// Bound the non-durable fallback queue. When it fills, `emit` returns an error
/// and respond's bounded report buffer retains the events for a later flush.
const GUARD_UPLOAD_WORK_QUEUE: usize = 64;
const GUARD_LIVE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
const GUARD_SHUTDOWN_LIVE_ATTEMPTS: usize = 1;

enum GuardUploadWork {
    DurableWake,
    Live(agent_contract::GuardEventBatch),
}

/// Respond report sink that uploads each flushed batch to Form's
/// `/ingest/guard-event` (the umbrella's injected transport for `agentd respond`).
///
/// **Durable outbox on Unix**: `emit` writes every batch to the local spool first,
/// then sends a coalescing wake-up. If no safe disk spool exists (currently
/// non-Unix), it non-blockingly queues the batch in bounded memory. Only the
/// worker performs blocking HTTP, keeping a slow control plane off the
/// `detect → decide → respond` path.
struct FormGuardSink {
    tx: Option<std::sync::mpsc::SyncSender<GuardUploadWork>>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl FormGuardSink {
    fn new(base_url: String) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<GuardUploadWork>(GUARD_UPLOAD_WORK_QUEUE);
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_shutdown = std::sync::Arc::clone(&shutdown);
        let worker_base_url = base_url.clone();
        let worker = std::thread::Builder::new()
            .name("respond-uploader".into())
            .spawn(move || {
                use std::sync::mpsc::RecvTimeoutError;
                let mut pending_live: Option<agent_contract::GuardEventBatch> = None;
                loop {
                    if worker_shutdown.load(std::sync::atomic::Ordering::Acquire) {
                        final_guard_live_attempts(
                            &rx,
                            &mut pending_live,
                            &worker_base_url,
                            GUARD_SHUTDOWN_LIVE_ATTEMPTS,
                        );
                        break;
                    }
                    if let Some(batch) = pending_live.take() {
                        match ingest::upload_guard_batch_live_while(
                            &batch,
                            &worker_base_url,
                            || !worker_shutdown.load(std::sync::atomic::Ordering::Acquire),
                        ) {
                            ingest::GuardLiveOutcome::Delivered => continue,
                            ingest::GuardLiveOutcome::Permanent(error) => {
                                eprintln!(
                                    "respond: permanent live upload failure for batch {}: {error}",
                                    batch.batch_id
                                );
                                continue;
                            }
                            ingest::GuardLiveOutcome::Transient(error) => {
                                if worker_shutdown.load(std::sync::atomic::Ordering::Acquire) {
                                    pending_live = Some(batch);
                                    continue;
                                }
                                eprintln!(
                                    "respond: live upload unavailable for batch {}; retaining it in bounded memory: {error}",
                                    batch.batch_id
                                );
                                pending_live = Some(batch);
                                if !wait_for_guard_retry(&worker_shutdown, GUARD_LIVE_RETRY_DELAY) {
                                    // Re-enter the loop so the shutdown branch
                                    // performs its bounded final live attempt.
                                    continue;
                                }
                                continue;
                            }
                        }
                    }
                    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                        Ok(GuardUploadWork::Live(batch)) => pending_live = Some(batch),
                        Ok(GuardUploadWork::DurableWake) | Err(RecvTimeoutError::Timeout) => {
                            if !worker_shutdown.load(std::sync::atomic::Ordering::Acquire) {
                                let _ = ingest::flush_spool_until_shutdown(
                                    &worker_base_url,
                                    &worker_shutdown,
                                );
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            if worker_shutdown.load(std::sync::atomic::Ordering::Acquire) {
                                continue;
                            }
                            break;
                        }
                    }
                }
            })
            .expect("spawn respond uploader thread");
        Self {
            tx: Some(tx),
            shutdown,
            worker: Some(worker),
        }
    }

    fn emit_with(
        &self,
        batch: &agent_contract::GuardEventBatch,
        spool: impl FnOnce(
            &agent_contract::GuardEventBatch,
        ) -> anyhow::Result<ingest::GuardSpoolOutcome>,
        live: impl FnOnce(&agent_contract::GuardEventBatch) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        match spool(batch)? {
            ingest::GuardSpoolOutcome::Spooled => self.signal_durable(batch),
            ingest::GuardSpoolOutcome::LiveRequired => live(batch),
        }
    }

    fn signal_durable(&self, batch: &agent_contract::GuardEventBatch) -> anyhow::Result<()> {
        use std::sync::mpsc::TrySendError;
        let Some(tx) = &self.tx else {
            return Ok(()); // durable; the next process will replay it
        };
        match tx.try_send(GuardUploadWork::DurableWake) {
            Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Disconnected(_)) => {
                eprintln!(
                    "respond: uploader unavailable; batch {} remains in durable spool",
                    batch.batch_id
                );
                Ok(())
            }
        }
    }

    fn enqueue_live(&self, batch: &agent_contract::GuardEventBatch) -> anyhow::Result<()> {
        use std::sync::mpsc::TrySendError;
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("respond live uploader is shutting down"))?;
        match tx.try_send(GuardUploadWork::Live(batch.clone())) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(live_delivery_rejected(batch, "queue is full")),
            Err(TrySendError::Disconnected(_)) => {
                Err(live_delivery_rejected(batch, "uploader disconnected"))
            }
        }
    }
}

fn live_delivery_rejected(batch: &agent_contract::GuardEventBatch, reason: &str) -> anyhow::Error {
    static REJECTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let total = REJECTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    anyhow::anyhow!(
        "respond live upload {reason} for batch {}; Form delivery was not accepted (cumulative rejected batches: {total})",
        batch.batch_id
    )
}

fn final_guard_live_attempts(
    rx: &std::sync::mpsc::Receiver<GuardUploadWork>,
    pending: &mut Option<agent_contract::GuardEventBatch>,
    base_url: &str,
    max_items: usize,
) {
    let (batches, dropped) = take_shutdown_live_batches(rx, pending, max_items);
    let attempted = batches.len();
    for batch in batches {
        match ingest::upload_guard_batch_live_once(&batch, base_url) {
            ingest::GuardLiveOutcome::Delivered => {}
            ingest::GuardLiveOutcome::Transient(error)
            | ingest::GuardLiveOutcome::Permanent(error) => {
                eprintln!(
                    "respond: final live upload failed for batch {} during shutdown: {error}",
                    batch.batch_id
                );
            }
        }
    }
    if dropped > 0 {
        eprintln!(
            "respond: shutdown discarded {dropped} non-durable live batch(es) after {attempted} bounded final attempt(s)"
        );
    }
}

fn take_shutdown_live_batches(
    rx: &std::sync::mpsc::Receiver<GuardUploadWork>,
    pending: &mut Option<agent_contract::GuardEventBatch>,
    max_items: usize,
) -> (Vec<agent_contract::GuardEventBatch>, usize) {
    let mut all = Vec::new();
    if let Some(batch) = pending.take() {
        all.push(batch);
    }
    all.extend(rx.try_iter().filter_map(|work| match work {
        GuardUploadWork::Live(batch) => Some(batch),
        GuardUploadWork::DurableWake => None,
    }));
    let dropped = all.len().saturating_sub(max_items);
    all.truncate(max_items);
    (all, dropped)
}

fn wait_for_guard_retry(
    shutdown: &std::sync::atomic::AtomicBool,
    duration: std::time::Duration,
) -> bool {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        if shutdown.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        std::thread::sleep(
            std::time::Duration::from_millis(100)
                .min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
    !shutdown.load(std::sync::atomic::Ordering::Acquire)
}

impl agent_respond::ReportSink for FormGuardSink {
    fn emit(&self, batch: &agent_contract::GuardEventBatch) -> anyhow::Result<()> {
        self.emit_with(batch, ingest::spool_guard_batch, |batch| {
            self.enqueue_live(batch)
        })
    }

    fn is_delivery_sink(&self) -> bool {
        true
    }
}

impl Drop for FormGuardSink {
    fn drop(&mut self) {
        // Durable batches remain on disk. Non-durable fallback batches are held
        // in a bounded worker queue; stop between retry attempts and wait at most
        // for the currently in-flight request's configured timeout.
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Release);
        self.tx.take();
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                eprintln!("respond: uploader worker panicked during shutdown");
            }
        }
    }
}

#[cfg(test)]
mod guard_sink_tests {
    use super::*;

    fn batch(id: &str) -> agent_contract::GuardEventBatch {
        serde_json::from_value(serde_json::json!({
            "batch_id": id,
            "collected_at": "2026-07-10T00:00:00Z",
            "host_id": "host-test",
            "agent_version": "0.1.0",
            "events": []
        }))
        .unwrap()
    }

    fn sink_with_sender(tx: std::sync::mpsc::SyncSender<GuardUploadWork>) -> FormGuardSink {
        FormGuardSink {
            tx: Some(tx),
            shutdown: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            worker: None,
        }
    }

    #[test]
    fn spool_unavailable_routes_guard_batch_to_bounded_live_queue() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let sink = sink_with_sender(tx);
        let batch = batch("live-1");

        sink.emit_with(
            &batch,
            |_| Ok(ingest::GuardSpoolOutcome::LiveRequired),
            |batch| sink.enqueue_live(batch),
        )
        .unwrap();

        let GuardUploadWork::Live(queued) = rx.try_recv().unwrap() else {
            panic!("expected live fallback work item");
        };
        assert_eq!(queued.batch_id, "live-1");
    }

    #[test]
    fn full_live_queue_backpressures_report_buffer_instead_of_blocking() {
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        tx.try_send(GuardUploadWork::Live(batch("already-pending")))
            .unwrap();
        let sink = sink_with_sender(tx);

        let error = sink
            .emit_with(
                &batch("live-2"),
                |_| Ok(ingest::GuardSpoolOutcome::LiveRequired),
                |batch| sink.enqueue_live(batch),
            )
            .expect_err("bounded queue must report backpressure");

        assert!(error.to_string().contains("queue is full"));
    }

    #[test]
    fn durable_batch_never_needs_live_fallback_when_wake_queue_is_full() {
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        tx.try_send(GuardUploadWork::DurableWake).unwrap();
        let sink = sink_with_sender(tx);
        let mut live_called = false;

        sink.emit_with(
            &batch("durable-1"),
            |_| Ok(ingest::GuardSpoolOutcome::Spooled),
            |_| {
                live_called = true;
                Ok(())
            },
        )
        .unwrap();

        assert!(!live_called);
    }

    #[test]
    fn graceful_shutdown_keeps_pending_first_and_bounds_final_attempts() {
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        tx.try_send(GuardUploadWork::Live(batch("queued-1")))
            .unwrap();
        tx.try_send(GuardUploadWork::DurableWake).unwrap();
        tx.try_send(GuardUploadWork::Live(batch("queued-2")))
            .unwrap();
        drop(tx);
        let mut pending = Some(batch("pending"));

        let (final_batches, dropped) = take_shutdown_live_batches(&rx, &mut pending, 1);

        assert_eq!(
            final_batches
                .iter()
                .map(|batch| batch.batch_id.as_str())
                .collect::<Vec<_>>(),
            vec!["pending"]
        );
        assert_eq!(dropped, 2);
        assert!(pending.is_none());
    }

    #[test]
    fn shutdown_interrupting_retry_preserves_pending_for_final_selection() {
        let (_tx, rx) = std::sync::mpsc::sync_channel(1);
        let shutdown = std::sync::atomic::AtomicBool::new(true);
        let mut pending = Some(batch("retrying"));

        assert!(!wait_for_guard_retry(
            &shutdown,
            std::time::Duration::from_secs(1)
        ));
        let (final_batches, dropped) = take_shutdown_live_batches(&rx, &mut pending, 1);

        assert_eq!(final_batches[0].batch_id, "retrying");
        assert_eq!(dropped, 0);
    }
}
