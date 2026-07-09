//! agentd: kcatta 的统一 CLI —— 把 collect / respond 能力聚合到单一 `agentd` 命令。
//!
//! 子命令在进程内分发到各能力库的 `cli` 模块
//! （`agent_collect_host::cli` / `agent_collect_trace::cli` / `agent_respond::cli`），与三个独立二进制
//! `agent-collect-host` / `agent-collect-trace` / `agent-respond` 共用同一套逻辑。
//!
//! **上报只发生在这里**：独立二进制只在本地产出结果文件；`agentd <cap> --upload <URL>` 才把
//! 结果上报 analyzer（ingest 能力内置于本 crate 的 [`ingest`] 模块）。
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
    /// 主机静态文件检测（= agent-collect-host）；`--upload` 时把合并 AssetReport 上报 analyzer。
    #[command(name = "collect-host", visible_alias = "host")]
    CollectHost {
        #[command(flatten)]
        args: agent_collect_host::cli::ScanArgs,
        /// 上报合并 AssetReport 到 analyzer（`<URL>/ingest/asset-report`）。
        #[arg(long, value_name = "URL")]
        upload: Option<String>,
    },
    /// 网络追踪（= agent-collect-trace）；`--upload` 时把 TraceBatch 上报 analyzer。
    #[command(name = "collect-trace", visible_alias = "trace")]
    CollectTrace {
        #[command(subcommand)]
        command: agent_collect_trace::cli::TraceCommand,
        /// 上报 TraceBatch 到 analyzer（`<URL>/ingest/trace-batch`）。
        #[arg(long, value_name = "URL")]
        upload: Option<String>,
    },
    /// 实时防护守护进程（= agent-respond）；`--upload` 时把 GuardEventBatch 实时推送 analyzer。
    #[command(name = "respond", visible_alias = "guard")]
    Respond {
        #[command(flatten)]
        args: agent_respond::cli::GuardArgs,
        /// 实时推送 GuardEventBatch 到 analyzer（`<URL>/ingest/guard-event`）。
        #[arg(long, value_name = "URL")]
        upload: Option<String>,
    },
    /// 编排守护进程：按间隔调度 collect-host+collect-trace、可选常驻 respond，统一上报 analyzer。
    Run {
        /// JSON 编排配置（采集间隔、各阶段开关、analyzer 地址）。
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
                        eprintln!("analyzer unreachable; report spooled for later delivery")
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
                        "analyzer unreachable; trace batch {} spooled for later delivery",
                        batch.batch_id
                    ),
                }
            }
            Ok(())
        }
        Command::Respond { args, upload } => {
            let mut sinks: Vec<Box<dyn agent_respond::ReportSink>> = Vec::new();
            if let Some(url) = upload {
                eprintln!("respond: uploading GuardEventBatch to {url}");
                sinks.push(Box::new(AnalyzerGuardSink::new(url)));
            }
            agent_respond::cli::run(args, sinks)
        }
        Command::Run { config } => {
            let config = run::RunConfig::from_path(&config)?;
            run::orchestrate(config)
        }
    }
}

/// Bound on the respond upload queue. Past this, batches are dropped (the local
/// NDJSON audit log remains the durable record) rather than back-pressuring the
/// real-time detection pipeline.
const GUARD_UPLOAD_QUEUE: usize = 1024;

/// Respond report sink that uploads each flushed batch to analyzer's
/// `/ingest/guard-event` (the umbrella's injected transport for `agentd respond`).
///
/// **Non-blocking**: `emit` only enqueues onto a bounded channel and returns
/// immediately; a dedicated background thread performs the blocking, retrying
/// HTTP upload. This decouples detection latency from analyzer availability — a
/// slow or unreachable analyzer can no longer stall `detect → decide → respond`
/// (previously each critical event blocked the single pipeline thread on a
/// 60s-timeout blocking POST).
struct AnalyzerGuardSink {
    tx: std::sync::mpsc::SyncSender<agent_contract::GuardEventBatch>,
}

impl AnalyzerGuardSink {
    fn new(base_url: String) -> Self {
        let (tx, rx) =
            std::sync::mpsc::sync_channel::<agent_contract::GuardEventBatch>(GUARD_UPLOAD_QUEUE);
        std::thread::Builder::new()
            .name("respond-uploader".into())
            .spawn(move || {
                // Drains the queue; each batch is uploaded with the retry/backoff
                // and durable spooling built into `ingest::upload_guard_batch`.
                while let Ok(batch) = rx.recv() {
                    match ingest::upload_guard_batch(&batch, &base_url) {
                        Ok(ingest::UploadOutcome::Delivered) => {}
                        Ok(ingest::UploadOutcome::Spooled) => eprintln!(
                            "respond: analyzer unreachable; batch {} spooled for later delivery",
                            batch.batch_id
                        ),
                        Err(e) => eprintln!(
                            "respond: analyzer upload failed for batch {} ({e}); kept in local audit log",
                            batch.batch_id
                        ),
                    }
                }
            })
            .expect("spawn respond uploader thread");
        Self { tx }
    }
}

impl agent_respond::ReportSink for AnalyzerGuardSink {
    fn emit(&self, batch: &agent_contract::GuardEventBatch) -> anyhow::Result<()> {
        use std::sync::mpsc::TrySendError;
        match self.tx.try_send(batch.clone()) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                // Analyzer backed up: don't block detection. The local audit sink
                // still records this batch, so it is not lost — just not uploaded.
                anyhow::bail!(
                    "analyzer upload queue full; batch dropped from upload (see audit log)"
                )
            }
            Err(TrySendError::Disconnected(_)) => {
                anyhow::bail!("respond uploader thread is gone")
            }
        }
    }
}
