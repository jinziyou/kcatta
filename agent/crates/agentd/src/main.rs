//! agentd: kcatta 的统一 CLI —— 把三大能力（host / flow / guard）聚合到单一 `agentd` 命令。
//!
//! 这是一个便捷的「总入口」二进制：子命令在进程内分发到各能力库的 `cli` 模块
//! （`agent_host::cli` / `agent_trace::cli` / `agent_guard::cli`），与三个独立二进制
//! `agent-host` / `agent-trace` / `agent-guard` 共用同一套逻辑。三个独立二进制仍是
//! 精简、可单独部署的产物；本二进制是包含三者的「全功能」入口。
//!
//! **上报只发生在这里**：独立二进制只在本地产出结果文件；`agentd <cap> --upload <URL>` 才把
//! 结果上报 analyzer（ingest 能力内置于本 crate 的 [`ingest`] 模块）。
//!
//! 实时抓包 / on-access / 网络联动 / IDS 经本 crate 的 `pcap` / `onaccess` / `network` /
//! `ids` / `full` feature 转发到对应能力 crate 开启。

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod ingest;
mod run;

#[derive(Debug, Parser)]
#[command(
    name = "agentd",
    version,
    about = "kcatta agentd 统一入口：host(主机静态文件检测) / trace(eBPF 网络·文件·进程追踪) / guard(实时防护) / run(编排调度)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// 主机静态文件检测（= agent-host）；`--upload` 时把合并 AssetReport 上报 analyzer。
    Host {
        #[command(flatten)]
        args: agent_host::cli::ScanArgs,
        /// 上报合并 AssetReport 到 analyzer（`<URL>/ingest/asset-report`）。
        #[arg(long, value_name = "URL")]
        upload: Option<String>,
    },
    /// 网络追踪（= agent-trace）；`--upload` 时把 TraceBatch 上报 analyzer。
    Trace {
        #[command(subcommand)]
        command: agent_trace::cli::TraceCommand,
        /// 上报 TraceBatch 到 analyzer（`<URL>/ingest/trace-batch`）。
        #[arg(long, value_name = "URL")]
        upload: Option<String>,
    },
    /// 实时防护守护进程（= agent-guard）；`--upload` 时把 GuardEventBatch 实时推送 analyzer。
    Guard {
        #[command(flatten)]
        args: agent_guard::cli::GuardArgs,
        /// 实时推送 GuardEventBatch 到 analyzer（`<URL>/ingest/guard-event`）。
        #[arg(long, value_name = "URL")]
        upload: Option<String>,
    },
    /// 编排守护进程：按间隔调度 host+trace 采集、可选常驻 guard，统一上报 analyzer。
    Run {
        /// JSON 编排配置（采集间隔、各阶段开关、analyzer 地址）。
        #[arg(long, value_name = "PATH", default_value = "/etc/kcatta/agentd.json")]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Host { args, upload } => {
            let report = agent_host::cli::run(args)?;
            if let (Some(url), Some(report)) = (upload, report) {
                ingest::upload_report(&report, &url)?;
                eprintln!("uploaded report to {url}");
            }
            Ok(())
        }
        Command::Trace { command, upload } => {
            let batch = agent_trace::cli::run(command)?;
            if let (Some(url), Some(batch)) = (upload, batch) {
                ingest::upload_batch(&batch, &url)?;
                let hits: usize = batch.events.iter().map(|f| f.threat_intel.len()).sum();
                eprintln!(
                    "uploaded {} ({} trace(s), {} threat-intel hit(s)) to {url}",
                    batch.batch_id,
                    batch.events.len(),
                    hits,
                );
            }
            Ok(())
        }
        Command::Guard { args, upload } => {
            let mut sinks: Vec<Box<dyn agent_guard::ReportSink>> = Vec::new();
            if let Some(url) = upload {
                eprintln!("guard: uploading GuardEventBatch to {url}");
                sinks.push(Box::new(AnalyzerGuardSink::new(url)));
            }
            agent_guard::cli::run(args, sinks)
        }
        Command::Run { config } => {
            let config = run::RunConfig::from_path(&config)?;
            run::orchestrate(config)
        }
    }
}

/// Guard report sink that uploads each flushed batch to analyzer's
/// `/ingest/guard-event` (the umbrella's injected transport for `agentd guard`).
struct AnalyzerGuardSink {
    base_url: String,
}

impl AnalyzerGuardSink {
    fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

impl agent_guard::ReportSink for AnalyzerGuardSink {
    fn emit(&self, batch: &agent_contract::GuardEventBatch) -> anyhow::Result<()> {
        ingest::upload_guard_batch(batch, &self.base_url)
    }
}
