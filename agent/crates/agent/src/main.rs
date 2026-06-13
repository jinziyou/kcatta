//! agent: kcatta 的统一 CLI —— 把三大能力（host / flow / guard）聚合到单一 `agent` 命令。
//!
//! 这是一个便捷的「总入口」二进制：子命令在进程内分发到各能力库的 `cli` 模块
//! （`agent_host::cli` / `agent_flow::cli` / `agent_guard::cli`），与三个独立二进制
//! `agent-host` / `agent-flow` / `agent-guard` 共用同一套逻辑。三个独立二进制仍是
//! 精简、可单独部署的产物；本二进制是包含三者的「全功能」入口。
//!
//! **上报只发生在这里**：独立二进制只在本地产出结果文件；`agent <cap> --upload <URL>` 才把
//! 结果上报 analyzer（ingest 能力内置于本 crate 的 [`ingest`] 模块）。
//!
//! 实时抓包 / on-access / 网络联动 / IDS 经本 crate 的 `pcap` / `onaccess` / `network` /
//! `ids` / `full` feature 转发到对应能力 crate 开启。

use anyhow::Result;
use clap::{Parser, Subcommand};

mod ingest;

#[derive(Debug, Parser)]
#[command(
    name = "agent",
    version,
    about = "kcatta agent 统一入口：host(主机静态文件检测) / flow(流量检测) / guard(实时防护)"
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
    /// 流量检测（= agent-flow）；`--upload` 时把 FlowBatch 上报 analyzer。
    Flow {
        #[command(subcommand)]
        command: agent_flow::cli::FlowCommand,
        /// 上报 FlowBatch 到 analyzer（`<URL>/ingest/flow-batch`）。
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
        Command::Flow { command, upload } => {
            let batch = agent_flow::cli::run(command)?;
            if let (Some(url), Some(batch)) = (upload, batch) {
                ingest::upload_batch(&batch, &url)?;
                let hits: usize = batch.flows.iter().map(|f| f.threat_intel.len()).sum();
                eprintln!(
                    "uploaded {} ({} flow(s), {} threat-intel hit(s)) to {url}",
                    batch.batch_id,
                    batch.flows.len(),
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
    }
}

/// Guard report sink that uploads each flushed batch to analyzer's
/// `/ingest/guard-event` (the umbrella's injected transport for `agent guard`).
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
