//! agent: posture 的统一 CLI —— 把三大能力（host / flow / guard）聚合到单一 `agent` 命令。
//!
//! 这是一个便捷的「总入口」二进制：子命令在进程内分发到各能力库的 `cli` 模块
//! （`posture_host::cli` / `posture_flow::cli` / `posture_guard::cli`），与三个独立二进制
//! `posture-host` / `posture-flow` / `posture-guard` 共用同一套逻辑。三个独立二进制仍是
//! 精简、可单独部署的产物；本二进制是包含三者的「全功能」入口。
//!
//! 实时抓包 / on-access / 网络联动 / IDS 经本 crate 的 `pcap` / `onaccess` / `network` /
//! `ids` / `full` feature 转发到对应能力 crate 开启。

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "agent",
    version,
    about = "posture agent 统一入口：host(主机静态文件检测) / flow(流量检测) / guard(实时防护)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// 主机静态文件检测（等价于 posture-host）。
    Host(posture_host::cli::ScanArgs),
    /// 流量检测：capture / intel-sync（等价于 posture-flow）。
    Flow {
        #[command(subcommand)]
        command: posture_flow::cli::FlowCommand,
    },
    /// 实时防护守护进程（等价于 posture-guard）。
    Guard(posture_guard::cli::GuardArgs),
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Host(args) => posture_host::cli::run(args),
        Command::Flow { command } => posture_flow::cli::run(command),
        Command::Guard(args) => posture_guard::cli::run(args),
    }
}
