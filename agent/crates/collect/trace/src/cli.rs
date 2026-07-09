//! `agent-collect-trace` CLI: subcommands + run, shared by the standalone `agent-collect-trace`
//! binary and the umbrella `agentd flow` subcommand.
//!
//! `capture` only **produces** a [`crate::TraceBatch`] (written to stdout / `--out`)
//! and returns it; uploading is the `agentd` umbrella's job. `intel-sync` downloads
//! IOC feeds to local JSON. Run standalone, `agent-collect-trace` is a pure local
//! collector / feed-syncer.

use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::intel::sync::{self, feodo, sslbl, threatfox};
use crate::{capture_batch, enrich_batch, CaptureConfig, ThreatFeed, TraceBatch};

/// Traffic-detection subcommands (`agent-collect-trace <cmd>` / `agentd flow <cmd>`).
#[derive(Debug, Subcommand)]
pub enum TraceCommand {
    /// Capture one cycle (collect) then optional IOC enrich (detect) → TraceBatch.
    Capture(TraceArgs),
    /// Download threat-intel IOC feeds into local JSON for `capture --intel`.
    IntelSync(IntelSyncArgs),
}

/// Dispatch a [`TraceCommand`]; returns the captured [`TraceBatch`] (for the caller
/// to optionally upload), or `None` for `intel-sync` / `--list-devices`.
pub fn run(command: TraceCommand) -> Result<Option<TraceBatch>> {
    match command {
        TraceCommand::Capture(args) => run_capture_cmd(args),
        TraceCommand::IntelSync(args) => run_intel_sync(args).map(|()| None),
    }
}

// ----------------------------------------------------------------- capture

/// `capture` arguments.
#[derive(Debug, Args)]
pub struct TraceArgs {
    /// Pretty-print the JSON output (default: compact).
    #[arg(long)]
    pretty: bool,

    /// Write JSON to a file instead of stdout.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Threat-intel IOC feed (JSON) to match events against. Defaults to a small
    /// built-in demo feed when omitted. Ignored with `--no-intel`.
    #[arg(long, value_name = "PATH")]
    intel: Option<PathBuf>,

    /// Collect-only: skip IOC enrich (detect phase). Emits raw `TraceBatch.events`
    /// with empty `threat_intel`.
    #[arg(long, conflicts_with = "intel")]
    no_intel: bool,

    /// Use synthetic mock events instead of live capture (default).
    #[arg(long, conflicts_with_all = ["pcap", "net_ebpf"])]
    mock: bool,

    /// Capture live traffic via libpcap (requires the `pcap` feature at build).
    /// Userspace L7 parsing yields JA3 / TLS SNI / DNS.
    #[arg(long, conflicts_with = "mock")]
    pcap: bool,

    /// Capture network flows via the in-kernel eBPF cgroup-skb backend (requires
    /// the `ebpf` feature + CAP_BPF + cgroup-v2). L4-only (no JA3/SNI/DNS);
    /// falls back to pcap/mock when unavailable. This is the network backend,
    /// distinct from `--ebpf` (which adds file/process tracepoint events).
    #[arg(long = "net-ebpf", conflicts_with = "mock")]
    net_ebpf: bool,

    /// Capture network connections from the OS connection table (IP Helper on
    /// Windows / `/proc` on Linux). Requires the `winnet` feature. No admin,
    /// libpcap, or eBPF; 5-tuple TCP connections only (no byte counters). The
    /// Windows network backend.
    #[arg(long, conflicts_with_all = ["mock", "pcap", "net_ebpf"])]
    winnet: bool,

    /// Network interface (`any`, `eth0`, `lo`, ...) for the pcap backend / eBPF pcap fallback.
    #[arg(long, default_value = "any")]
    iface: String,

    /// Capture / flow-accounting window in seconds (pcap and net-ebpf backends).
    #[arg(long, default_value_t = 5)]
    duration: u64,

    /// BPF filter expression (pcap backend / eBPF pcap fallback).
    #[arg(long, default_value = "tcp or udp or icmp")]
    bpf: String,

    /// List libpcap capture devices and exit (requires the `pcap` feature).
    #[cfg(feature = "pcap")]
    #[arg(long)]
    list_devices: bool,

    /// Also run the eBPF tracer (process exec/exit + file opens) and include its
    /// events in the batch. Requires the `ebpf` build feature + CAP_BPF/root.
    #[arg(long)]
    ebpf: bool,

    /// eBPF tracer window in seconds (used with `--ebpf`).
    #[arg(long, default_value_t = 5, requires = "ebpf")]
    ebpf_duration: u64,
}

fn run_capture_cmd(args: TraceArgs) -> Result<Option<TraceBatch>> {
    #[cfg(feature = "pcap")]
    if args.list_devices {
        for name in crate::pcap::list_devices().context("list pcap devices")? {
            println!("{name}");
        }
        return Ok(None);
    }

    let capture_config = build_capture_config(&args)?;
    // Collect then (optional) detect — same two-phase shape as host scans.
    let mut batch = capture_batch(&capture_config).context("running capture")?;
    if !args.no_intel {
        let feed = match &args.intel {
            Some(path) => ThreatFeed::from_json_path(path).context("loading threat-intel feed")?,
            None => ThreatFeed::builtin(),
        };
        enrich_batch(&feed, &mut batch);
    }

    if args.ebpf {
        attach_ebpf(&mut batch, args.ebpf_duration)?;
    }

    write_json(&batch, args.out.as_deref(), args.pretty)?;
    Ok(Some(batch))
}

/// Run the eBPF tracer and fold its process / file events into the batch.
#[cfg(feature = "ebpf")]
fn attach_ebpf(batch: &mut TraceBatch, duration_secs: u64) -> Result<()> {
    let (processes, files) = crate::ebpf::capture(
        &batch.collector_id,
        std::time::Duration::from_secs(duration_secs),
    )
    .context("running eBPF tracer")?;
    batch.process_events = processes;
    batch.file_events = files;
    Ok(())
}

#[cfg(not(feature = "ebpf"))]
fn attach_ebpf(_batch: &mut TraceBatch, _duration_secs: u64) -> Result<()> {
    anyhow::bail!("rebuild with `--features ebpf` to use the eBPF tracer (`--ebpf`)")
}

fn build_capture_config(args: &TraceArgs) -> Result<CaptureConfig> {
    if args.net_ebpf {
        #[cfg(feature = "ebpf")]
        {
            return Ok(CaptureConfig::ebpf(
                args.iface.clone(),
                args.duration,
                args.bpf.clone(),
            ));
        }
        #[cfg(not(feature = "ebpf"))]
        {
            bail!("rebuild with `--features ebpf` to use the eBPF network backend (--net-ebpf)")
        }
    }

    if args.winnet {
        #[cfg(feature = "winnet")]
        {
            return Ok(CaptureConfig::win_net(args.duration));
        }
        #[cfg(not(feature = "winnet"))]
        {
            bail!("rebuild with `--features winnet` to use the connection-table backend (--winnet)")
        }
    }

    if args.mock || !args.pcap {
        return Ok(CaptureConfig::mock());
    }

    #[cfg(feature = "pcap")]
    {
        Ok(CaptureConfig::pcap(
            args.iface.clone(),
            args.duration,
            args.bpf.clone(),
        ))
    }

    #[cfg(not(feature = "pcap"))]
    {
        bail!("rebuild with `--features pcap` to use live capture (--pcap)")
    }
}

// --------------------------------------------------------------- intel-sync

/// `intel-sync` arguments.
#[derive(Debug, Args)]
pub struct IntelSyncArgs {
    /// Feed adapter(s) to sync (`feodo` | `sslbl` | `threatfox`). Repeatable;
    /// outputs are merged (dedup on type+value) when multiple are given.
    #[arg(long = "source", value_name = "NAME", required = true)]
    sources: Vec<String>,

    /// Output JSON path (default: data/feeds/<source>.json, or merged.json).
    #[arg(long, short)]
    out: Option<PathBuf>,

    /// Override download URL for the `feodo` adapter (IP C2 blocklist).
    #[arg(long, default_value = feodo::DEFAULT_URL)]
    feodo_url: String,

    /// Override download URL for the `sslbl` adapter (JA3 fingerprint blacklist).
    #[arg(long, default_value = sslbl::DEFAULT_URL)]
    sslbl_url: String,

    /// Override download URL for the `threatfox` adapter (domain + ip:port IOCs).
    #[arg(long, default_value = threatfox::DEFAULT_URL)]
    threatfox_url: String,

    /// HTTP timeout in seconds.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

fn run_intel_sync(args: IntelSyncArgs) -> Result<()> {
    let timeout = Duration::from_secs(args.timeout);

    let mut feeds = Vec::new();
    for source in &args.sources {
        let feed =
            sync_source(source, &args, timeout).with_context(|| format!("sync source {source}"))?;
        eprintln!("{source}: {} indicator(s)", feed.len());
        feeds.push(feed);
    }

    let (out_path, written) = if feeds.len() == 1 {
        let source = &args.sources[0];
        let path = args.out.clone().unwrap_or_else(|| default_out_path(source));
        sync::write_feed(&path, &feed_source_label(source), &feeds[0])?;
        (path, feeds[0].len())
    } else {
        let merged = sync::merge_feeds(&feeds);
        let path = args
            .out
            .clone()
            .unwrap_or_else(|| PathBuf::from("data/feeds/merged.json"));
        sync::write_feed(&path, "merged", &merged)?;
        (path, merged.len())
    };

    println!("wrote {} indicator(s) to {}", written, out_path.display());
    Ok(())
}

fn sync_source(name: &str, args: &IntelSyncArgs, timeout: Duration) -> Result<ThreatFeed> {
    match name {
        "feodo" => {
            let body = http_get_text(&args.feodo_url, timeout)?;
            feodo::parse_json(&body)
        }
        "sslbl" => {
            let body = http_get_text(&args.sslbl_url, timeout)?;
            sslbl::parse_csv(&body)
        }
        "threatfox" => {
            let body = http_get_text(&args.threatfox_url, timeout)?;
            threatfox::parse_json(&body)
        }
        other => bail!("unknown source {other:?} (supported: feodo, sslbl, threatfox)"),
    }
}

fn default_out_path(source: &str) -> PathBuf {
    PathBuf::from(format!("data/feeds/{source}.json"))
}

fn feed_source_label(source: &str) -> String {
    match source {
        "feodo" => feodo::SOURCE.to_string(),
        "sslbl" => sslbl::SOURCE.to_string(),
        "threatfox" => threatfox::SOURCE.to_string(),
        other => other.to_string(),
    }
}

// ----------------------------------------------------------------- helpers

/// Blocking HTTP GET → body text. Local to the binary (the flow library stays
/// reqwest-free; only `intel-sync` downloads feeds).
fn http_get_text(url: &str, timeout: Duration) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("agent-collect-trace/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build HTTP client")?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("GET {url} failed ({status})");
    }

    // Bound the body: feeds are remote and attacker-influenceable (a hostile or
    // MITM'd mirror could stream an unbounded body and OOM the agent). Reject an
    // over-ceiling Content-Length up front, then read through a capped reader so a
    // chunked / length-lying body is also bounded.
    const MAX_FEED_BYTES: u64 = 64 * 1024 * 1024;
    if let Some(len) = response.content_length() {
        if len > MAX_FEED_BYTES {
            bail!("GET {url}: body too large ({len} bytes > {MAX_FEED_BYTES} cap)");
        }
    }
    let mut buf = Vec::new();
    response
        .take(MAX_FEED_BYTES + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("read body from {url}"))?;
    if buf.len() as u64 > MAX_FEED_BYTES {
        bail!("GET {url}: body exceeded {MAX_FEED_BYTES} byte cap");
    }
    String::from_utf8(buf).with_context(|| format!("decode body from {url} as UTF-8"))
}

/// Serialize `value` as JSON to a file (logging `wrote <path>`) or stdout.
fn write_json<T: Serialize>(value: &T, dest: Option<&Path>, pretty: bool) -> Result<()> {
    let payload = if pretty {
        serde_json::to_vec_pretty(value)?
    } else {
        serde_json::to_vec(value)?
    };
    match dest {
        Some(path) => {
            std::fs::write(path, &payload)
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&payload)?;
            stdout.write_all(b"\n")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap {
        #[command(flatten)]
        args: TraceArgs,
    }

    #[test]
    fn no_intel_conflicts_with_intel_path() {
        assert!(Wrap::try_parse_from(["x", "--no-intel", "--intel", "f.json"]).is_err());
        assert!(Wrap::try_parse_from(["x", "--no-intel"]).is_ok());
    }
}
