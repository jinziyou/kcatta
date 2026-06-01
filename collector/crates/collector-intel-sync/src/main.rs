//! collector-intel-sync: download remote IOC feeds to local JSON.
//!
//! Mirrors the offline-friendly refresh model of `form-osv-sync`: sync is an
//! explicit, schedulable step; capture/matching reads the on-disk feed only.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use collector_core::intel::sync::{self, feodo};
use collector_core::ThreatFeed;

#[derive(Debug, Parser)]
#[command(
    name = "collector-intel-sync",
    version,
    about = "Download threat-intel IOC feeds into local JSON for collector-cli --intel"
)]
struct Args {
    /// Feed adapter(s) to sync. Repeatable; outputs are merged when multiple.
    #[arg(long = "source", value_name = "NAME", required = true)]
    sources: Vec<String>,

    /// Output JSON path (default: data/feeds/<source>.json, or merged.json).
    #[arg(long, short)]
    out: Option<PathBuf>,

    /// Override download URL for the `feodo` adapter.
    #[arg(long, default_value = feodo::DEFAULT_URL)]
    feodo_url: String,

    /// HTTP timeout in seconds.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let timeout = Duration::from_secs(args.timeout);

    let mut feeds = Vec::new();
    for source in &args.sources {
        let feed = sync_source(source, &args.feodo_url, timeout)
            .with_context(|| format!("sync source {source}"))?;
        eprintln!("{source}: {} indicator(s)", feed.len());
        feeds.push(feed);
    }

    let (out_path, written) = if feeds.len() == 1 {
        let source = &args.sources[0];
        let path = args.out.clone().unwrap_or_else(|| default_out_path(source));
        let label = feed_source_label(source);
        sync::write_feed(&path, &label, &feeds[0])?;
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

fn sync_source(name: &str, feodo_url: &str, timeout: Duration) -> Result<ThreatFeed> {
    match name {
        "feodo" => {
            let body = http_get(feodo_url, timeout)?;
            feodo::parse_json(&body)
        }
        other => bail!("unknown source {other:?} (supported: feodo)"),
    }
}

fn http_get(url: &str, timeout: Duration) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent("cyber-posture-collector-intel-sync/0.1")
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

    response
        .text()
        .with_context(|| format!("read body from {url}"))
}

fn default_out_path(source: &str) -> PathBuf {
    PathBuf::from(format!("data/feeds/{source}.json"))
}

fn feed_source_label(source: &str) -> String {
    match source {
        "feodo" => feodo::SOURCE.to_string(),
        other => other.to_string(),
    }
}
