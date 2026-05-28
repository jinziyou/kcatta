//! Static filesystem scan API: mount root + target → per-asset JSON files.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use scanner_contract::Asset;
use scanner_runtime::{Collector, CollectorOutput, ScanContext};

use crate::collectors::{HostCollector, PackagesCollector, PortsCollector};

/// What to extract from the mounted tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanTarget {
    /// `host.json` only.
    #[default]
    Host,
    /// `packages.json` only.
    Packages,
    /// `ports.json` only.
    Ports,
    /// `host.json`, `packages.json`, and `ports.json`.
    All,
}

impl ScanTarget {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "packages" | "package" => Ok(Self::Packages),
            "ports" | "port" => Ok(Self::Ports),
            "all" => Ok(Self::All),
            other => anyhow::bail!("unknown scan target {other:?} (use host|packages|ports|all)"),
        }
    }

    fn targets(self) -> &'static [ScanTarget] {
        match self {
            Self::Host => &[Self::Host],
            Self::Packages => &[Self::Packages],
            Self::Ports => &[Self::Ports],
            Self::All => &[Self::Host, Self::Packages, Self::Ports],
        }
    }
}

/// Static scan parameters.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Mounted filesystem root (default `/`).
    pub root: PathBuf,
    /// Scan object (default [`ScanTarget::Host`]).
    pub target: ScanTarget,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            target: ScanTarget::Host,
        }
    }
}

/// Paths of JSON files written by [`run_static_scan`].
#[derive(Debug, Clone, Default)]
pub struct ScanOutput {
    pub host: Option<PathBuf>,
    pub packages: Option<PathBuf>,
    pub ports: Option<PathBuf>,
}

/// Scan `options.root` and write one JSON file per asset category under `output_dir`.
pub fn run_static_scan(options: &ScanOptions, output_dir: &Path) -> anyhow::Result<ScanOutput> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create output dir {}", output_dir.display()))?;

    let mut ctx = ScanContext::at(&options.root);
    let mut out = ScanOutput::default();

    for &target in options.target.targets() {
        match target {
            ScanTarget::Host => {
                ensure_host(&mut ctx)?;
                let path = output_dir.join("host.json");
                write_json(&path, ctx.host.as_ref().expect("host set"))?;
                out.host = Some(path);
            }
            ScanTarget::Packages => {
                ensure_host(&mut ctx)?;
                let assets = PackagesCollector.collect(&mut ctx)?;
                let packages = assets_into_packages(assets)?;
                let path = output_dir.join("packages.json");
                write_json(&path, &packages)?;
                out.packages = Some(path);
            }
            ScanTarget::Ports => {
                ensure_host(&mut ctx)?;
                let assets = PortsCollector.collect(&mut ctx)?;
                let ports = assets_into_ports(assets)?;
                let path = output_dir.join("ports.json");
                write_json(&path, &ports)?;
                out.ports = Some(path);
            }
            ScanTarget::All => unreachable!("expanded above"),
        }
    }

    Ok(out)
}

fn ensure_host(ctx: &mut ScanContext) -> anyhow::Result<()> {
    if ctx.host.is_some() {
        return Ok(());
    }
    match HostCollector.collect(ctx)? {
        CollectorOutput::Host(host) => {
            ctx.host_id = Some(host.host_id.clone());
            ctx.host = Some(host);
            Ok(())
        }
        _ => anyhow::bail!("host collector returned unexpected output"),
    }
}

fn assets_into_packages(output: CollectorOutput) -> anyhow::Result<Vec<Asset>> {
    match output {
        CollectorOutput::Assets(v) => Ok(v),
        _ => anyhow::bail!("packages collector returned unexpected output"),
    }
}

fn assets_into_ports(output: CollectorOutput) -> anyhow::Result<Vec<Asset>> {
    match output {
        CollectorOutput::Assets(v) => Ok(v),
        _ => anyhow::bail!("ports collector returned unexpected output"),
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
    let file = fs::File::create(path)
        .with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(file, value)
        .with_context(|| format!("write JSON to {}", path.display()))?;
    Ok(())
}
