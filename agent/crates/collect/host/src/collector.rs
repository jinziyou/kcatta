//! Pluggable interface for inventory **sources**.
//!
//! Detect engines (malware / posture / secrets) are orchestrated via
//! [`crate::detect_phase`], not via this trait.

use std::path::{Path, PathBuf};

use agent_contract::{Asset, HostInfo};

/// Windows package collection scope (ignored on Linux).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WindowsPackageProfile {
    /// Uninstall, WinGet, CBS, AppX, Chocolatey, and language packages.
    #[default]
    Full,
    /// Skip CBS (Component Based Servicing) — can be thousands of update entries.
    Apps,
}

impl WindowsPackageProfile {
    /// Parse CLI values (`full`, `apps`).
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "apps" => Ok(Self::Apps),
            other => anyhow::bail!("unknown windows package profile {other:?} (use full|apps)"),
        }
    }
}

/// Mutable state shared across sources in one scan cycle.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Filesystem root of the scan target (mounted image, chroot, or `/`).
    pub scan_root: PathBuf,
    /// Set by the host collector; required by asset collectors.
    pub host_id: Option<String>,
    /// Full host descriptor when the host collector has run.
    pub host: Option<HostInfo>,
    /// Extra project directories (relative to `scan_root`) to scan for
    /// language packages beyond the global install locations, e.g. a venv or
    /// a project's `node_modules`. Empty by default.
    pub project_roots: Vec<PathBuf>,
    /// Whether package collection auto-discovers language-project roots under
    /// ``scan_root``. Explicit ``project_roots`` remain usable when disabled.
    pub project_discovery: bool,
    /// Windows-only: whether to include CBS update packages (default [`WindowsPackageProfile::Full`]).
    pub windows_packages: WindowsPackageProfile,
}

impl ScanContext {
    /// Create context rooted at `scan_root` with no host populated yet.
    pub fn at(scan_root: impl AsRef<Path>) -> Self {
        Self {
            scan_root: scan_root.as_ref().to_path_buf(),
            host_id: None,
            host: None,
            project_roots: Vec::new(),
            project_discovery: true,
            windows_packages: WindowsPackageProfile::default(),
        }
    }

    /// Builder: set extra project roots to scan for language packages.
    #[must_use]
    pub fn with_project_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.project_roots = roots;
        self
    }

    /// Builder: enable or disable automatic language-project root discovery.
    #[must_use]
    pub fn with_project_discovery(mut self, enabled: bool) -> Self {
        self.project_discovery = enabled;
        self
    }

    /// Builder: Windows package scope (CBS on/off).
    #[must_use]
    pub fn with_windows_packages(mut self, profile: WindowsPackageProfile) -> Self {
        self.windows_packages = profile;
        self
    }
}

impl Default for ScanContext {
    fn default() -> Self {
        Self::at("/")
    }
}

/// One result returned by a legacy [`Collector`].
///
/// This type and the single-result [`Collector::collect`] signature are kept
/// intact so existing out-of-tree collectors continue to compile unchanged.
#[derive(Debug, Clone)]
pub enum CollectorOutput {
    /// Host descriptor (from the host collector).
    Host(HostInfo),
    /// Batch of assets (packages, services, …).
    Assets(Vec<Asset>),
}

/// Legacy, category-oriented inventory collector.
///
/// Collectors run in plan order and return exactly one result. New code that
/// models a physical information origin should implement [`Source`] instead.
pub trait Collector: Send + Sync {
    /// Stable identifier for logging and diagnostics.
    fn id(&self) -> &'static str;
    /// Run one collection step, reading/writing `ctx` as needed.
    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput>;
}

/// One result emitted by a [`Source`].
///
/// A source may emit several results in one invocation. This lets a source
/// mirror the boundary of the system it reads (for example, the filesystem)
/// while preserving the existing host + asset-batch wire model.
#[derive(Debug, Clone)]
pub enum SourceResult {
    /// Host descriptor.
    Host(HostInfo),
    /// Batch of assets (packages, services, …).
    Assets(Vec<Asset>),
}

/// A physical or logical origin of inventory information.
///
/// Sources run in plan order. A source may return any number of results; empty
/// asset batches can simply be omitted. Across the complete scan plan, exactly
/// one host result must precede every asset result.
pub trait Source: Send + Sync {
    /// Stable identifier for logging and diagnostics.
    fn id(&self) -> &'static str;
    /// Read this source and return its result batches in deterministic order.
    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<Vec<SourceResult>>;
}

impl From<CollectorOutput> for SourceResult {
    fn from(output: CollectorOutput) -> Self {
        match output {
            CollectorOutput::Host(host) => Self::Host(host),
            CollectorOutput::Assets(assets) => Self::Assets(assets),
        }
    }
}

/// Adapt every legacy collector to the multi-result source interface.
///
/// The adapter produces a one-element vector, preserving the legacy
/// collector's exact behavior while allowing old collector plans to be passed
/// to the source-oriented scan runner.
impl<T> Source for T
where
    T: Collector + ?Sized,
{
    fn id(&self) -> &'static str {
        Collector::id(self)
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<Vec<SourceResult>> {
        Collector::collect(self, ctx).map(|result| vec![result.into()])
    }
}

#[cfg(test)]
mod tests {
    use super::{Collector, CollectorOutput, ScanContext};

    struct ExternalStyleCollector;

    impl Collector for ExternalStyleCollector {
        fn id(&self) -> &'static str {
            "external-style"
        }

        fn collect(&self, _ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
            Ok(CollectorOutput::Assets(Vec::new()))
        }
    }

    #[test]
    fn legacy_method_call_still_returns_one_collector_output() {
        let mut ctx = ScanContext::default();
        let output: CollectorOutput = ExternalStyleCollector.collect(&mut ctx).unwrap();

        assert!(matches!(output, CollectorOutput::Assets(assets) if assets.is_empty()));
    }
}
