//! Pluggable collector interface implemented by this crate's host collectors
//! (the asset collectors and the built-in `MalwareCollector`, enabled at
//! runtime via `--malware`).

use std::path::{Path, PathBuf};

use agent_contract::{Asset, HostInfo, Vulnerability};

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

/// Mutable state shared across collectors in one scan cycle.
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
            windows_packages: WindowsPackageProfile::default(),
        }
    }

    /// Builder: set extra project roots to scan for language packages.
    #[must_use]
    pub fn with_project_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.project_roots = roots;
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

/// What a collector returns after one invocation.
#[derive(Debug, Clone)]
pub enum CollectorOutput {
    /// Host descriptor (from the host collector).
    Host(HostInfo),
    /// Batch of assets (packages, services, …).
    Assets(Vec<Asset>),
    /// Batch of findings (e.g. `posture-malware` hits).
    Vulnerabilities(Vec<Vulnerability>),
}

/// Collectors implement this trait; the `agent host` command (or tests) assemble
/// them into a plan and pass it to [`crate::run_scan`].
///
/// Collectors run in plan order. A host collector should run first so
/// `ScanContext::host_id` is set for asset collectors.
pub trait Collector: Send + Sync {
    /// Stable identifier for logging and diagnostics.
    fn id(&self) -> &'static str;
    /// Run one collection step, reading/writing `ctx` as needed.
    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput>;
}
