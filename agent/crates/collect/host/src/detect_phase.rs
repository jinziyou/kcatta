//! Detect phase for host scans (orchestration, not collect).
//!
//! Collectors under [`crate::default_collectors`] produce **assets** only.
//! Engines in `agent-detect*` produce findings; this module runs them and
//! returns [`Vulnerability`] rows to merge into an [`AssetReport`] via
//! [`crate::run_scan_with_detect`] or a direct [`run_detect_at`] call.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_contract::Vulnerability;
use agent_detect::{posture, secrets};
use agent_detect_malware::{
    default_workers, detection_to_vulnerability, run_scan, MalwareOptions, SignatureSet,
};

/// Options for the host detect phase (malware / posture / secrets).
#[derive(Debug, Clone, Default)]
pub struct DetectOpts {
    /// When `Some`, run the malware signature engine with these options.
    pub malware: Option<MalwareDetectOpts>,
    /// Run sshd / shadow / SUID posture checks.
    pub posture: bool,
    /// Run secret-leak scan (opt-in; walks small files).
    pub secrets: bool,
}

/// Malware-engine knobs for [`DetectOpts::malware`].
#[derive(Debug, Clone)]
pub struct MalwareDetectOpts {
    /// Parallel scan workers.
    pub workers: usize,
    /// Extra signatures JSON path (extends the built-in set).
    pub signatures_path: Option<PathBuf>,
    /// Also scan dependency/build/VCS trees pruned by default.
    pub scan_all_dirs: bool,
}

impl Default for MalwareDetectOpts {
    fn default() -> Self {
        Self {
            workers: default_workers(),
            signatures_path: None,
            scan_all_dirs: false,
        }
    }
}

impl DetectOpts {
    /// True when at least one detect engine is enabled.
    #[must_use]
    pub fn any_enabled(&self) -> bool {
        self.malware.is_some() || self.posture || self.secrets
    }
}

/// Run enabled detect engines against `scan_root`, attributing findings to `host_id`.
pub fn run_detect_at(
    scan_root: impl AsRef<Path>,
    host_id: &str,
    opts: &DetectOpts,
) -> anyhow::Result<Vec<Vulnerability>> {
    let scan_root = scan_root.as_ref();
    let mut vulnerabilities = Vec::new();

    if let Some(malware) = &opts.malware {
        vulnerabilities.extend(run_malware_detect(scan_root, host_id, malware)?);
    }
    if opts.posture {
        vulnerabilities.extend(posture::collect(scan_root, host_id));
    }
    if opts.secrets {
        vulnerabilities.extend(secrets::collect(scan_root, host_id));
    }

    Ok(vulnerabilities)
}

/// Signature malware scan → host-attributed vulnerabilities.
pub(crate) fn run_malware_detect(
    scan_root: &Path,
    host_id: &str,
    opts: &MalwareDetectOpts,
) -> anyhow::Result<Vec<Vulnerability>> {
    let mut signatures = SignatureSet::builtin();
    if let Some(path) = &opts.signatures_path {
        signatures.load_extra(path)?;
    }

    let mut options = MalwareOptions::new(scan_root);
    options.signatures = Arc::new(signatures);
    options.workers = opts.workers.max(1);
    if opts.scan_all_dirs {
        options.skip_dirs = Vec::new();
    }

    let result = run_scan(&options)?;
    Ok(result
        .detections
        .iter()
        .map(|d| detection_to_vulnerability(d, host_id))
        .collect())
}
