//! Host detection stage orchestration.
//!
//! This module owns the transition from a collected host snapshot (represented
//! by its filesystem root and host id) to security findings. Keeping this code
//! in `agent-detect` makes the SOC stage boundary explicit: collect discovers
//! inventory, detect produces [`Vulnerability`] rows, and a composition layer
//! decides how to assemble the final report.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_contract::Vulnerability;
use agent_detect_malware::{
    default_workers, detection_to_vulnerability, run_scan, MalwareOptions, SignatureSet,
};

use crate::{posture, secrets};

/// Options for the host detection stage (malware / posture / secrets).
#[derive(Debug, Clone, Default)]
pub struct DetectOptions {
    /// When `Some`, run the malware signature engine with these options.
    pub malware: Option<MalwareDetectOptions>,
    /// Run sshd / shadow / SUID posture checks.
    pub posture: bool,
    /// Run secret-leak detection (opt-in; walks small files).
    pub secrets: bool,
}

/// Malware-engine settings used by [`DetectOptions::malware`].
#[derive(Debug, Clone)]
pub struct MalwareDetectOptions {
    /// Parallel scan workers.
    pub workers: usize,
    /// Extra signatures JSON path (extends the built-in set).
    pub signatures_path: Option<PathBuf>,
    /// Also scan dependency/build/VCS trees pruned by default.
    pub scan_all_dirs: bool,
}

impl Default for MalwareDetectOptions {
    fn default() -> Self {
        Self {
            workers: default_workers(),
            signatures_path: None,
            scan_all_dirs: false,
        }
    }
}

impl DetectOptions {
    /// Whether at least one host detector is enabled.
    #[must_use]
    pub fn any_enabled(&self) -> bool {
        self.malware.is_some() || self.posture || self.secrets
    }
}

/// Run enabled host detectors against `scan_root`.
///
/// Every returned finding is attributed to `host_id`. The function never
/// mutates an [`agent_contract::AssetReport`]; report assembly belongs to the
/// runtime/composition layer that called collect and detect.
pub fn detect(
    scan_root: impl AsRef<Path>,
    host_id: &str,
    options: &DetectOptions,
) -> anyhow::Result<Vec<Vulnerability>> {
    let scan_root = scan_root.as_ref();
    let mut vulnerabilities = Vec::new();

    if let Some(malware) = &options.malware {
        vulnerabilities.extend(detect_malware(scan_root, host_id, malware)?);
    }
    if options.posture {
        vulnerabilities.extend(posture::collect(scan_root, host_id));
    }
    if options.secrets {
        vulnerabilities.extend(secrets::collect(scan_root, host_id));
    }

    for vulnerability in &mut vulnerabilities {
        vulnerability.normalize_wire_fields()?;
    }

    Ok(vulnerabilities)
}

fn detect_malware(
    scan_root: &Path,
    host_id: &str,
    options: &MalwareDetectOptions,
) -> anyhow::Result<Vec<Vulnerability>> {
    let mut signatures = SignatureSet::builtin();
    if let Some(path) = &options.signatures_path {
        signatures.load_extra(path)?;
    }

    let mut malware = MalwareOptions::new(scan_root);
    malware.signatures = Arc::new(signatures);
    malware.workers = options.workers.max(1);
    if options.scan_all_dirs {
        malware.skip_dirs = Vec::new();
    }

    let result = run_scan(&malware)?;
    Ok(result
        .detections
        .iter()
        .map(|detection| detection_to_vulnerability(detection, host_id))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn empty_options_produce_no_findings() {
        let root = tempfile::tempdir().unwrap();
        let findings = detect(root.path(), "host-1", &DetectOptions::default()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn posture_findings_are_host_attributed() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("etc/ssh")).unwrap();
        fs::write(
            root.path().join("etc/ssh/sshd_config"),
            "PermitRootLogin yes\n",
        )
        .unwrap();

        let findings = detect(
            root.path(),
            "host-stage",
            &DetectOptions {
                posture: true,
                ..DetectOptions::default()
            },
        )
        .unwrap();

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .all(|finding| finding.affected_asset_id == "host-stage"));
    }
}
