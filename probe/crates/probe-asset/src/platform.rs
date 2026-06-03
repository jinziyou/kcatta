//! OS family detection for a scan root (Linux mount, Windows disk, or live host).

use std::path::{Path, PathBuf};

/// Target operating system inferred from the scan root layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    /// FHS-style tree (`etc/os-release`, `var/lib/dpkg`, …).
    Linux,
    /// Windows installation (`Windows/System32/…`).
    Windows,
}

/// Detect the OS family from paths present under `scan_root`.
///
/// Windows is detected when `Windows/System32/ntoskrnl.exe` or
/// `Windows/System32/config/SYSTEM` exists (case-insensitive on Linux mounts).
/// Otherwise Linux is assumed for backward compatibility.
pub fn detect(scan_root: &Path) -> OsFamily {
    if windows_marker(scan_root).is_some() {
        OsFamily::Windows
    } else {
        OsFamily::Linux
    }
}

/// Default scan root for the current host OS.
pub fn default_scan_root() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("SystemDrive")
            .map(|d| PathBuf::from(format!("{d}\\")))
            .unwrap_or_else(|_| PathBuf::from(r"C:\"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/")
    }
}

/// Whether this scan should use the live Windows registry API instead of offline hives.
///
/// Returns `true` when built for Windows and `scan_root` points at the boot volume.
#[cfg(windows)]
pub fn use_live_registry(scan_root: &Path) -> bool {
    if detect(scan_root) != OsFamily::Windows {
        return false;
    }
    let canonical = normalize_root(scan_root);
    let system_drive = std::env::var("SystemDrive")
        .map(|d| PathBuf::from(format!("{d}\\")))
        .unwrap_or_else(|_| PathBuf::from(r"C:\"));
    canonical == normalize_root(&system_drive)
        || canonical == normalize_root(Path::new(r"C:\"))
        || scan_root.as_os_str().is_empty()
        || scan_root == Path::new("/")
}

#[cfg(windows)]
fn normalize_root(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Whether this scan should use the live Windows registry API instead of offline hives.
///
/// Always `false` on non-Windows build targets.
#[cfg(not(windows))]
pub fn use_live_registry(_scan_root: &Path) -> bool {
    false
}

fn windows_marker(scan_root: &Path) -> Option<PathBuf> {
    find_path_case_insensitive(
        scan_root,
        &["Windows", "System32", "ntoskrnl.exe"],
    )
    .or_else(|| {
        find_path_case_insensitive(scan_root, &["Windows", "System32", "config", "SYSTEM"])
    })
}

/// Resolve `components` under `root`, matching each segment case-insensitively.
pub fn find_path_case_insensitive(root: &Path, components: &[&str]) -> Option<PathBuf> {
    let mut current = root.to_path_buf();
    for component in components {
        let entries = std::fs::read_dir(&current).ok()?;
        let mut next = None;
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().eq_ignore_ascii_case(component) {
                next = Some(entry.path());
                break;
            }
        }
        current = next?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_linux_layout() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("etc")).unwrap();
        fs::write(temp.path().join("etc/os-release"), "ID=debian\n").unwrap();
        assert_eq!(detect(temp.path()), OsFamily::Linux);
    }

    #[test]
    fn detects_windows_layout_case_insensitive() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("windows/System32")).unwrap();
        fs::write(temp.path().join("windows/System32/ntoskrnl.exe"), b"").unwrap();
        assert_eq!(detect(temp.path()), OsFamily::Windows);
    }
}
