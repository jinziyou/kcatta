//! Windows OS identity from the SOFTWARE registry hive.

use super::registry::{HiveKind, RegistryAccess};

const CURRENT_VERSION: &str = r"Microsoft\Windows NT\CurrentVersion";

/// Windows release metadata (registry-backed, analogous to Linux `os-release`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsDistro {
    /// `ProductName`, e.g. `Windows 10 Pro`.
    pub product_name: Option<String>,
    /// `DisplayVersion`, e.g. `22H2` or `Windows 11`.
    pub display_version: Option<String>,
    /// `CurrentVersion`, e.g. `6.3`.
    pub current_version: Option<String>,
    /// `CurrentBuild` / `CurrentBuildNumber`.
    pub current_build: Option<String>,
    /// `UBR` (update build revision), appended to kernel string.
    pub ubr: Option<String>,
    /// `EditionID`, e.g. `Professional`.
    pub edition_id: Option<String>,
}

impl WindowsDistro {
    /// Read Windows release metadata via `reg`.
    pub fn read(reg: &RegistryAccess) -> Self {
        Self {
            product_name: reg.get_string(HiveKind::Software, CURRENT_VERSION, "ProductName"),
            display_version: reg.get_string(HiveKind::Software, CURRENT_VERSION, "DisplayVersion"),
            current_version: reg.get_string(HiveKind::Software, CURRENT_VERSION, "CurrentVersion"),
            current_build: reg
                .get_string(HiveKind::Software, CURRENT_VERSION, "CurrentBuild")
                .or_else(|| {
                    reg.get_string(HiveKind::Software, CURRENT_VERSION, "CurrentBuildNumber")
                }),
            ubr: reg.get_string(HiveKind::Software, CURRENT_VERSION, "UBR"),
            edition_id: reg.get_string(HiveKind::Software, CURRENT_VERSION, "EditionID"),
        }
    }

    /// Human-readable OS string (Linux `PRETTY_NAME` equivalent).
    pub fn pretty_os(&self) -> String {
        let mut parts = Vec::new();
        if let Some(name) = &self.product_name {
            parts.push(name.clone());
        }
        if let Some(display) = &self.display_version {
            if parts
                .first()
                .is_none_or(|n| !n.contains(display.as_str()))
            {
                parts.push(display.clone());
            }
        }
        if let Some(edition) = &self.edition_id {
            if parts
                .first()
                .is_none_or(|n| !n.to_ascii_lowercase().contains(&edition.to_ascii_lowercase()))
            {
                parts.push(edition.clone());
            }
        }
        if parts.is_empty() {
            "Windows".to_string()
        } else {
            parts.join(" ")
        }
    }

    /// Kernel / build string (Linux `proc/version` analogue).
    pub fn kernel_string(&self) -> Option<String> {
        let build = self.current_build.as_ref()?;
        Some(match self.ubr.as_deref() {
            Some(ubr) if !ubr.is_empty() => format!("{build}.{ubr}"),
            _ => build.clone(),
        })
    }

    /// Major Windows release for inventory tagging, e.g. `10`, `11`.
    pub fn release_major(&self) -> Option<String> {
        if let Some(build) = self.current_build.as_ref() {
            if let Ok(n) = build.parse::<u32>() {
                if n >= 22000 {
                    return Some("11".to_string());
                }
                if n >= 10240 {
                    return Some("10".to_string());
                }
                if n >= 9600 {
                    return Some("8.1".to_string());
                }
                if n >= 9200 {
                    return Some("8".to_string());
                }
            }
        }
        self.display_version
            .as_ref()
            .and_then(|d| {
                if d.contains("11") {
                    Some("11".to_string())
                } else if d.contains("10") {
                    Some("10".to_string())
                } else {
                    None
                }
            })
            .or_else(|| self.current_version.clone())
    }

    /// OSV-style ecosystem for Windows inventory, e.g. `Windows:11`.
    pub fn osv_ecosystem(&self) -> Option<String> {
        self.release_major()
            .map(|major| format!("Windows:{major}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_build_to_windows_11() {
        let distro = WindowsDistro {
            product_name: Some("Windows 11 Pro".to_string()),
            current_build: Some("22631".to_string()),
            ubr: Some("4037".to_string()),
            ..Default::default()
        };
        assert_eq!(distro.release_major().as_deref(), Some("11"));
        assert_eq!(distro.osv_ecosystem().as_deref(), Some("Windows:11"));
        assert_eq!(distro.kernel_string().as_deref(), Some("22631.4037"));
    }

    #[test]
    fn pretty_os_joins_fields() {
        let distro = WindowsDistro {
            product_name: Some("Windows 10 Pro".to_string()),
            display_version: Some("22H2".to_string()),
            edition_id: Some("Professional".to_string()),
            ..Default::default()
        };
        assert!(distro.pretty_os().contains("Windows 10 Pro"));
        assert!(distro.pretty_os().contains("22H2"));
    }
}
