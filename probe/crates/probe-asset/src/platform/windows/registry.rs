//! Registry access for Windows scans: offline hive files or live HKLM on Windows.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use nt_hive::{Hive, KeyNode, KeyValueDataType};
use probe_runtime::ScanContext;

use super::paths::config_dir;
use crate::platform;

/// Which on-disk hive backs a registry view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiveKind {
    /// `SOFTWARE` hive (`HKLM\SOFTWARE` when live).
    Software,
    /// `SYSTEM` hive (`HKLM\SYSTEM` when live).
    System,
    /// `SAM` hive (`HKLM\SAM` when live; often requires elevation).
    Sam,
}

/// Unified registry reader for offline and live scans.
pub struct RegistryAccess {
    offline: Option<OfflineHives>,
    live: bool,
}

struct OfflineHives {
    software: Option<Vec<u8>>,
    system: Option<Vec<u8>>,
    sam: Option<Vec<u8>>,
}

impl RegistryAccess {
    /// Open registry access for `ctx` (offline hives and/or live HKLM).
    pub fn open(ctx: &ScanContext) -> Self {
        let live = platform::use_live_registry(&ctx.scan_root);
        let offline = if live { None } else { OfflineHives::open(ctx) };
        Self { offline, live }
    }

    /// Read a string value at `subpath` (backslash-separated, hive-relative).
    pub fn get_string(&self, hive: HiveKind, subpath: &str, value: &str) -> Option<String> {
        if self.live {
            return live_get_string(hive, subpath, value);
        }
        let offline = self.offline.as_ref()?;
        offline.get_string(hive, subpath, value)
    }

    /// List immediate subkey names at `subpath`.
    pub fn list_subkeys(&self, hive: HiveKind, subpath: &str) -> Vec<String> {
        if self.live {
            return live_list_subkeys(hive, subpath);
        }
        self.offline
            .as_ref()
            .map(|o| o.list_subkeys(hive, subpath))
            .unwrap_or_default()
    }

    /// Read all string/DWORD values on a subkey (value name → string).
    pub fn read_values(&self, hive: HiveKind, subpath: &str) -> HashMap<String, String> {
        if self.live {
            return live_read_values(hive, subpath);
        }
        self.offline
            .as_ref()
            .map(|o| o.read_values(hive, subpath))
            .unwrap_or_default()
    }

    /// Read the default value of a subkey as a DWORD (used for SAM user RIDs).
    pub fn get_default_dword(&self, hive: HiveKind, subpath: &str) -> Option<u32> {
        if self.live {
            return live_get_default_dword(hive, subpath);
        }
        self.offline
            .as_ref()
            .and_then(|o| o.get_default_dword(hive, subpath))
    }

    /// Read a `REG_MULTI_SZ` value as a list of strings.
    pub fn get_multi_string(&self, hive: HiveKind, subpath: &str, value: &str) -> Vec<String> {
        if self.live {
            return live_get_multi_string(hive, subpath, value);
        }
        self.offline
            .as_ref()
            .map(|o| o.get_multi_string(hive, subpath, value))
            .unwrap_or_default()
    }
}

impl OfflineHives {
    fn open(ctx: &ScanContext) -> Option<Self> {
        let dir = config_dir(ctx)?;
        Some(Self {
            software: load_hive_bytes(&dir.join("SOFTWARE")),
            system: load_hive_bytes(&dir.join("SYSTEM")),
            sam: load_hive_bytes(&dir.join("SAM")),
        })
    }

    fn hive_bytes(&self, kind: HiveKind) -> Option<&[u8]> {
        match kind {
            HiveKind::Software => self.software.as_deref(),
            HiveKind::System => self.system.as_deref(),
            HiveKind::Sam => self.sam.as_deref(),
        }
    }

    fn get_string(&self, hive: HiveKind, subpath: &str, value: &str) -> Option<String> {
        self.with_key(hive, subpath, |key| read_key_string(&key, value))?
    }

    fn list_subkeys(&self, hive: HiveKind, subpath: &str) -> Vec<String> {
        self.with_key(hive, subpath, |key| {
            let Some(subkeys) = key.subkeys() else {
                return Vec::new();
            };
            let Ok(iter) = subkeys else {
                return Vec::new();
            };
            iter.filter_map(|sk| sk.ok()?.name().ok().map(|n| n.to_string()))
                .collect()
        })
        .unwrap_or_default()
    }

    fn read_values(&self, hive: HiveKind, subpath: &str) -> HashMap<String, String> {
        self.with_key(hive, subpath, |key| {
            let Some(values) = key.values() else {
                return HashMap::new();
            };
            let Ok(iter) = values else {
                return HashMap::new();
            };
            let mut out = HashMap::new();
            for value in iter.flatten() {
                let Ok(name) = value.name() else {
                    continue;
                };
                let name = if name.is_empty() {
                    "(default)".to_string()
                } else {
                    name.to_string()
                };
                if let Ok(data_type) = value.data_type() {
                    match data_type {
                        KeyValueDataType::RegSZ | KeyValueDataType::RegExpandSZ => {
                            if let Ok(text) = value.string_data() {
                                out.insert(name, text.to_string());
                            }
                        }
                        KeyValueDataType::RegDWord | KeyValueDataType::RegDWordBigEndian => {
                            if let Ok(n) = value.dword_data() {
                                out.insert(name, n.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            out
        })
        .unwrap_or_default()
    }

    fn get_default_dword(&self, hive: HiveKind, subpath: &str) -> Option<u32> {
        self.with_key(hive, subpath, |key| read_key_default_dword(&key))?
    }

    fn get_multi_string(&self, hive: HiveKind, subpath: &str, value: &str) -> Vec<String> {
        self.with_key(hive, subpath, |key| read_key_multi_string(&key, value))
            .unwrap_or_default()
    }

    fn with_key<R>(
        &self,
        hive: HiveKind,
        subpath: &str,
        f: impl FnOnce(KeyNode<'_, &[u8]>) -> R,
    ) -> Option<R> {
        let bytes = self.hive_bytes(hive)?;
        let hive = Hive::new(bytes).ok()?;
        let root = hive.root_key_node().ok()?;
        let key = if subpath.is_empty() {
            root
        } else {
            root.subpath(subpath).and_then(|r| r.ok())?
        };
        Some(f(key))
    }
}

fn load_hive_bytes(path: &Path) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

fn read_key_string(key: &KeyNode<'_, &[u8]>, value: &str) -> Option<String> {
    let value = key.value(value)?.ok()?;
    match value.data_type().ok()? {
        KeyValueDataType::RegSZ | KeyValueDataType::RegExpandSZ => {
            value.string_data().ok().map(|s| s.to_string())
        }
        KeyValueDataType::RegDWord | KeyValueDataType::RegDWordBigEndian => {
            value.dword_data().ok().map(|n| n.to_string())
        }
        _ => None,
    }
}

fn read_key_default_dword(key: &KeyNode<'_, &[u8]>) -> Option<u32> {
    let value = key.value("")?.ok()?;
    value.dword_data().ok()
}

fn read_key_multi_string(key: &KeyNode<'_, &[u8]>, name: &str) -> Vec<String> {
    let Some(result) = key.value(name) else {
        return Vec::new();
    };
    let Ok(value) = result else {
        return Vec::new();
    };
    if value.data_type().ok() != Some(KeyValueDataType::RegMultiSZ) {
        return Vec::new();
    }
    let Ok(iter) = value.multi_string_data() else {
        return Vec::new();
    };
    iter.filter_map(|s| s.ok().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(windows)]
fn live_hklm_subpath(hive: HiveKind, subpath: &str) -> String {
    let prefix = match hive {
        HiveKind::Software => "SOFTWARE",
        HiveKind::System => "SYSTEM",
        HiveKind::Sam => "SAM",
    };
    if subpath.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}\\{subpath}")
    }
}

#[cfg(windows)]
fn live_get_string(hive: HiveKind, subpath: &str, value: &str) -> Option<String> {
    use winreg::RegKey;

    let path = live_hklm_subpath(hive, subpath);
    let key = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(&path)
        .ok()?;
    key.get_value(value).ok()
}

#[cfg(windows)]
fn live_get_default_dword(hive: HiveKind, subpath: &str) -> Option<u32> {
    use winreg::RegKey;

    let path = live_hklm_subpath(hive, subpath);
    let key = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(&path)
        .ok()?;
    key.get_value("").ok()
}

#[cfg(windows)]
fn live_get_multi_string(hive: HiveKind, subpath: &str, value: &str) -> Vec<String> {
    use winreg::enums::REG_MULTI_SZ;
    use winreg::RegKey;

    let path = live_hklm_subpath(hive, subpath);
    let key = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(&path)
        .ok();
    let Some(key) = key else {
        return Vec::new();
    };
    let Ok(raw) = key.get_raw_value(value) else {
        return Vec::new();
    };
    if raw.vtype != REG_MULTI_SZ {
        return Vec::new();
    }
    decode_utf16_null_list(&raw.bytes)
}

#[cfg(windows)]
fn decode_utf16_null_list(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 {
            if i > start {
                let u16s: Vec<u16> = bytes[start..i]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                if let Ok(text) = String::from_utf16(&u16s) {
                    let text = text.trim().to_string();
                    if !text.is_empty() {
                        strings.push(text);
                    }
                }
            }
            start = i + 2;
        }
        i += 2;
    }
    strings
}

#[cfg(windows)]
fn live_list_subkeys(hive: HiveKind, subpath: &str) -> Vec<String> {
    use winreg::RegKey;

    let path = live_hklm_subpath(hive, subpath);
    let key = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(&path)
        .ok();
    let Some(key) = key else {
        return Vec::new();
    };
    key.enum_keys().filter_map(Result::ok).collect()
}

#[cfg(windows)]
fn live_read_values(hive: HiveKind, subpath: &str) -> HashMap<String, String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let path = live_hklm_subpath(hive, subpath);
    let key = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(&path).ok();
    let Some(key) = key else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for item in key.enum_values().filter_map(Result::ok) {
        let (name, value) = item;
        let text = match value {
            winreg::RegValue {
                vtype: REG_SZ | REG_EXPAND_SZ,
                bytes,
            } => String::from_utf8_lossy(&bytes)
                .trim_end_matches('\0')
                .to_string(),
            winreg::RegValue {
                vtype: REG_DWORD,
                bytes,
            } => {
                if bytes.len() >= 4 {
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()
                } else {
                    continue;
                }
            }
            _ => continue,
        };
        let name = if name.is_empty() {
            "(default)".to_string()
        } else {
            name
        };
        out.insert(name, text);
    }
    out
}

#[cfg(not(windows))]
fn live_get_multi_string(_hive: HiveKind, _subpath: &str, _value: &str) -> Vec<String> {
    Vec::new()
}

#[cfg(not(windows))]
fn live_get_default_dword(_hive: HiveKind, _subpath: &str) -> Option<u32> {
    None
}

#[cfg(not(windows))]
fn live_get_string(_hive: HiveKind, _subpath: &str, _value: &str) -> Option<String> {
    None
}

#[cfg(not(windows))]
fn live_list_subkeys(_hive: HiveKind, _subpath: &str) -> Vec<String> {
    Vec::new()
}

#[cfg(not(windows))]
fn live_read_values(_hive: HiveKind, _subpath: &str) -> HashMap<String, String> {
    HashMap::new()
}

/// Pick the control set prefix present in the SYSTEM hive (`ControlSet001`, …).
pub fn control_set_prefix(reg: &RegistryAccess) -> &'static str {
    for candidate in ["ControlSet001", "ControlSet002", "CurrentControlSet"] {
        if reg
            .get_string(
                HiveKind::System,
                &format!("{candidate}\\Control\\ComputerName"),
                "ComputerName",
            )
            .is_some()
            || !reg
                .list_subkeys(HiveKind::System, &format!("{candidate}\\Services"))
                .is_empty()
        {
            return candidate;
        }
    }
    "ControlSet001"
}
