//! Fixed-path SSH credential sources for Linux mounts.

use base64::Engine;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::ScanContext;
use agent_contract::{Asset, Credential, CredentialKind};

use crate::root::join_root;
use crate::walk::handlers::ssh_home;

const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
const MAX_AUTHORIZED_KEYS_BYTES: u64 = 256 * 1024;

/// SSH credentials as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let mut out = Vec::new();
    scan_ssh_dir(ctx, &join_root(ctx, "etc/ssh"), None, &mut out);
    scan_authorized_keys(
        ctx,
        &join_root(ctx, "root/.ssh/authorized_keys"),
        Some("root"),
        &mut out,
    );
    ssh_home::scan_linux_homes(ctx, &mut out);
    out.sort_by(|a, b| credential_fingerprint(a).cmp(credential_fingerprint(b)));
    out
}

fn credential_fingerprint(asset: &Asset) -> &str {
    match asset {
        Asset::Credential(c) => &c.fingerprint,
        _ => "",
    }
}

pub(crate) fn scan_ssh_dir(
    ctx: &ScanContext,
    dir: &Path,
    owner: Option<&str>,
    out: &mut Vec<Asset>,
) {
    if !dir.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name == "authorized_keys" || name.ends_with("_key") {
            continue;
        }
        if !name.ends_with(".pub") {
            continue;
        }
        ingest_key_file(ctx, &path, owner, out);
    }
}

pub(crate) fn scan_authorized_keys(
    ctx: &ScanContext,
    path: &Path,
    owner: Option<&str>,
    out: &mut Vec<Asset>,
) {
    if !path.is_file() {
        return;
    }
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    if meta.len() > MAX_AUTHORIZED_KEYS_BYTES {
        return;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let rel = rel_path(ctx, path);
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((_, key_b64)) = parse_key_line(line) else {
            continue;
        };
        let Some(blob) = decode_openssh_blob(key_b64) else {
            continue;
        };
        let fingerprint = ssh_fingerprint(&blob);
        out.push(Asset::Credential(Credential {
            asset_id: format!("cred-{fingerprint}"),
            parent_asset_id: None,
            credential_kind: CredentialKind::SshKey,
            fingerprint,
            path: Some(format!("{rel}#{idx}")),
            owner: owner.map(str::to_string),
        }));
    }
}

fn ingest_key_file(ctx: &ScanContext, path: &Path, owner: Option<&str>, out: &mut Vec<Asset>) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    if meta.len() > MAX_KEY_FILE_BYTES {
        return;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let Some(line) = text.lines().find(|l| !l.trim().is_empty()) else {
        return;
    };
    let Some((_, key_b64)) = parse_key_line(line.trim()) else {
        return;
    };
    let Some(blob) = decode_openssh_blob(key_b64) else {
        return;
    };
    let fingerprint = ssh_fingerprint(&blob);
    out.push(Asset::Credential(Credential {
        asset_id: format!("cred-{fingerprint}"),
        parent_asset_id: None,
        credential_kind: CredentialKind::SshKey,
        fingerprint,
        path: Some(rel_path(ctx, path)),
        owner: owner.map(str::to_string),
    }));
}

fn rel_path(ctx: &ScanContext, path: &Path) -> String {
    path.strip_prefix(&ctx.scan_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn parse_key_line(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.split_whitespace();
    let typ = parts.next()?;
    if typ == "command" || typ.starts_with("from=") {
        return None;
    }
    if !typ.starts_with("ssh-") && !typ.starts_with("ecdsa-") {
        return None;
    }
    let key_b64 = parts.next()?;
    Some((typ, key_b64))
}

fn decode_openssh_blob(b64: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

fn ssh_fingerprint(key_blob: &[u8]) -> String {
    let digest = sha256(key_blob);
    let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    let trimmed = b64.trim_end_matches('=');
    format!("SHA256:{trimmed}")
}

/// SHA-256 via the `sha2` crate (was a ~120-line hand-rolled implementation —
/// unnecessary attack surface for a security tool when `sha2` is already a dep).
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsURFqkM+K0OqYj2o/MHmDP test@host";

    #[test]
    fn fingerprint_matches_openssh_style() {
        let parts: Vec<_> = TEST_PUB.split_whitespace().collect();
        let blob = decode_openssh_blob(parts[1]).unwrap();
        let fp = ssh_fingerprint(&blob);
        assert!(fp.starts_with("SHA256:"));
        assert!(!fp.contains('='));
    }
}
