//! Fixed-path SSH credential sources for Linux mounts.

use base64::Engine;
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

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

struct Sha256 {
    state: [u32; 8],
    len: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            len: 0,
            buf: [0; 64],
            buf_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.process(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.process(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn process(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut h = self.state;
        for i in 0..64 {
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
            let ch = (h[4] & h[5]) ^ ((!h[4]) & h[6]);
            let t1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            let maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            let t2 = s0.wrapping_add(maj);
            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(t1);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            self.state[i] = self.state[i].wrapping_add(h[i]);
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        let lb = bit_len.to_be_bytes();
        self.update(&lb);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
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
