//! Helpers shared by SSH and WinRM remote scan pipelines.

use std::path::Path;

use fusion_asset::ScanTarget;

pub(crate) fn target_arg(t: ScanTarget) -> &'static str {
    match t {
        ScanTarget::Host => "host",
        ScanTarget::Packages => "packages",
        ScanTarget::Sbom => "sbom",
        ScanTarget::Services => "services",
        ScanTarget::Accounts => "accounts",
        ScanTarget::Credentials => "credentials",
        ScanTarget::Identity => "identity",
        ScanTarget::All => "all",
    }
}

pub(crate) fn expected_files(t: ScanTarget) -> &'static [&'static str] {
    match t {
        ScanTarget::Host => &["host.json"],
        ScanTarget::Packages => &["packages.json"],
        ScanTarget::Sbom => &["sbom.cyclonedx.json"],
        ScanTarget::Services => &["services.json"],
        ScanTarget::Accounts => &["accounts.json"],
        ScanTarget::Credentials => &["credentials.json"],
        ScanTarget::Identity => &["services.json", "accounts.json", "credentials.json"],
        ScanTarget::All => &[
            "host.json",
            "packages.json",
            "sbom.cyclonedx.json",
            "services.json",
            "accounts.json",
            "credentials.json",
        ],
    }
}

pub(crate) fn parse_marked_exit(stdout: &str) -> Option<i32> {
    stdout
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix("__exit="))
        .and_then(|n| n.parse().ok())
}

pub(crate) fn sha256_file(path: &Path) -> anyhow::Result<String> {
    use anyhow::Context;
    use std::io::Read;

    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).context("read for sha256")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.hex())
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

    fn hex(mut self) -> String {
        let bit_len = self.len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        let lb = bit_len.to_be_bytes();
        self.update(&lb);
        let mut s = String::with_capacity(64);
        for word in self.state.iter() {
            s.push_str(&format!("{word:08x}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fusion_asset::ScanTarget;

    #[test]
    fn parse_marked_exit_reads_last_marker() {
        assert_eq!(parse_marked_exit("noise\n__exit=0\n"), Some(0));
        assert_eq!(parse_marked_exit("__exit=5"), Some(5));
        assert_eq!(parse_marked_exit("no marker"), None);
    }

    #[test]
    fn expected_files_match_target() {
        assert_eq!(expected_files(ScanTarget::Host), &["host.json"]);
        assert_eq!(expected_files(ScanTarget::Packages), &["packages.json"]);
        assert_eq!(expected_files(ScanTarget::Sbom), &["sbom.cyclonedx.json"]);
    }

    #[test]
    fn sha256_known_vectors() {
        let mut h = Sha256::new();
        h.update(b"");
        assert_eq!(
            h.hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(
            h.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
