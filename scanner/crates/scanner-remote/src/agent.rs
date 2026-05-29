//! Agent-mode remote scan: ship a static `scanner-asset` binary to the
//! target, run it in place against the live filesystem, pull the JSON back,
//! then remove all traces.
//!
//! Pipeline:
//! 1. [`bootstrap::ensure_key_auth`] (password → key on first run).
//! 2. [`crate::ssh::SshSession`] over multiplexed OpenSSH.
//! 3. Probe target arch; reject if it cannot match the shipped binary.
//! 4. Pick a writable, non-`noexec` work dir; create it (RAII cleanup).
//! 5. `scp` the binary up, `chmod +x`, sha256-verify.
//! 6. Run `scanner-asset -r <root> -t <target> -o <work>/out`.
//! 7. `scp` the per-asset JSON files back into `output_dir`.
//! 8. `rm -rf` the work dir on drop, even on error.
//!
//! This needs **no** snapshot, qemu-nbd, or nbd kernel module — only SSH and
//! a writable directory on the target.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use scanner_asset::ScanTarget;

use crate::bootstrap;
use crate::ssh::{SshOptions, SshSession};

/// Optional ClamAV scan run on the target after asset collection.
#[derive(Debug, Clone)]
pub struct MalwareAgentOptions {
    pub binary: PathBuf,
    pub jobs: usize,
    /// `clamd` Unix socket path **on the target** (auto-detect when unset).
    pub clamd_socket: Option<String>,
}

/// Candidate work-dir parents, in priority order. First that is writable and
/// not mounted `noexec` wins. `{id}` is replaced with the task id.
const WORKDIR_CANDIDATES: &[&str] = &[
    "/var/lib/scdr",
    "/opt/scdr",
    "/root/.cache/scdr",
    "/tmp",
];

#[derive(Debug, Clone)]
pub struct AgentScanOptions {
    pub ssh: SshOptions,
    /// One-shot password (only used if key auth fails on first run).
    pub password: Option<String>,
    /// Local static `scanner-asset` binary to ship (musl recommended).
    pub asset_binary: PathBuf,
    /// Filesystem root to scan on the target (default `/`).
    pub scan_root: String,
    pub target: ScanTarget,
    /// Local output directory for the per-asset JSON files.
    pub output_dir: PathBuf,
    /// Optional stable task id; auto-generated if `None`.
    pub task_id: Option<String>,
    /// When set, ship and run `scanner-malware` on the target (needs `clamd` there).
    pub malware: Option<MalwareAgentOptions>,
}

#[derive(Debug, Clone)]
pub struct AgentScanReport {
    pub task_id: String,
    /// Local paths of JSON files pulled back from the target.
    pub files: Vec<PathBuf>,
}

pub fn run_agent_scan(mut opts: AgentScanOptions) -> anyhow::Result<AgentScanReport> {
    let task_id = opts
        .task_id
        .clone()
        .unwrap_or_else(|| crate::short_id(uuid::Uuid::new_v4()));

    if !opts.asset_binary.is_file() {
        bail!(
            "asset binary not found: {} \n\
             build it first:\n  \
             rustup target add x86_64-unknown-linux-musl\n  \
             cargo build -p scanner-asset --target x86_64-unknown-linux-musl --release",
            opts.asset_binary.display()
        );
    }

    let key_path = bootstrap::ensure_key_auth(
        &opts.ssh.target,
        opts.ssh.port,
        opts.ssh.identity.as_deref(),
        opts.password.as_deref(),
    )
    .context("ensure key-based ssh auth")?;
    opts.ssh.identity = Some(key_path);
    opts.password.take();

    let session = SshSession::connect(opts.ssh.clone()).context("establish ssh session")?;

    probe_arch_compatible(&session).context("probe target architecture")?;

    let workdir = RemoteWorkdir::create(&session, &task_id).context("create remote work dir")?;
    let remote_bin = format!("{}/scanner-asset", workdir.path());
    let remote_out = format!("{}/out", workdir.path());

    session
        .scp_upload(&opts.asset_binary, &remote_bin)
        .context("upload scanner-asset binary")?;

    verify_upload(&session, &opts.asset_binary, &remote_bin)
        .context("verify uploaded binary integrity")?;

    let run = session.exec(&format!(
        "chmod +x {remote_bin} && mkdir -p {remote_out} && \
         {remote_bin} -r {root} -t {target} -o {remote_out}; echo __exit=$?",
        root = sh_quote(&opts.scan_root),
        target = target_arg(opts.target),
    ))?;
    let exit = parse_marked_exit(&run.stdout);
    if exit != Some(0) {
        bail!(
            "remote scanner-asset failed (exit {:?})\nstdout: {}\nstderr: {}",
            exit,
            run.stdout.trim(),
            run.stderr.trim()
        );
    }

    std::fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("create local output dir {}", opts.output_dir.display()))?;

    let mut files = Vec::new();
    for fname in expected_files(opts.target) {
        let remote_file = format!("{remote_out}/{fname}");
        if !remote_exists(&session, &remote_file)? {
            continue;
        }
        let local_file = opts.output_dir.join(fname);
        session
            .scp_download(&remote_file, &local_file)
            .with_context(|| format!("download {fname}"))?;
        files.push(local_file);
    }

    if files.is_empty() {
        bail!(
            "remote scan produced no JSON files under {remote_out} \
             (target={:?}); nothing pulled back",
            opts.target
        );
    }

    if let Some(malware) = &opts.malware {
        run_remote_malware(
            &session,
            &workdir,
            &remote_out,
            &opts.scan_root,
            malware,
            &opts.output_dir,
            &mut files,
        )
        .context("remote malware scan")?;
    }

    drop(workdir); // explicit: rm -rf remote work dir
    Ok(AgentScanReport { task_id, files })
}

fn run_remote_malware(
    session: &SshSession,
    workdir: &RemoteWorkdir<'_>,
    remote_out: &str,
    scan_root: &str,
    malware: &MalwareAgentOptions,
    output_dir: &Path,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    if !malware.binary.is_file() {
        bail!(
            "malware binary not found: {}\n\
             build it first:\n  \
             rustup target add x86_64-unknown-linux-musl\n  \
             cargo build -p scanner-malware --target x86_64-unknown-linux-musl --release",
            malware.binary.display()
        );
    }

    let remote_bin = format!("{}/scanner-malware", workdir.path());
    session
        .scp_upload(&malware.binary, &remote_bin)
        .context("upload scanner-malware binary")?;
    verify_upload(session, &malware.binary, &remote_bin)
        .context("verify uploaded malware binary integrity")?;

    let mut cmd = format!(
        "chmod +x {remote_bin} && {remote_bin} -r {root} -o {remote_out} -j {jobs}",
        root = sh_quote(scan_root),
        jobs = malware.jobs.max(1),
    );
    if let Some(sock) = &malware.clamd_socket {
        cmd.push_str(&format!(" --clamd-socket {}", sh_quote(sock)));
    }
    cmd.push_str("; echo __exit=$?");

    let run = session.exec(&cmd)?;
    let exit = parse_marked_exit(&run.stdout);
    if exit != Some(0) {
        bail!(
            "remote scanner-malware failed (exit {:?})\nstdout: {}\nstderr: {}",
            exit,
            run.stdout.trim(),
            run.stderr.trim()
        );
    }

    let remote_json = format!("{remote_out}/malware.json");
    if remote_exists(session, &remote_json)? {
        let local = output_dir.join("malware.json");
        session
            .scp_download(&remote_json, &local)
            .context("download malware.json")?;
        files.push(local);
    }
    Ok(())
}

/// RAII guard: `rm -rf` the remote work dir on drop.
struct RemoteWorkdir<'a> {
    session: &'a SshSession,
    path: String,
}

impl<'a> RemoteWorkdir<'a> {
    fn create(session: &'a SshSession, task_id: &str) -> anyhow::Result<Self> {
        let parent = pick_workdir_parent(session)?;
        let path = format!("{parent}/scan-{task_id}");
        let out = session.exec(&format!(
            "mkdir -p {p} && chmod 700 {p} && echo __ok",
            p = sh_quote(&path)
        ))?;
        if !out.success() || !out.stdout.contains("__ok") {
            bail!(
                "failed to create remote work dir {path}: {}",
                out.stderr.trim()
            );
        }
        Ok(Self { session, path })
    }

    fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for RemoteWorkdir<'_> {
    fn drop(&mut self) {
        // Guard against empty/wildcard paths before rm -rf.
        if self.path.starts_with('/') && self.path.contains("/scan-") {
            if let Err(e) = self.session.exec(&format!("rm -rf {}", sh_quote(&self.path))) {
                eprintln!(
                    "[scanner-remote/agent] cleanup rm -rf {} failed: {e:#}",
                    self.path
                );
            }
        }
    }
}

/// Find the first writable, non-`noexec` candidate parent dir on the target.
fn pick_workdir_parent(session: &SshSession) -> anyhow::Result<String> {
    // One round-trip: for each candidate, try to create it and check the
    // mount options of the filesystem backing it for `noexec`.
    let script = WORKDIR_CANDIDATES
        .iter()
        .map(|c| {
            format!(
                "if mkdir -p {c} 2>/dev/null && [ -w {c} ]; then \
                   opts=$(awk -v d={c} '$2==d || (index(d,$2)==1 && length($2)>best){{best=length($2);o=$4}} END{{print o}}' /proc/self/mounts); \
                   case \",$opts,\" in *,noexec,*) : ;; *) echo {c}; exit 0;; esac; \
                 fi"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let out = session.exec(&script)?;
    let chosen = out.stdout.trim().lines().next().unwrap_or("").trim();
    if chosen.is_empty() {
        bail!(
            "no writable non-noexec work dir among {:?} on {}",
            WORKDIR_CANDIDATES,
            session.target()
        );
    }
    Ok(chosen.to_string())
}

fn probe_arch_compatible(session: &SshSession) -> anyhow::Result<()> {
    let out = session.exec("uname -m")?;
    let arch = out.stdout.trim();
    // MVP ships x86_64 only. Reject obvious mismatches early with a clear msg.
    match arch {
        "x86_64" | "amd64" => Ok(()),
        other => bail!(
            "target arch {other:?} not supported by the shipped binary \
             (MVP builds x86_64-unknown-linux-musl). Build a matching target."
        ),
    }
}

fn verify_upload(
    session: &SshSession,
    local: &Path,
    remote_path: &str,
) -> anyhow::Result<()> {
    let local_sum = sha256_file(local)?;
    let out = session.exec(&format!("sha256sum {} 2>/dev/null", sh_quote(remote_path)))?;
    let remote_sum = out
        .stdout
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    if remote_sum.is_empty() {
        // sha256sum missing on target: skip with a warning rather than fail.
        eprintln!("[scanner-remote/agent] sha256sum unavailable on target; skipping integrity check");
        return Ok(());
    }
    if remote_sum != local_sum {
        bail!("uploaded binary sha256 mismatch (local {local_sum}, remote {remote_sum})");
    }
    Ok(())
}

fn remote_exists(session: &SshSession, path: &str) -> anyhow::Result<bool> {
    let out = session.exec(&format!("test -f {} && echo __y", sh_quote(path)))?;
    Ok(out.stdout.contains("__y"))
}

fn target_arg(t: ScanTarget) -> &'static str {
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

fn expected_files(t: ScanTarget) -> &'static [&'static str] {
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

/// Minimal single-quote shell escaping for paths/args we send remotely.
fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

fn parse_marked_exit(stdout: &str) -> Option<i32> {
    stdout
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix("__exit="))
        .and_then(|n| n.parse().ok())
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))?;
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

// --- tiny dependency-free SHA-256 ----------------------------------------
// Avoids pulling a crate just to checksum a ~1MB file once per scan.

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
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0x1f83d9ab, 0x5be0cd19,
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

    // SHA-256 round arithmetic indexes K[i]/w[i] together; index form is
    // clearer than iterator zipping here.
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

    #[test]
    fn sh_quote_escapes() {
        assert_eq!(sh_quote("/tmp/x"), "'/tmp/x'");
        assert_eq!(sh_quote("a'b"), r#"'a'\''b'"#);
    }

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
        assert_eq!(
            expected_files(ScanTarget::All),
            &[
                "host.json",
                "packages.json",
                "sbom.cyclonedx.json",
                "services.json",
                "accounts.json",
                "credentials.json",
            ]
        );
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

    #[test]
    fn sha256_multiblock() {
        // 56-byte NIST vector: forces a second block during padding.
        let mut h = Sha256::new();
        h.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            h.hex(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_chunked_update_matches_oneshot() {
        // Feed > 64 bytes in awkward chunks; must equal single-shot.
        let data: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
        let mut a = Sha256::new();
        a.update(&data);
        let oneshot = a.hex();
        let mut b = Sha256::new();
        for chunk in data.chunks(7) {
            b.update(chunk);
        }
        assert_eq!(b.hex(), oneshot);
    }
}
