//! OpenSSH-backed remote executor with connection multiplexing.
//!
//! Uses ControlMaster + ControlPath + ControlPersist so every [`exec`] call
//! multiplexes a new channel over **one** TCP connection: no re-auth per
//! command, low latency.
//!
//! Lifetime:
//! - `connect` starts an `ssh -M -N -f` master and waits for its control
//!   socket to appear.
//! - `Drop` issues `ssh -O exit` to tear the master down.
//!
//! [`exec`]: SshSession::exec

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use tempfile::TempDir;

/// Result of a single remote command execution. Non-zero exits are returned
/// as `Ok` (not `Err`) so callers can probe for missing commands.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Captured stdout (UTF-8 lossy).
    pub stdout: String,
    /// Captured stderr (UTF-8 lossy).
    pub stderr: String,
    /// Raw exit status code.
    pub status: i32,
}

impl CommandOutput {
    /// Whether the remote command exited with status 0.
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

/// Per-session SSH options.
#[derive(Debug, Clone)]
pub struct SshOptions {
    /// `user@host`.
    pub target: String,
    /// SSH port (defaults to 22).
    pub port: u16,
    /// Identity file (`-i`). `None` uses agent / default keys.
    pub identity: Option<PathBuf>,
    /// `-o StrictHostKeyChecking=...`. Default: `accept-new`.
    pub strict_host_key_checking: String,
    /// `-o UserKnownHostsFile=...`. `None` uses default.
    pub known_hosts: Option<PathBuf>,
    /// How long the multiplexed connection stays idle before tear-down.
    pub control_persist: Duration,
    /// Max time to wait for the master to come up.
    pub connect_timeout: Duration,
}

impl SshOptions {
    /// Defaults: port 22, `StrictHostKeyChecking=accept-new`, 60s control persist.
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            port: 22,
            identity: None,
            strict_host_key_checking: "accept-new".into(),
            known_hosts: None,
            control_persist: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(15),
        }
    }
}

/// Multiplexed OpenSSH session (ControlMaster). Tear down on drop.
pub struct SshSession {
    opts: SshOptions,
    /// Owns the tempdir so the socket path stays valid for the session.
    _control_dir: TempDir,
    control_path: PathBuf,
}

impl SshSession {
    /// Start the SSH master process and wait for the control socket.
    pub fn connect(opts: SshOptions) -> anyhow::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("scdr-ssh.")
            .tempdir()
            .context("create ssh control dir")?;
        let control_path = dir.path().join("ctl");

        let mut cmd = Command::new("ssh");
        push_common_opts(&mut cmd, &opts, &control_path);
        cmd.args([
            "-M",
            "-N",
            "-f",
            "-o",
            &format!("ConnectTimeout={}", opts.connect_timeout.as_secs().max(1)),
        ]);
        cmd.arg(&opts.target);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = cmd.output().context("spawn ssh master")?;
        if !output.status.success() {
            bail!(
                "ssh master failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim(),
            );
        }

        wait_for_socket(&control_path, opts.connect_timeout)
            .context("ssh master started but control socket never appeared")?;

        Ok(Self {
            opts,
            _control_dir: dir,
            control_path,
        })
    }

    fn base_cmd(&self) -> Command {
        let mut c = Command::new("ssh");
        push_common_opts(&mut c, &self.opts, &self.control_path);
        c
    }

    /// `scp` command sharing this session's ControlMaster socket. `scp` uses
    /// `-P` (capital) for the port, unlike `ssh`.
    fn scp_base_cmd(&self) -> Command {
        let mut c = Command::new("scp");
        c.args([
            "-P",
            &self.opts.port.to_string(),
            "-o",
            "ControlMaster=auto",
            "-o",
            &format!("ControlPath={}", self.control_path.display()),
            "-o",
            "BatchMode=yes",
            "-o",
            &format!(
                "StrictHostKeyChecking={}",
                self.opts.strict_host_key_checking
            ),
        ]);
        if let Some(ref id) = self.opts.identity {
            c.args(["-i", &id.display().to_string()]);
        }
        c.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        c
    }

    /// Upload a local file to `remote_path` on the target.
    pub fn scp_upload(&self, local: &Path, remote_path: &str) -> anyhow::Result<()> {
        let mut c = self.scp_base_cmd();
        c.arg("--").arg(local);
        c.arg(format!("{}:{}", self.opts.target, remote_path));
        let out = c
            .output()
            .with_context(|| format!("spawn scp upload {}", local.display()))?;
        if !out.status.success() {
            bail!(
                "scp upload {} -> {}:{} failed: {}",
                local.display(),
                self.opts.target,
                remote_path,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// Download `remote_path` from the target to a local path.
    pub fn scp_download(&self, remote_path: &str, local: &Path) -> anyhow::Result<()> {
        let mut c = self.scp_base_cmd();
        c.arg("--")
            .arg(format!("{}:{}", self.opts.target, remote_path))
            .arg(local);
        let out = c
            .output()
            .with_context(|| format!("spawn scp download {remote_path}"))?;
        if !out.status.success() {
            bail!(
                "scp download {}:{} -> {} failed: {}",
                self.opts.target,
                remote_path,
                local.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        let mut cmd = self.base_cmd();
        cmd.args(["-O", "exit"]);
        cmd.arg(&self.opts.target);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _ = cmd.status();
    }
}

impl SshSession {
    /// Run `cmd` on the target through a multiplexed channel. Non-zero exits
    /// come back as `Ok` so callers can probe for missing commands.
    pub fn exec(&self, cmd: &str) -> anyhow::Result<CommandOutput> {
        let mut c = self.base_cmd();
        c.arg(&self.opts.target).arg(cmd);
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = c
            .output()
            .with_context(|| format!("ssh exec {:?}", trunc(cmd, 80)))?;
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            status: output.status.code().unwrap_or(-1),
        })
    }

    /// Human label (`user@host`) for logs.
    pub fn target(&self) -> &str {
        &self.opts.target
    }
}

fn push_common_opts(cmd: &mut Command, opts: &SshOptions, control_path: &Path) {
    cmd.args([
        "-p",
        &opts.port.to_string(),
        "-o",
        "ControlMaster=auto",
        "-o",
        &format!("ControlPath={}", control_path.display()),
        "-o",
        &format!("ControlPersist={}", opts.control_persist.as_secs().max(1)),
        "-o",
        &format!("StrictHostKeyChecking={}", opts.strict_host_key_checking),
        "-o",
        "BatchMode=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
    ]);
    if let Some(ref id) = opts.identity {
        cmd.args(["-i", &id.display().to_string(), "-o", "IdentitiesOnly=yes"]);
    }
    if let Some(ref kh) = opts.known_hosts {
        cmd.args(["-o", &format!("UserKnownHostsFile={}", kh.display())]);
    }
}

fn wait_for_socket(path: &Path, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(anyhow!("control socket {} never appeared", path.display()))
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        // Step back to a UTF-8 char boundary so slicing never panics on multi-byte input.
        let mut end = n;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies command construction without spawning real ssh.
    #[test]
    fn common_opts_include_control_master_and_batch_mode() {
        let opts = SshOptions::new("user@host");
        let mut cmd = Command::new("ssh");
        push_common_opts(&mut cmd, &opts, Path::new("/tmp/ctl"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|a| a == "ControlMaster=auto"));
        assert!(args.iter().any(|a| a == "BatchMode=yes"));
        assert!(args.iter().any(|a| a.starts_with("ControlPath=/tmp/ctl")));
        assert!(args.iter().any(|a| a == "ServerAliveInterval=15"));
    }

    #[test]
    fn identity_adds_identities_only() {
        let mut opts = SshOptions::new("u@h");
        opts.identity = Some(PathBuf::from("/key"));
        let mut cmd = Command::new("ssh");
        push_common_opts(&mut cmd, &opts, Path::new("/tmp/ctl"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|a| a == "-i"));
        assert!(args.iter().any(|a| a == "/key"));
        assert!(args.iter().any(|a| a == "IdentitiesOnly=yes"));
    }
}
