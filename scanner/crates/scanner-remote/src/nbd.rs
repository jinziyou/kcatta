//! NBD over SSH data channel.
//!
//! Pipeline:
//! 1. Start `qemu-nbd` on the remote host, bound to `127.0.0.1:<port>`,
//!    serving the snapshot block device read-only.
//! 2. Open an SSH local-forward so `127.0.0.1:<port>` on the scanner side
//!    tunnels to the remote `qemu-nbd`.
//! 3. Run `nbd-client` on the scanner side, attaching the tunneled port to a
//!    local `/dev/nbdN` device.
//! 4. `mount -o ro,noexec,nodev,nosuid /dev/nbdN <mount_path>`.
//!
//! [`NbdMount`] owns all four resources and reverses them on drop. Cleanup
//! is best-effort and idempotent so a partial setup still tears down cleanly.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use scanner_snapshot_contract::{RemoteExec, RemoteSnapshot};

use crate::ssh::{PortForward, SshSession};

/// Tunable parameters for the NBD channel.
#[derive(Debug, Clone)]
pub struct NbdOptions {
    /// Local block device to attach (`/dev/nbd0` by default).
    pub local_nbd: PathBuf,
    /// Local + remote TCP port for the tunnel (10809 by default — the IANA
    /// NBD port).
    pub port: u16,
    /// Where to create the mount directory (`<mount_base>/scdr-scan-<id>`).
    pub mount_base: PathBuf,
    /// Optional `mount -t <type>` hint. `None` lets `mount(8)` auto-detect.
    pub fs_type: Option<String>,
    /// Max time to wait for the remote `qemu-nbd` to start listening.
    pub remote_listen_timeout: Duration,
    /// Max time to wait for the local NBD device to settle after `nbd-client`.
    pub nbd_attach_timeout: Duration,
}

impl Default for NbdOptions {
    fn default() -> Self {
        Self {
            local_nbd: PathBuf::from("/dev/nbd0"),
            port: 10809,
            mount_base: PathBuf::from("/mnt"),
            fs_type: None,
            remote_listen_timeout: Duration::from_secs(10),
            nbd_attach_timeout: Duration::from_secs(10),
        }
    }
}

/// RAII handle for the full pipeline. Drop tears everything down in reverse.
pub struct NbdMount {
    mount_path: PathBuf,
    local_nbd: PathBuf,
    /// Kept alive for the lifetime of the mount; drop kills `ssh -L`.
    _forward: PortForward,
    exec: Arc<dyn RemoteExec>,
    remote_qemu_pid: Option<u32>,
    remote_port: u16,
}

impl NbdMount {
    /// Filesystem root that callers should pass to `scanner-asset`.
    pub fn mount_path(&self) -> &Path {
        &self.mount_path
    }

    /// Establish the full pipeline against `snapshot`.
    pub fn establish(
        session: &SshSession,
        snapshot: &RemoteSnapshot,
        opts: &NbdOptions,
    ) -> anyhow::Result<Self> {
        let mount_path = opts
            .mount_base
            .join(format!("scdr-scan-{}", snapshot.id));

        ensure_local_prereqs(&opts.local_nbd)?;

        // 1. start remote qemu-nbd in the background and capture its PID
        let remote_qemu_pid = start_remote_qemu_nbd(
            &**snapshot.exec(),
            &snapshot.device_path,
            opts.port,
        )?;
        let exec_for_drop: Arc<dyn RemoteExec> = snapshot.exec().clone();

        // From here on, any error must shoot down the remote qemu-nbd.
        let guard = RemoteQemuGuard {
            exec: exec_for_drop.clone(),
            pid: remote_qemu_pid,
            port: opts.port,
        };

        wait_remote_listening(&**snapshot.exec(), opts.port, opts.remote_listen_timeout)
            .context("remote qemu-nbd never started listening")?;

        // 2. open ssh -L tunnel
        let forward = session
            .open_local_forward(opts.port, "127.0.0.1", opts.port)
            .context("open ssh -L tunnel")?;

        // 3. attach local NBD client (this needs root on the scanner host)
        attach_local_nbd(&opts.local_nbd, opts.port, opts.nbd_attach_timeout)?;
        let nbd_guard = LocalNbdGuard {
            device: opts.local_nbd.clone(),
        };

        // 4. mount
        std::fs::create_dir_all(&mount_path)
            .with_context(|| format!("mkdir {}", mount_path.display()))?;
        let mount_guard = MountGuard {
            path: mount_path.clone(),
        };
        mount_local(&opts.local_nbd, &mount_path, opts.fs_type.as_deref())?;

        // Defuse guards: success path keeps everything, cleanup runs via our own Drop.
        std::mem::forget(mount_guard);
        std::mem::forget(nbd_guard);
        std::mem::forget(guard);

        Ok(Self {
            mount_path,
            local_nbd: opts.local_nbd.clone(),
            _forward: forward,
            exec: exec_for_drop,
            remote_qemu_pid: Some(remote_qemu_pid),
            remote_port: opts.port,
        })
    }
}

impl Drop for NbdMount {
    fn drop(&mut self) {
        if let Err(e) = local_umount(&self.mount_path) {
            eprintln!(
                "[scanner-remote/nbd] umount {} failed: {e:#}",
                self.mount_path.display()
            );
        }
        let _ = std::fs::remove_dir(&self.mount_path);
        if let Err(e) = local_nbd_detach(&self.local_nbd) {
            eprintln!(
                "[scanner-remote/nbd] nbd-client -d {} failed: {e:#}",
                self.local_nbd.display()
            );
        }
        // PortForward drops itself.
        if let Err(e) = stop_remote_qemu_nbd(&*self.exec, self.remote_qemu_pid, self.remote_port) {
            eprintln!("[scanner-remote/nbd] stop remote qemu-nbd failed: {e:#}");
        }
    }
}

// ---- guards used only on the error path of establish() -------------------

struct RemoteQemuGuard {
    exec: Arc<dyn RemoteExec>,
    pid: u32,
    port: u16,
}
impl Drop for RemoteQemuGuard {
    fn drop(&mut self) {
        let _ = stop_remote_qemu_nbd(&*self.exec, Some(self.pid), self.port);
    }
}

struct LocalNbdGuard {
    device: PathBuf,
}
impl Drop for LocalNbdGuard {
    fn drop(&mut self) {
        let _ = local_nbd_detach(&self.device);
    }
}

struct MountGuard {
    path: PathBuf,
}
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = local_umount(&self.path);
        let _ = std::fs::remove_dir(&self.path);
    }
}

// ---- remote helpers ------------------------------------------------------

fn start_remote_qemu_nbd(
    exec: &dyn RemoteExec,
    snapshot_device: &str,
    port: u16,
) -> anyhow::Result<u32> {
    // Detach via `setsid`+`nohup` so the qemu-nbd process survives the SSH
    // command that started it; capture its PID via $!.
    let script = format!(
        "set -e\n\
         sudo -n -b nohup qemu-nbd \
           --read-only \
           --bind=127.0.0.1 \
           --port={port} \
           --persistent \
           --format=raw \
           {snapshot_device} </dev/null >/tmp/scdr-qemu-nbd-{port}.log 2>&1\n\
         # qemu-nbd forks; sudo -b returns instantly. Resolve PID by listening port.\n\
         for _ in $(seq 1 50); do \
           pid=$(sudo -n ss -ltnp \"sport = :{port}\" 2>/dev/null | \
                 awk -F'pid=' 'NR>1 {{split($2,a,\",\"); print a[1]; exit}}'); \
           [ -n \"$pid\" ] && echo \"$pid\" && exit 0; \
           sleep 0.1; \
         done\n\
         echo 0\n"
    );
    let out = run_remote_bash(exec, &script).context("start remote qemu-nbd")?;
    if !out.success() {
        bail!(
            "remote qemu-nbd start failed (exit {}): {}",
            out.status,
            out.stderr.trim()
        );
    }
    let pid_str = out.stdout.trim();
    pid_str.parse::<u32>().with_context(|| {
        format!("parse remote qemu-nbd PID from {pid_str:?} (port {port})")
    })
}

fn wait_remote_listening(
    exec: &dyn RemoteExec,
    port: u16,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let probe = format!("sudo -n ss -ltn \"sport = :{port}\" | grep -q LISTEN && echo ok");
    while Instant::now() < deadline {
        let out = exec.exec(&probe)?;
        if out.success() && out.stdout.trim() == "ok" {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(150));
    }
    bail!("remote port {port} not LISTENing within {:?}", timeout)
}

fn stop_remote_qemu_nbd(
    exec: &dyn RemoteExec,
    pid: Option<u32>,
    port: u16,
) -> anyhow::Result<()> {
    let cmd = match pid {
        Some(p) => format!(
            "sudo -n kill {p} 2>/dev/null || true; \
             sudo -n pkill -f 'qemu-nbd.*--port={port}' 2>/dev/null || true"
        ),
        None => format!("sudo -n pkill -f 'qemu-nbd.*--port={port}' 2>/dev/null || true"),
    };
    let out = exec.exec(&cmd)?;
    if !out.success() {
        bail!(
            "remote qemu-nbd kill exit {}: {}",
            out.status,
            out.stderr.trim()
        );
    }
    Ok(())
}

fn run_remote_bash(
    exec: &dyn RemoteExec,
    script: &str,
) -> anyhow::Result<scanner_snapshot_contract::CommandOutput> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(script);
    exec.exec(&format!("echo {b64} | base64 -d | bash"))
}

// ---- local helpers -------------------------------------------------------

fn ensure_local_prereqs(local_nbd: &Path) -> anyhow::Result<()> {
    if !local_nbd.exists() {
        // Try to load the nbd kernel module first.
        let _ = Command::new("sudo")
            .args(["-n", "modprobe", "nbd"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    if !local_nbd.exists() {
        bail!(
            "{} does not exist (load the `nbd` kernel module: `sudo modprobe nbd`)",
            local_nbd.display()
        );
    }
    Ok(())
}

fn attach_local_nbd(
    device: &Path,
    port: u16,
    timeout: Duration,
) -> anyhow::Result<()> {
    let status = Command::new("sudo")
        .args(["-n", "nbd-client", "-N", "", "-persist"])
        .arg("127.0.0.1")
        .arg(port.to_string())
        .arg(device)
        .arg("-timeout=30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("spawn nbd-client")?;
    if !status.status.success() {
        bail!(
            "nbd-client attach {} -> 127.0.0.1:{port} failed: {}",
            device.display(),
            String::from_utf8_lossy(&status.stderr).trim()
        );
    }
    // Wait for the device to report a non-zero size.
    let size_path = PathBuf::from(format!(
        "/sys/block/{}/size",
        device
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("nbd0")
    ));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(&size_path) {
            if s.trim().parse::<u64>().unwrap_or(0) > 0 {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!(
        "{} attached but size never became non-zero (no data from remote)",
        device.display()
    )
}

fn local_nbd_detach(device: &Path) -> anyhow::Result<()> {
    let out = Command::new("sudo")
        .args(["-n", "nbd-client", "-d"])
        .arg(device)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("spawn nbd-client -d")?;
    if !out.status.success() {
        bail!(
            "nbd-client -d {} failed: {}",
            device.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn mount_local(
    device: &Path,
    mount_path: &Path,
    fs_type: Option<&str>,
) -> anyhow::Result<()> {
    let mut cmd = Command::new("sudo");
    cmd.args(["-n", "mount", "-o", "ro,noexec,nodev,nosuid"]);
    if let Some(t) = fs_type {
        cmd.args(["-t", t]);
    }
    cmd.arg(device).arg(mount_path);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let out = cmd.output().context("spawn mount")?;
    if !out.status.success() {
        bail!(
            "mount {} {} failed: {}",
            device.display(),
            mount_path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn local_umount(mount_path: &Path) -> anyhow::Result<()> {
    if !is_mounted(mount_path) {
        return Ok(());
    }
    let out = Command::new("sudo")
        .args(["-n", "umount"])
        .arg(mount_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("spawn umount")?;
    if !out.status.success() {
        bail!(
            "umount {} failed: {}",
            mount_path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn is_mounted(path: &Path) -> bool {
    let mounts = match std::fs::read_to_string("/proc/self/mounts") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let needle = path.to_string_lossy();
    mounts
        .lines()
        .any(|l| l.split_whitespace().nth(1) == Some(&needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_use_iana_port_and_nbd0() {
        let o = NbdOptions::default();
        assert_eq!(o.port, 10809);
        assert_eq!(o.local_nbd, PathBuf::from("/dev/nbd0"));
        assert_eq!(o.mount_base, PathBuf::from("/mnt"));
    }

    #[test]
    fn is_mounted_returns_false_for_nonexistent_path() {
        assert!(!is_mounted(Path::new("/nonexistent/path/xyz/zzz")));
    }
}
