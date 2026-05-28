//! LVM snapshot backend.
//!
//! Source identifier: `/dev/<vg>/<lv>` (canonical) or `/dev/mapper/<vg>-<lv>`.
//! Produces a read-only snapshot at `/dev/<vg>/scdr-snap-<id>`, suitable to
//! be exposed via `qemu-nbd` on the remote host.

use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use base64::Engine;
use scanner_snapshot_contract::{
    CommandOutput, RemoteExec, RemoteSnapshot, SnapshotBackend, SnapshotRequest,
};

const BACKEND: &str = "lvm";
const SNAP_NAME_PREFIX: &str = "scdr-snap-";
const MIN_SNAP_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
const MAX_SNAP_BYTES: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB
const SNAP_FRACTION_PCT: u64 = 15;

#[derive(Debug, Default, Clone)]
pub struct LvmBackend;

impl LvmBackend {
    pub fn new() -> Self {
        Self
    }
}

impl SnapshotBackend for LvmBackend {
    fn name(&self) -> &'static str {
        BACKEND
    }

    fn probe(&self, exec: &dyn RemoteExec) -> anyhow::Result<bool> {
        let out = exec.exec(
            "command -v lvcreate >/dev/null 2>&1 \
             && command -v lvremove >/dev/null 2>&1 \
             && command -v lvs >/dev/null 2>&1 \
             && echo ok",
        )?;
        Ok(out.success() && out.stdout.trim() == "ok")
    }

    fn create_snapshot(
        &self,
        exec: Arc<dyn RemoteExec>,
        req: &SnapshotRequest<'_>,
    ) -> anyhow::Result<RemoteSnapshot> {
        let (vg, lv) = parse_source(req.source)?;
        let snap_id = sanitize_id(req.id);
        if snap_id.is_empty() {
            bail!("snapshot id is empty after sanitization: {:?}", req.id);
        }
        let snap_name = format!("{SNAP_NAME_PREFIX}{snap_id}");
        let snap_path = format!("/dev/{vg}/{snap_name}");

        let size_bytes = probe_source_size(&*exec, &vg, &lv)?
            .map(snapshot_size_for_source)
            .unwrap_or(MIN_SNAP_BYTES);

        let script = build_create_script(&vg, &lv, &snap_name, size_bytes, req.freeze_mount);
        let out = run_bash(&*exec, &script)
            .with_context(|| format!("create snapshot {snap_name} on {}", exec.target()))?;
        if !out.success() {
            bail!(
                "lvcreate snapshot {snap_name} failed (exit {}): {}",
                out.status,
                out.stderr.trim()
            );
        }

        let cleanup = vec![format!("sudo -n lvremove -f {snap_path}")];
        Ok(RemoteSnapshot::new(
            BACKEND, snap_id, snap_path, exec, cleanup,
        ))
    }
}

fn parse_source(source: &str) -> anyhow::Result<(String, String)> {
    let trimmed = source
        .strip_prefix("/dev/")
        .ok_or_else(|| anyhow!("LVM source must start with /dev/: {source:?}"))?;
    if let Some(rest) = trimmed.strip_prefix("mapper/") {
        let (vg, lv) = rest
            .split_once('-')
            .ok_or_else(|| anyhow!("invalid /dev/mapper path: {source:?}"))?;
        return ensure_non_empty(vg, lv, source);
    }
    let (vg, lv) = trimmed
        .split_once('/')
        .ok_or_else(|| anyhow!("LVM source must be /dev/<vg>/<lv>: {source:?}"))?;
    ensure_non_empty(vg, lv, source)
}

fn ensure_non_empty(vg: &str, lv: &str, source: &str) -> anyhow::Result<(String, String)> {
    if vg.is_empty() || lv.is_empty() {
        bail!("LVM source has empty vg or lv: {source:?}");
    }
    if lv.contains('/') {
        bail!("LVM lv name contains '/': {source:?}");
    }
    Ok((vg.to_string(), lv.to_string()))
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn probe_source_size(
    exec: &dyn RemoteExec,
    vg: &str,
    lv: &str,
) -> anyhow::Result<Option<u64>> {
    let out = exec.exec(&format!(
        "sudo -n lvs --noheadings --units b --nosuffix -o lv_size /dev/{vg}/{lv}"
    ))?;
    if !out.success() {
        return Ok(None);
    }
    Ok(out.stdout.trim().parse::<u64>().ok())
}

fn snapshot_size_for_source(src_bytes: u64) -> u64 {
    let raw = src_bytes / 100 * SNAP_FRACTION_PCT;
    raw.clamp(MIN_SNAP_BYTES, MAX_SNAP_BYTES)
}

fn build_create_script(
    vg: &str,
    lv: &str,
    snap: &str,
    bytes: u64,
    freeze: Option<&str>,
) -> String {
    let lvcreate = format!("sudo -n lvcreate -s -n {snap} -L {bytes}B /dev/{vg}/{lv}");
    match freeze {
        Some(mount) => format!(
            "set -e\n\
             trap 'sudo -n fsfreeze -u \"{mount}\" >/dev/null 2>&1 || true' EXIT\n\
             sudo -n fsfreeze -f \"{mount}\"\n\
             {lvcreate}\n"
        ),
        None => format!("set -e\n{lvcreate}\n"),
    }
}

fn run_bash(exec: &dyn RemoteExec, script: &str) -> anyhow::Result<CommandOutput> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(script);
    exec.exec(&format!("echo {b64} | base64 -d | bash"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockExec {
        log: Mutex<Vec<String>>,
        replies: Mutex<Vec<CommandOutput>>,
    }

    impl MockExec {
        fn new(replies: Vec<CommandOutput>) -> Self {
            Self {
                log: Mutex::new(Vec::new()),
                replies: Mutex::new(replies),
            }
        }
        fn ok(stdout: &str) -> CommandOutput {
            CommandOutput {
                stdout: stdout.into(),
                stderr: String::new(),
                status: 0,
            }
        }
    }

    impl RemoteExec for MockExec {
        fn exec(&self, cmd: &str) -> anyhow::Result<CommandOutput> {
            self.log.lock().unwrap().push(cmd.to_string());
            let mut r = self.replies.lock().unwrap();
            Ok(if r.is_empty() {
                MockExec::ok("")
            } else {
                r.remove(0)
            })
        }
        fn target(&self) -> &str {
            "mock@host"
        }
    }

    #[test]
    fn parse_source_canonical() {
        assert_eq!(
            parse_source("/dev/vg0/root").unwrap(),
            ("vg0".into(), "root".into())
        );
    }

    #[test]
    fn parse_source_mapper() {
        assert_eq!(
            parse_source("/dev/mapper/vg0-root").unwrap(),
            ("vg0".into(), "root".into())
        );
    }

    #[test]
    fn parse_source_rejects_bad_inputs() {
        assert!(parse_source("vg0/root").is_err());
        assert!(parse_source("/dev/").is_err());
        assert!(parse_source("/dev/vg0/").is_err());
        assert!(parse_source("/dev/vg0/root/extra").is_err());
    }

    #[test]
    fn sanitize_id_replaces_illegal_chars() {
        assert_eq!(sanitize_id("abc 123"), "abc-123");
        assert_eq!(sanitize_id("--abc--"), "abc");
        assert_eq!(sanitize_id("a/b.c"), "a-b-c");
    }

    #[test]
    fn snapshot_size_is_clamped() {
        assert_eq!(snapshot_size_for_source(0), MIN_SNAP_BYTES);
        assert_eq!(snapshot_size_for_source(100), MIN_SNAP_BYTES);
        assert_eq!(
            snapshot_size_for_source(1024 * 1024 * 1024 * 1024),
            MAX_SNAP_BYTES
        );
        let one_gib = 1024_u64 * 1024 * 1024;
        let expected = (one_gib * 10) / 100 * SNAP_FRACTION_PCT;
        assert_eq!(
            snapshot_size_for_source(one_gib * 10),
            expected.clamp(MIN_SNAP_BYTES, MAX_SNAP_BYTES)
        );
    }

    #[test]
    fn build_script_includes_freeze_trap_when_mount_set() {
        let s = build_create_script("vg0", "root", "scdr-snap-x", 1 << 30, Some("/data"));
        assert!(s.contains("fsfreeze -f \"/data\""));
        assert!(s.contains("trap"));
        assert!(s.contains("fsfreeze -u \"/data\""));
        assert!(s.contains("lvcreate -s -n scdr-snap-x"));
    }

    #[test]
    fn build_script_omits_freeze_when_none() {
        let s = build_create_script("vg0", "root", "scdr-snap-x", 1 << 30, None);
        assert!(!s.contains("fsfreeze"));
        assert!(s.contains("lvcreate -s -n scdr-snap-x"));
    }

    #[test]
    fn probe_returns_true_when_commands_present() {
        let exec = MockExec::new(vec![MockExec::ok("ok\n")]);
        assert!(LvmBackend::new().probe(&exec).unwrap());
    }

    #[test]
    fn probe_returns_false_when_command_missing() {
        let exec = MockExec::new(vec![CommandOutput {
            stdout: String::new(),
            stderr: "not found".into(),
            status: 1,
        }]);
        assert!(!LvmBackend::new().probe(&exec).unwrap());
    }

    #[test]
    fn create_snapshot_issues_size_probe_then_create_then_cleanup() {
        let exec = Arc::new(MockExec::new(vec![
            MockExec::ok("21474836480\n"), // size probe: 20 GiB
            MockExec::ok(""),               // create script success
        ]));
        let backend = LvmBackend::new();
        let req = SnapshotRequest {
            source: "/dev/vg0/root",
            freeze_mount: Some("/"),
            id: "task-001",
        };
        {
            let snap = backend
                .create_snapshot(exec.clone(), &req)
                .expect("create snapshot");
            assert_eq!(snap.backend, "lvm");
            assert_eq!(snap.device_path, "/dev/vg0/scdr-snap-task-001");
            assert_eq!(snap.id, "task-001");
        }
        let log = exec.log.lock().unwrap();
        assert_eq!(log.len(), 3, "size probe + create + cleanup");
        assert!(log[0].contains("lvs --noheadings"));
        assert!(log[1].starts_with("echo "));
        assert!(log[1].contains("base64 -d | bash"));
        assert!(log[2].contains("lvremove -f /dev/vg0/scdr-snap-task-001"));
    }

    #[test]
    fn create_snapshot_propagates_lvcreate_failure() {
        let exec = Arc::new(MockExec::new(vec![
            MockExec::ok("10737418240\n"),
            CommandOutput {
                stdout: String::new(),
                stderr: "Volume group \"vg0\" not found".into(),
                status: 5,
            },
        ]));
        let backend = LvmBackend::new();
        let req = SnapshotRequest {
            source: "/dev/vg0/root",
            freeze_mount: None,
            id: "x",
        };
        let err = backend.create_snapshot(exec, &req).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("lvcreate snapshot"), "{msg}");
        assert!(msg.contains("not found"), "{msg}");
    }
}
