//! eBPF tracer backend (feature `ebpf`).
//!
//! Loads the `trace-ebpf` programs (compiled by `build.rs`), attaches the
//! process and file tracepoints, drains the shared ring buffer for a bounded
//! window, and converts each record into the contract's [`ProcessTraceEvent`] /
//! [`FileTraceEvent`]. Records are read out of the ring buffer with `bytemuck`
//! against the shared [`agent_ebpf`] layout — no `unsafe` on this side.
//!
//! Loading requires `CAP_BPF`/root and a BTF-enabled kernel; [`capture`] returns
//! a descriptive error otherwise (the caller falls back gracefully).

use std::time::{Duration, Instant};

use agent_contract::{FileOp, FileTraceEvent, ProcessEventType, ProcessTraceEvent};
use agent_ebpf::{file_op, kind, ExecEvent, ExitEvent, FileEvent};
use anyhow::Context as _;
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use chrono::Utc;
use uuid::Uuid;

/// The bpf object built and embedded by `build.rs`.
static TRACE_EBPF: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/trace-ebpf"));

/// How often to poll the ring buffer when it is momentarily empty.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Load the trace programs and attach the tracepoints.
fn load() -> anyhow::Result<Ebpf> {
    let mut ebpf = Ebpf::load(TRACE_EBPF).context(
        "load trace-ebpf object (needs CAP_BPF/root and a BTF-enabled kernel; \
         try `sudo` or run the userspace fallback)",
    )?;
    attach(&mut ebpf, "trace_exec", "sched", "sched_process_exec")?;
    attach(&mut ebpf, "trace_exit", "sched", "sched_process_exit")?;
    attach(&mut ebpf, "trace_openat", "syscalls", "sys_enter_openat")?;
    Ok(ebpf)
}

fn attach(ebpf: &mut Ebpf, prog: &str, category: &str, name: &str) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(prog)
        .with_context(|| format!("program `{prog}` missing from object"))?
        .try_into()
        .with_context(|| format!("`{prog}` is not a tracepoint"))?;
    program.load().with_context(|| format!("load `{prog}`"))?;
    program
        .attach(category, name)
        .with_context(|| format!("attach `{prog}` to {category}/{name}"))?;
    Ok(())
}

/// Decode a NUL-terminated, fixed-width kernel byte buffer into a `String`.
fn decode_cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn op_to_contract(op: u32) -> FileOp {
    match op as u8 {
        file_op::UNLINK => FileOp::Unlink,
        file_op::RENAME => FileOp::Rename,
        _ => FileOp::Open,
    }
}

/// Run the eBPF tracer for `duration`, returning the collected process and file
/// events. `host_id` attributes every event to this collector.
pub fn capture(
    host_id: &str,
    duration: Duration,
) -> anyhow::Result<(Vec<ProcessTraceEvent>, Vec<FileTraceEvent>)> {
    let mut ebpf = load()?;
    let map = ebpf
        .map_mut("EVENTS")
        .context("`EVENTS` ring buffer missing from object")?;
    let mut ring = RingBuf::try_from(map).context("open EVENTS ring buffer")?;

    let mut processes = Vec::new();
    let mut files = Vec::new();
    let deadline = Instant::now() + duration;

    while Instant::now() < deadline {
        let mut drained_any = false;
        while let Some(item) = ring.next() {
            drained_any = true;
            let bytes: &[u8] = &item;
            if bytes.len() < 4 {
                continue;
            }
            match u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) {
                kind::EXEC if bytes.len() >= size_of::<ExecEvent>() => {
                    let e: ExecEvent =
                        bytemuck::pod_read_unaligned(&bytes[..size_of::<ExecEvent>()]);
                    processes.push(ProcessTraceEvent {
                        trace_id: format!("proc-{}", Uuid::new_v4()),
                        host_id: host_id.to_string(),
                        ts: Utc::now(),
                        event_type: ProcessEventType::Exec,
                        pid: e.pid,
                        ppid: (e.ppid != 0).then_some(e.ppid),
                        uid: Some(e.uid),
                        comm: decode_cstr(&e.comm),
                        exe: None,
                        argv: Vec::new(),
                        cgroup: None,
                        exit_code: None,
                        threat_intel: Vec::new(),
                    });
                }
                kind::EXIT if bytes.len() >= size_of::<ExitEvent>() => {
                    let e: ExitEvent =
                        bytemuck::pod_read_unaligned(&bytes[..size_of::<ExitEvent>()]);
                    processes.push(ProcessTraceEvent {
                        trace_id: format!("proc-{}", Uuid::new_v4()),
                        host_id: host_id.to_string(),
                        ts: Utc::now(),
                        event_type: ProcessEventType::Exit,
                        pid: e.pid,
                        ppid: None,
                        uid: None,
                        comm: decode_cstr(&e.comm),
                        exe: None,
                        argv: Vec::new(),
                        cgroup: None,
                        exit_code: None,
                        threat_intel: Vec::new(),
                    });
                }
                kind::FILE if bytes.len() >= size_of::<FileEvent>() => {
                    let e: FileEvent =
                        bytemuck::pod_read_unaligned(&bytes[..size_of::<FileEvent>()]);
                    files.push(FileTraceEvent {
                        trace_id: format!("file-{}", Uuid::new_v4()),
                        host_id: host_id.to_string(),
                        ts: Utc::now(),
                        pid: e.pid,
                        comm: decode_cstr(&e.comm),
                        uid: Some(e.uid),
                        op: op_to_contract(e.op),
                        path: decode_cstr(&e.path),
                        target_path: None,
                        ret: None,
                        threat_intel: Vec::new(),
                    });
                }
                _ => {}
            }
        }
        if !drained_any {
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    Ok((processes, files))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_nul_terminated_comm() {
        let mut buf = [0u8; agent_ebpf::COMM_LEN];
        buf[..4].copy_from_slice(b"bash");
        assert_eq!(decode_cstr(&buf), "bash");
        // A buffer with no NUL uses the whole slice.
        assert_eq!(decode_cstr(b"curl"), "curl");
    }

    #[test]
    fn maps_file_op_codes() {
        assert_eq!(op_to_contract(file_op::OPEN as u32), FileOp::Open);
        assert_eq!(op_to_contract(file_op::UNLINK as u32), FileOp::Unlink);
        assert_eq!(op_to_contract(file_op::RENAME as u32), FileOp::Rename);
        // Unknown codes fall back to Open.
        assert_eq!(op_to_contract(99), FileOp::Open);
    }
}
