//! kcatta agent-trace eBPF programs (kernel side).
//!
//! Three tracepoints feed one ring buffer, multiplexed by the leading `kind`
//! field of each [`ebpf_common`] event:
//!   * `sched/sched_process_exec`  → [`ExecEvent`]  (program invocations)
//!   * `sched/sched_process_exit`  → [`ExitEvent`]  (process exits)
//!   * `syscalls/sys_enter_openat` → [`FileEvent`]  (file opens)
//!
//! The `agent-trace` userspace loader attaches these, drains the ring buffer,
//! and converts the records into `ProcessTraceEvent` / `FileTraceEvent`.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        gen::bpf_probe_read_user_str,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ebpf_common::{file_op, kind, ExecEvent, ExitEvent, FileEvent, PATH_LEN};

/// Single ring buffer carrying every event kind (256 KiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// `const char *filename` lives at offset 24 in the `sys_enter_openat` tracepoint
/// record (common header 8 + syscall_nr 8 + dfd 8).
const OPENAT_FILENAME_OFF: usize = 24;

#[tracepoint]
pub fn trace_exec(ctx: TracePointContext) -> u32 {
    let _ = try_exec(&ctx);
    0
}

fn try_exec(_ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1_i64)?;
    let event = ExecEvent {
        kind: kind::EXEC,
        pid,
        // ppid via task_struct->real_parent needs CO-RE bindings; left 0 (unknown),
        // resolved best-effort by the userspace loader from /proc when available.
        ppid: 0,
        uid,
        comm,
    };
    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
    Ok(())
}

#[tracepoint]
pub fn trace_exit(ctx: TracePointContext) -> u32 {
    let _ = try_exit(&ctx);
    0
}

fn try_exit(_ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1_i64)?;
    let event = ExitEvent {
        kind: kind::EXIT,
        pid,
        comm,
    };
    if let Some(mut entry) = EVENTS.reserve::<ExitEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
    Ok(())
}

#[tracepoint]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    let _ = try_openat(&ctx);
    0
}

fn try_openat(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1_i64)?;
    // The user-space pointer to the path argument.
    let filename: *const u8 = unsafe { ctx.read_at::<*const u8>(OPENAT_FILENAME_OFF)? };

    let Some(mut entry) = EVENTS.reserve::<FileEvent>(0) else {
        return Ok(());
    };
    let ptr = entry.as_mut_ptr();
    // Zero the whole record first so no uninitialized padding is submitted
    // (the verifier rejects ring-buffer entries with uninitialized bytes).
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<FileEvent>());
        (*ptr).kind = kind::FILE;
        (*ptr).pid = pid;
        (*ptr).uid = uid;
        (*ptr).op = file_op::OPEN as u32;
        (*ptr).comm = comm;
        // Best-effort copy of the path; leaves the buffer zeroed on failure.
        let path = (*ptr).path.as_mut_ptr() as *mut core::ffi::c_void;
        bpf_probe_read_user_str(path, PATH_LEN as u32, filename as *const core::ffi::c_void);
    }
    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // eBPF programs cannot unwind; the verifier guarantees this is unreachable.
    loop {}
}

/// Kernel BPF helpers used here (probe-read) are GPL-only; declare the license
/// so the verifier permits them.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
