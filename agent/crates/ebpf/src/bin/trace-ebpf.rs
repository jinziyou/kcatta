//! kcatta agent-trace eBPF programs (kernel side).
//!
//! Tracepoints feed one ring buffer, multiplexed by the leading `kind`
//! field of each [`agent_ebpf`] event:
//!   * `sched/sched_process_exec`     → [`ExecEvent`]  (program invocations)
//!   * `sched/sched_process_exit`     → [`ExitEvent`]  (process exits)
//!   * `syscalls/sys_enter_openat`    → [`FileEvent`] op=OPEN
//!   * `syscalls/sys_enter_unlinkat`  → [`FileEvent`] op=UNLINK (deletes)
//!   * `syscalls/sys_enter_renameat2` → [`FileEvent`] op=RENAME (renames)
//!
//! When the ring buffer is full, the dropped event is counted in the `DROPPED`
//! per-CPU map so the userspace loader can report loss instead of it being
//! silent — silent loss would let an attacker mask activity with an event storm.
//!
//! The `agent-trace` userspace loader attaches these, drains the ring buffer,
//! and converts the records into `ProcessTraceEvent` / `FileTraceEvent`.
#![no_std]
#![no_main]

use agent_ebpf::{file_op, kind, ExecEvent, ExitEvent, FileEvent, NetEvent, PATH_LEN};
use aya_ebpf::{
    cty::c_long,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        gen::bpf_probe_read_user_str,
    },
    macros::{cgroup_skb, map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::{SkBuffContext, TracePointContext},
};

/// Single ring buffer carrying every event kind (256 KiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU count of events dropped because the ring buffer was full. The
/// userspace loader sums this after draining and surfaces it (loss is then
/// quantifiable, not silent).
#[map]
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Record one dropped event (ring buffer was full).
fn bump_dropped() {
    if let Some(counter) = DROPPED.get_ptr_mut(0) {
        unsafe {
            *counter += 1;
        }
    }
}

/// `const char *filename`/`pathname` lives at offset 24 in the `sys_enter_openat`
/// and `sys_enter_unlinkat` tracepoint records (common header 8 + syscall_nr 8 +
/// dfd 8). For `sys_enter_renameat2` the *old* name pointer is also at offset 24
/// (header 8 + nr 8 + olddfd 8); the new name (offset 40) is not captured in v1.
const PATHNAME_OFF: usize = 24;

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
    match EVENTS.reserve::<ExecEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => bump_dropped(),
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
    match EVENTS.reserve::<ExitEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => bump_dropped(),
    }
    Ok(())
}

#[tracepoint]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    let _ = try_file_op(&ctx, file_op::OPEN);
    0
}

/// `syscalls/sys_enter_unlinkat` — file deletes (op = UNLINK).
#[tracepoint]
pub fn trace_unlinkat(ctx: TracePointContext) -> u32 {
    let _ = try_file_op(&ctx, file_op::UNLINK);
    0
}

/// `syscalls/sys_enter_renameat2` — file renames (op = RENAME; old path only in v1).
#[tracepoint]
pub fn trace_renameat(ctx: TracePointContext) -> u32 {
    let _ = try_file_op(&ctx, file_op::RENAME);
    0
}

/// Emit a [`FileEvent`] for an open/unlink/rename tracepoint. The path (or, for
/// rename, the old path) pointer is at [`PATHNAME_OFF`] in all three records.
fn try_file_op(ctx: &TracePointContext, op: u8) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1_i64)?;
    // The user-space pointer to the path argument.
    let filename: *const u8 = unsafe { ctx.read_at::<*const u8>(PATHNAME_OFF)? };

    let Some(mut entry) = EVENTS.reserve::<FileEvent>(0) else {
        bump_dropped();
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
        (*ptr).op = op as u32;
        (*ptr).comm = comm;
        // Best-effort copy of the path; leaves the buffer zeroed on failure.
        let path = (*ptr).path.as_mut_ptr() as *mut core::ffi::c_void;
        bpf_probe_read_user_str(path, PATH_LEN as u32, filename as *const core::ffi::c_void);
    }
    entry.submit(0);
    Ok(())
}

// ---- Network flow telemetry (cgroup-skb backend) -------------------------------
//
// L4 telemetry: one [`NetEvent`] per packet (5-tuple + on-wire length) into the
// shared ring buffer; the userspace loader aggregates them into bidirectional
// flows. Emitting per-packet records (rather than an in-kernel aggregation map)
// keeps the userspace drain `bytemuck`-based and `unsafe`-free and reuses the
// existing ring-buffer + drop-counter path. No L7 (JA3/SNI/DNS) — that stays with
// the pcap backend. cgroup-skb sees the packet at L3 (no Ethernet header).

#[cgroup_skb]
pub fn net_egress(ctx: SkBuffContext) -> i32 {
    let _ = emit_net_event(&ctx);
    1 // always allow — observe only, never drop
}

#[cgroup_skb]
pub fn net_ingress(ctx: SkBuffContext) -> i32 {
    let _ = emit_net_event(&ctx);
    1
}

/// Parse the L3/L4 5-tuple and emit one [`NetEvent`] to the ring buffer.
fn emit_net_event(ctx: &SkBuffContext) -> Result<(), c_long> {
    let version_ihl: u8 = ctx.load(0)?;
    let version = version_ihl >> 4;
    if version != 4 && version != 6 {
        return Ok(());
    }

    let Some(mut entry) = EVENTS.reserve::<NetEvent>(0) else {
        bump_dropped();
        return Ok(());
    };
    let ptr = entry.as_mut_ptr();
    let ok = unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<NetEvent>());
        (*ptr).kind = kind::NET;
        (*ptr).bytes = ctx.len();
        fill_net_tuple(ctx, &mut *ptr, version_ihl, version)
    };
    match ok {
        Ok(()) => entry.submit(0),
        // A short/truncated packet we couldn't fully parse: discard the slot.
        Err(_) => entry.discard(0),
    }
    Ok(())
}

/// Fill the 5-tuple of a zeroed `NetEvent` from the L3 packet (offset 0 = IP header).
fn fill_net_tuple(
    ctx: &SkBuffContext,
    ev: &mut NetEvent,
    version_ihl: u8,
    version: u8,
) -> Result<(), c_long> {
    if version == 4 {
        ev.family = 4;
        ev.proto = ctx.load(9)?;
        let src: [u8; 4] = ctx.load(12)?;
        let dst: [u8; 4] = ctx.load(16)?;
        ev.src_addr[..4].copy_from_slice(&src);
        ev.dst_addr[..4].copy_from_slice(&dst);
        let ihl = ((version_ihl & 0x0f) as usize) * 4;
        if ev.proto == 6 || ev.proto == 17 {
            ev.src_port = ctx.load(ihl)?;
            ev.dst_port = ctx.load(ihl + 2)?;
        }
    } else {
        ev.family = 6;
        ev.proto = ctx.load(6)?; // next header (no ext-header chasing in v1)
        ev.src_addr = ctx.load(8)?;
        ev.dst_addr = ctx.load(24)?;
        if ev.proto == 6 || ev.proto == 17 {
            ev.src_port = ctx.load(40)?;
            ev.dst_port = ctx.load(42)?;
        }
    }
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
