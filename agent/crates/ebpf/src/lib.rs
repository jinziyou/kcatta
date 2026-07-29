//! Shared event types passed from the eBPF programs to the userspace loaders.
//!
//! These are plain `#[repr(C)]` POD structs the kernel-side eBPF programs
//! (the `trace-ebpf` bin) write into a ring buffer and the `agent-collect-trace` /
//! `agent-respond` userspace loaders read back. They are `no_std` on the eBPF side;
//! the userspace side reads them with `bytemuck` against this same layout.
//!
//! Ring-buffer events begin with a `kind: u32` discriminator so a single ring
//! can multiplex process/file shapes. Network telemetry uses the separate
//! [`FlowKey`] / [`FlowValue`] LRU hash-map layout to aggregate in-kernel.
//!
//! The structs derive [`bytemuck::Pod`] so the userspace loader can read them
//! straight out of the ring buffer with a layout-checked, `unsafe`-free copy.
//!
//! Licensing: this library is Apache-2.0 (pure POD, no GPL kernel helpers). The
//! kernel programs that share these types live as the GPL-2.0 bin targets of the
//! same `agent-ebpf` crate; see this crate's `src/bin/` and the workspace NOTICE.
#![no_std]
#![deny(unsafe_code)]

use bytemuck::{Pod, Zeroable};

/// Length of the kernel `comm` field (`TASK_COMM_LEN`).
pub const COMM_LEN: usize = 16;
/// Maximum captured path length (longer paths are truncated).
pub const PATH_LEN: usize = 256;

/// Event-kind discriminators (the `kind` field of every event).
pub mod kind {
    /// [`super::ExecEvent`] — a process `execve`.
    pub const EXEC: u32 = 1;
    /// [`super::ExitEvent`] — a process exit.
    pub const EXIT: u32 = 2;
    /// [`super::FileEvent`] — a file operation.
    pub const FILE: u32 = 3;
}

/// File-operation codes (the `op` field of [`FileEvent`]); these mirror the
/// `agent_contract::FileOp` variants the loader maps them to.
pub mod file_op {
    /// `openat` family.
    pub const OPEN: u8 = 0;
    /// `unlinkat` (delete).
    pub const UNLINK: u8 = 1;
    /// `renameat` family (see — `target_path` is not captured in v1).
    pub const RENAME: u8 = 2;
}

/// A process `execve` observed by the eBPF tracer.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ExecEvent {
    /// Always [`kind::EXEC`].
    pub kind: u32,
    /// PID (thread-group id) of the new process image.
    pub pid: u32,
    /// Parent PID, or `0` when not resolved.
    pub ppid: u32,
    /// Acting user id.
    pub uid: u32,
    /// Short program name (`comm`, NUL-padded).
    pub comm: [u8; COMM_LEN],
}

/// A process exit observed by the eBPF tracer.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ExitEvent {
    /// Always [`kind::EXIT`].
    pub kind: u32,
    /// PID (thread-group id) that exited.
    pub pid: u32,
    /// Short program name (`comm`, NUL-padded).
    pub comm: [u8; COMM_LEN],
}

/// Directional L3/L4 flow identity used by the cgroup-skb LRU hash map.
///
/// Multi-byte address/port fields remain in raw network-byte order across the
/// kernel/userspace boundary. IPv4 addresses occupy the first four bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Pod, Zeroable)]
pub struct FlowKey {
    /// IP family: `4` or `6`.
    pub family: u8,
    /// L4 protocol number (TCP=6, UDP=17, ICMP=1, ICMPv6=58).
    pub proto: u8,
    /// Source port, network byte order (zeroed for ICMP / no L4 port).
    pub src_port: [u8; 2],
    /// Destination port, network byte order (zeroed for ICMP / no L4 port).
    pub dst_port: [u8; 2],
    /// Padding to keep the struct free of implicit padding (POD requirement).
    pub _pad: [u8; 2],
    /// Source address (IPv4 in the first 4 bytes).
    pub src_addr: [u8; 16],
    /// Destination address (IPv4 in the first 4 bytes).
    pub dst_addr: [u8; 16],
}

/// In-kernel aggregate for one directional [`FlowKey`].
///
/// The timestamps use the monotonic nanosecond clock returned by
/// `bpf_ktime_get_ns`; userspace anchors that clock to UTC after detaching the
/// probes. The LRU map stores one value slot per CPU; userspace merges those
/// slots after capture, avoiding cross-CPU counter races in the packet path.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod, Zeroable)]
pub struct FlowValue {
    /// Total on-wire bytes observed in this direction.
    pub bytes: u64,
    /// Total packets observed in this direction.
    pub packets: u64,
    /// First observation on the kernel monotonic clock.
    pub first_seen_ns: u64,
    /// Last observation on the kernel monotonic clock.
    pub last_seen_ns: u64,
}

// Kernel map ABI guard: changing either layout requires updating the userspace
// byte-array decoder in `agent-collect-trace` in the same release.
const _: [(); 40] = [(); core::mem::size_of::<FlowKey>()];
const _: [(); 32] = [(); core::mem::size_of::<FlowValue>()];

/// A file operation observed by the eBPF tracer.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct FileEvent {
    /// Always [`kind::FILE`].
    pub kind: u32,
    /// PID performing the operation.
    pub pid: u32,
    /// Acting user id.
    pub uid: u32,
    /// One of the [`file_op`] codes.
    pub op: u32,
    /// Short process name (`comm`, NUL-padded).
    pub comm: [u8; COMM_LEN],
    /// Target path (NUL-terminated, truncated to [`PATH_LEN`]).
    pub path: [u8; PATH_LEN],
}
