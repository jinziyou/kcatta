//! Shared event types passed from the eBPF programs to the userspace loaders.
//!
//! These are plain `#[repr(C)]` POD structs the kernel-side eBPF programs
//! (`trace-ebpf`, `guard-ebpf`) write into a ring buffer and the `agent-trace` /
//! `agent-guard` userspace loaders read back. They are `no_std` on the eBPF side;
//! the `user` feature adds the `aya::Pod` impls the loader needs to copy them out.
//!
//! Every event begins with a `kind: u32` discriminator so a single ring buffer
//! can multiplex the three event shapes; the reader peeks `kind` then casts.
//!
//! The structs derive [`bytemuck::Pod`] so the userspace loader can read them
//! straight out of the ring buffer with a layout-checked, `unsafe`-free copy.
#![no_std]

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
