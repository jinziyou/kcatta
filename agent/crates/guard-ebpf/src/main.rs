//! kcatta agent-guard eBPF blocker (kernel side).
//!
//! A `cgroup/connect4` (+`connect6`) program that denies outbound connections to
//! destination IPs the userspace guard has placed in the `BLOCKED_V4` /
//! `BLOCKED_V6` maps — kernel-level egress blocking that replaces the userspace
//! `nft` netblock when the `ebpf` feature is enabled. Returns `1` (allow) on any
//! error so a map/verifier hiccup can never wedge the host's networking.
//!
//! Note: this needs cgroup-v2 BPF attach (common); unlike eBPF-LSM it does NOT
//! require `CONFIG_BPF_LSM`.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

/// Blocked IPv4 destinations, keyed by `user_ip4` (network byte order, as the
/// kernel presents it). Value is an unused marker.
#[map]
static BLOCKED_V4: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

/// Blocked IPv6 destinations, keyed by the 16-byte address.
#[map]
static BLOCKED_V6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(4096, 0);

/// connect(2) verdict: `1` = allow, `0` = block (`EPERM` to the caller).
const ALLOW: i32 = 1;
const BLOCK: i32 = 0;

#[cgroup_sock_addr(connect4)]
pub fn guard_connect4(ctx: SockAddrContext) -> i32 {
    let dst_ip = unsafe { (*ctx.sock_addr).user_ip4 };
    if unsafe { BLOCKED_V4.get(&dst_ip) }.is_some() {
        return BLOCK;
    }
    ALLOW
}

#[cgroup_sock_addr(connect6)]
pub fn guard_connect6(ctx: SockAddrContext) -> i32 {
    let mut addr = [0u8; 16];
    let words = unsafe { (*ctx.sock_addr).user_ip6 };
    // `user_ip6` is four `__be32` words; copy their bytes out in order.
    for (i, word) in words.iter().enumerate() {
        let bytes = word.to_ne_bytes();
        addr[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    if unsafe { BLOCKED_V6.get(&addr) }.is_some() {
        return BLOCK;
    }
    ALLOW
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Map helpers are GPL-only; declare the license so the verifier permits them.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
