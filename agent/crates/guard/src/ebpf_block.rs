//! eBPF netblock backend (feature `ebpf`).
//!
//! Loads the `guard-ebpf` cgroup-connect program, attaches it to the cgroup-v2
//! root (host-wide egress), and exposes `block` / `unblock` that toggle entries
//! in the kernel `BLOCKED_V4` / `BLOCKED_V6` maps. The [`crate::respond`] layer
//! uses this in place of `nft` when available, and falls back to `nft` on any
//! load/attach error (so a kernel without cgroup-BPF never loses enforcement).
//!
//! Needs `CAP_BPF` + cgroup-v2 BPF attach at runtime (no `CONFIG_BPF_LSM`).

use std::fs::File;
use std::net::IpAddr;

use anyhow::Context as _;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::Ebpf;

/// The bpf object built and embedded by `build.rs`.
static GUARD_EBPF: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/guard-ebpf"));

/// Default cgroup-v2 root that scopes host-wide egress blocking.
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// A loaded, cgroup-attached eBPF egress blocker.
pub struct EbpfNetblock {
    ebpf: Ebpf,
    // Keep the cgroup fd alive for the lifetime of the attachment.
    _cgroup: File,
}

impl EbpfNetblock {
    /// Load + attach against the default cgroup-v2 root ([`CGROUP_V2_ROOT`]).
    pub fn load_default() -> anyhow::Result<Self> {
        Self::load(CGROUP_V2_ROOT)
    }

    /// Load the program and attach both connect4 and connect6 to `cgroup_path`.
    pub fn load(cgroup_path: &str) -> anyhow::Result<Self> {
        let mut ebpf = Ebpf::load(GUARD_EBPF)
            .context("load guard-ebpf object (needs CAP_BPF + cgroup-v2 BPF)")?;
        let cgroup = File::open(cgroup_path)
            .with_context(|| format!("open cgroup-v2 root {cgroup_path}"))?;

        for prog_name in ["guard_connect4", "guard_connect6"] {
            let program: &mut CgroupSockAddr = ebpf
                .program_mut(prog_name)
                .with_context(|| format!("program `{prog_name}` missing"))?
                .try_into()
                .with_context(|| format!("`{prog_name}` is not a cgroup_sock_addr"))?;
            program
                .load()
                .with_context(|| format!("load `{prog_name}`"))?;
            program
                .attach(&cgroup, CgroupAttachMode::Single)
                .with_context(|| format!("attach `{prog_name}` to {cgroup_path}"))?;
        }

        Ok(Self {
            ebpf,
            _cgroup: cgroup,
        })
    }

    /// Add `ip` to the kernel deny set (idempotent).
    pub fn block(&mut self, ip: IpAddr) -> anyhow::Result<()> {
        match ip {
            IpAddr::V4(v4) => {
                let mut map: AyaHashMap<_, u32, u8> =
                    AyaHashMap::try_from(self.ebpf.map_mut("BLOCKED_V4").context("BLOCKED_V4")?)?;
                // Kernel `user_ip4` is network byte order read as a host u32; load
                // the octets in order to match it.
                map.insert(u32::from_ne_bytes(v4.octets()), 1u8, 0)?;
            }
            IpAddr::V6(v6) => {
                let mut map: AyaHashMap<_, [u8; 16], u8> =
                    AyaHashMap::try_from(self.ebpf.map_mut("BLOCKED_V6").context("BLOCKED_V6")?)?;
                map.insert(v6.octets(), 1u8, 0)?;
            }
        }
        Ok(())
    }

    /// Remove `ip` from the kernel deny set (idempotent).
    pub fn unblock(&mut self, ip: IpAddr) -> anyhow::Result<()> {
        match ip {
            IpAddr::V4(v4) => {
                let mut map: AyaHashMap<_, u32, u8> =
                    AyaHashMap::try_from(self.ebpf.map_mut("BLOCKED_V4").context("BLOCKED_V4")?)?;
                let _ = map.remove(&u32::from_ne_bytes(v4.octets()));
            }
            IpAddr::V6(v6) => {
                let mut map: AyaHashMap<_, [u8; 16], u8> =
                    AyaHashMap::try_from(self.ebpf.map_mut("BLOCKED_V6").context("BLOCKED_V6")?)?;
                let _ = map.remove(&v6.octets());
            }
        }
        Ok(())
    }
}
