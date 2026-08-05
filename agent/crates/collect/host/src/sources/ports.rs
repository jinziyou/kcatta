//! Listening network sockets from `/proc/net/{tcp,tcp6,udp,udp6}`.
//!
//! This is the producer for the long-defined but never-populated [`Port`] asset:
//! a host's live attack surface (which ports are open, and — best-effort — the
//! process behind each).
//!
//! Everything is read **relative to `ctx.scan_root`**, like every other source.
//! That self-gates correctly: a live-root scan (`scan_root == "/"`) reads the
//! real `/proc` and sees real listeners, while an image / chroot / mounted-disk
//! scan reads that target's empty `proc/` and emits nothing — so a listener is
//! never mis-attributed to an offline filesystem.
//!
//! The inode→pid mapping (via `proc/<pid>/fd`) is best-effort and needs
//! privileges to see other users' sockets; `pid` / `process_name` are left
//! `None` whenever it is unavailable.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

use agent_contract::{Asset, CollectionKind, CollectionRun, CollectionRunStatus, Port, PortProto};

use crate::root::join_root;
use crate::ScanContext;

// Per the kernel's tcp_states.h: a listening TCP socket is in state TCP_LISTEN.
const TCP_LISTEN: &str = "0A";
// UDP has no LISTEN state; a bound (server) UDP socket reports TCP_CLOSE here.
const UDP_BOUND: &str = "07";

const PROC_NET_SOURCES: [(&str, PortProto, bool, &str); 4] = [
    ("proc/net/tcp", PortProto::Tcp, false, TCP_LISTEN),
    ("proc/net/tcp6", PortProto::Tcp, true, TCP_LISTEN),
    ("proc/net/udp", PortProto::Udp, false, UDP_BOUND),
    ("proc/net/udp6", PortProto::Udp, true, UDP_BOUND),
];

/// One parsed `/proc/net/*` row for a socket in the wanted state.
struct RawListener {
    addr: String,
    port: u16,
    inode: u64,
}

struct ListenerRead {
    listeners: Vec<(PortProto, RawListener)>,
    unavailable_sources: usize,
    malformed_rows: usize,
}

/// Listening ports under `ctx.scan_root` as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    collect_with_coverage(ctx).0
}

/// Collect listener assets and coverage from the same `/proc/net` reads.
pub(crate) fn collect_with_coverage(ctx: &ScanContext) -> (Vec<Asset>, CollectionRun) {
    let snapshot = read_listeners(ctx);
    let (status, reason) = coverage_from_snapshot(&snapshot);
    let listeners = snapshot.listeners;
    if listeners.is_empty() {
        return (Vec::new(), collection_run(status, reason, 0));
    }

    let wanted: HashSet<u64> = listeners.iter().map(|(_, r)| r.inode).collect();
    let inode_map = build_inode_map(ctx, &wanted);

    // Dedup by (proto, addr, port): a dual-stack listener can appear in both the
    // v4 and v6 tables, and re-scans must be stable.
    let mut seen: HashSet<(&'static str, String, u16)> = HashSet::new();
    let mut out: Vec<Asset> = Vec::new();
    for (proto, raw) in listeners {
        if !seen.insert((proto_str(proto), raw.addr.clone(), raw.port)) {
            continue;
        }
        let (pid, process_name) = match inode_map.get(&raw.inode) {
            Some((pid, name)) => (Some(*pid), Some(name.clone())),
            None => (None, None),
        };
        out.push(Asset::Port(Port {
            asset_id: format!("port-{}-{}-{}", proto_str(proto), raw.addr, raw.port),
            parent_asset_id: None,
            proto,
            port: raw.port,
            listen_addr: raw.addr,
            process_name,
            pid,
        }));
    }
    out.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    let record_count = out.len();
    (out, collection_run(status, reason, record_count))
}

fn coverage_from_snapshot(snapshot: &ListenerRead) -> (CollectionRunStatus, Option<&'static str>) {
    if snapshot.unavailable_sources == PROC_NET_SOURCES.len() {
        return (
            CollectionRunStatus::Failed,
            Some("proc_net_sources_unavailable"),
        );
    }

    if snapshot.unavailable_sources > 0 {
        return (
            CollectionRunStatus::Partial,
            Some("proc_net_sources_partial"),
        );
    }
    if snapshot.malformed_rows > 0 {
        return (CollectionRunStatus::Partial, Some("proc_net_rows_skipped"));
    }
    (CollectionRunStatus::Complete, None)
}

fn collection_run(
    status: CollectionRunStatus,
    reason: Option<&str>,
    record_count: usize,
) -> CollectionRun {
    CollectionRun {
        collector: CollectionKind::Port,
        status,
        record_count,
        reason: reason.map(str::to_string),
    }
}

fn read_listeners(ctx: &ScanContext) -> ListenerRead {
    let mut listeners = Vec::new();
    let mut unavailable_sources = 0;
    let mut malformed_rows = 0;
    for (rel, proto, v6, want_state) in PROC_NET_SOURCES {
        let Ok(content) = fs::read_to_string(join_root(ctx, rel)) else {
            unavailable_sources += 1;
            continue;
        };
        let (rows, skipped) = parse_proc_net_with_stats(&content, v6, want_state);
        malformed_rows += skipped;
        listeners.extend(rows.into_iter().map(|raw| (proto, raw)));
    }
    ListenerRead {
        listeners,
        unavailable_sources,
        malformed_rows,
    }
}

fn proto_str(proto: PortProto) -> &'static str {
    match proto {
        PortProto::Tcp => "tcp",
        PortProto::Udp => "udp",
    }
}

fn sort_key(asset: &Asset) -> (u16, &'static str, &str) {
    match asset {
        Asset::Port(p) => (p.port, proto_str(p.proto), p.listen_addr.as_str()),
        _ => (0, "", ""),
    }
}

/// Parse a `/proc/net/{tcp,udp}[6]` table, keeping rows in `want_state`.
#[cfg(test)]
fn parse_proc_net(content: &str, v6: bool, want_state: &str) -> Vec<RawListener> {
    parse_proc_net_with_stats(content, v6, want_state).0
}

fn parse_proc_net_with_stats(
    content: &str,
    v6: bool,
    want_state: &str,
) -> (Vec<RawListener>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0;
    let mut lines = content.lines();
    let Some(header) = lines.next() else {
        return (out, 1);
    };
    if !valid_proc_net_header(header) {
        return (out, 1);
    }
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        // Columns: sl(0) local(1) rem(2) st(3) tx:rx(4) tr:tm(5) retrnsmt(6)
        //          uid(7) timeout(8) inode(9) ...
        let mut cols = line.split_whitespace();
        let _sl = cols.next();
        let Some(local) = cols.next() else {
            skipped += 1;
            continue;
        };
        let _rem = cols.next();
        let Some(state) = cols.next() else {
            skipped += 1;
            continue;
        };
        if state.len() != 2 || !state.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            skipped += 1;
            continue;
        }
        if !state.eq_ignore_ascii_case(want_state) {
            continue;
        }
        // inode is the 6th token after `state` (skip tx:rx, tr:tm, retrnsmt, uid, timeout).
        let Some(inode_str) = cols.nth(5) else {
            skipped += 1;
            continue;
        };
        let Ok(inode) = inode_str.parse::<u64>() else {
            skipped += 1;
            continue;
        };

        let Some((addr_hex, port_hex)) = local.split_once(':') else {
            skipped += 1;
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            skipped += 1;
            continue;
        };
        if port == 0 {
            continue;
        }
        let Some(addr) = (if v6 {
            parse_hex_ipv6(addr_hex)
        } else {
            parse_hex_ipv4(addr_hex)
        }) else {
            skipped += 1;
            continue;
        };
        out.push(RawListener { addr, port, inode });
    }
    (out, skipped)
}

fn valid_proc_net_header(header: &str) -> bool {
    let fields: Vec<&str> = header.split_whitespace().collect();
    fields.first() == Some(&"sl")
        && fields.contains(&"local_address")
        && fields.contains(&"rem_address")
        && fields.contains(&"st")
        && fields.contains(&"inode")
}

/// `/proc/net/tcp` IPv4: a host-order hex word, little-endian on the wire
/// (`0100007F` -> `127.0.0.1`).
fn parse_hex_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let word = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(word.to_le_bytes()).to_string())
}

/// `/proc/net/tcp6` IPv6: four host-order hex words, each little-endian.
fn parse_hex_ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

/// Best-effort map of socket inode -> (pid, process name) via `proc/<pid>/fd`.
///
/// Only the inodes in `wanted` are recorded. Any unreadable pid/fd (no
/// privileges, racing process exit) is skipped, so the map is partial by design.
fn build_inode_map(ctx: &ScanContext, wanted: &HashSet<u64>) -> HashMap<u64, (u32, String)> {
    let mut map: HashMap<u64, (u32, String)> = HashMap::new();
    let Ok(entries) = fs::read_dir(join_root(ctx, "proc")) else {
        return map;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let pid_dir = entry.path();
        let Ok(fds) = fs::read_dir(pid_dir.join("fd")) else {
            continue;
        };
        let mut name: Option<String> = None;
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if !wanted.contains(&inode) {
                continue;
            }
            if name.is_none() {
                name = fs::read_to_string(pid_dir.join("comm"))
                    .ok()
                    .map(|s| s.trim().to_string());
            }
            let pname = name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("pid {pid}"));
            map.entry(inode).or_insert((pid, pname));
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    // A real `/proc/net/tcp` header + an sshd LISTEN on 0.0.0.0:22 (inode 10001)
    // and an ESTABLISHED connection (must be ignored).
    const TCP_SAMPLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10001 1 0000 100 0 0 10 0
   1: 0100007F:0050 0100007F:1234 01 00000000:00000000 00:00000000 00000000     0        0 10002 1 0000 100 0 0 10 0
";

    #[test]
    fn parses_listening_ipv4_only() {
        let rows = parse_proc_net(TCP_SAMPLE, false, TCP_LISTEN);
        assert_eq!(rows.len(), 1, "only the LISTEN row");
        assert_eq!(rows[0].addr, "0.0.0.0");
        assert_eq!(rows[0].port, 22);
        assert_eq!(rows[0].inode, 10001);
    }

    #[test]
    fn parses_loopback_and_ipv6_any() {
        assert_eq!(parse_hex_ipv4("0100007F").unwrap(), "127.0.0.1");
        assert_eq!(parse_hex_ipv4("00000000").unwrap(), "0.0.0.0");
        assert_eq!(
            parse_hex_ipv6("00000000000000000000000000000000").unwrap(),
            "::"
        );
        assert_eq!(
            parse_hex_ipv6("00000000000000000000000001000000").unwrap(),
            "::1"
        );
    }

    #[test]
    fn collect_emits_port_asset_with_pid_from_proc() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("proc/net")).unwrap();
        fs::write(root.join("proc/net/tcp"), TCP_SAMPLE).unwrap();
        // A process owning socket inode 10001, named "sshd".
        fs::create_dir_all(root.join("proc/777/fd")).unwrap();
        fs::write(root.join("proc/777/comm"), "sshd\n").unwrap();
        symlink("socket:[10001]", root.join("proc/777/fd/3")).unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Port(p) => {
                assert_eq!(p.proto, PortProto::Tcp);
                assert_eq!(p.port, 22);
                assert_eq!(p.listen_addr, "0.0.0.0");
                assert_eq!(p.pid, Some(777));
                assert_eq!(p.process_name.as_deref(), Some("sshd"));
                assert_eq!(p.asset_id, "port-tcp-0.0.0.0-22");
            }
            other => panic!("expected port, got {other:?}"),
        }
    }

    #[test]
    fn collect_dedups_same_listener_listed_twice() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("proc/net")).unwrap();
        // The same (tcp, 0.0.0.0, 22) listener appearing twice collapses to one.
        let dup = "   2: 00000000:0016 00000000:0000 0A 00000000:00000000 \
00:00000000 00000000     0        0 10001 1 0000 100 0 0 10 0\n";
        fs::write(root.join("proc/net/tcp"), format!("{TCP_SAMPLE}{dup}")).unwrap();

        let assets = collect(&ScanContext::at(root));
        assert_eq!(assets.len(), 1);
    }

    #[test]
    fn collect_on_image_without_proc_is_empty() {
        let temp = tempfile::tempdir().unwrap();
        // No proc/ at all (a mounted image): nothing to attribute.
        let ctx = ScanContext::at(temp.path());
        let (assets, run) = collect_with_coverage(&ctx);
        assert!(assets.is_empty());
        assert_eq!(run.record_count, assets.len());
        assert_eq!(run.status, CollectionRunStatus::Failed);
        assert_eq!(run.reason.as_deref(), Some("proc_net_sources_unavailable"));
    }

    #[test]
    fn coverage_distinguishes_verified_zero_and_malformed_rows() {
        let complete = tempfile::tempdir().unwrap();
        fs::create_dir_all(complete.path().join("proc/net")).unwrap();
        for source in ["tcp", "tcp6", "udp", "udp6"] {
            fs::write(
                complete.path().join("proc/net").join(source),
                "sl local_address rem_address st tx rx tr uid timeout inode\n",
            )
            .unwrap();
        }
        let (assets, run) = collect_with_coverage(&ScanContext::at(complete.path()));
        assert!(assets.is_empty());
        assert_eq!(run.record_count, assets.len());
        assert_eq!(run.status, CollectionRunStatus::Complete);
        assert!(run.reason.is_none());

        fs::remove_file(complete.path().join("proc/net/udp6")).unwrap();
        let (assets, run) = collect_with_coverage(&ScanContext::at(complete.path()));
        assert!(assets.is_empty());
        assert_eq!(run.record_count, assets.len());
        assert_eq!(run.status, CollectionRunStatus::Partial);
        assert_eq!(run.reason.as_deref(), Some("proc_net_sources_partial"));
        fs::write(
            complete.path().join("proc/net/udp6"),
            "sl local_address rem_address st tx rx tr uid timeout inode\n",
        )
        .unwrap();

        fs::write(
            complete.path().join("proc/net/tcp"),
            "sl local_address rem_address st tx rx tr uid timeout inode\nmalformed\n",
        )
        .unwrap();
        let (assets, run) = collect_with_coverage(&ScanContext::at(complete.path()));
        assert!(assets.is_empty());
        assert_eq!(run.record_count, assets.len());
        assert_eq!(run.status, CollectionRunStatus::Partial);
        assert_eq!(run.reason.as_deref(), Some("proc_net_rows_skipped"));

        for malformed in ["", "garbage\n"] {
            fs::write(complete.path().join("proc/net/tcp"), malformed).unwrap();
            let (assets, run) = collect_with_coverage(&ScanContext::at(complete.path()));
            assert!(assets.is_empty());
            assert_eq!(run.record_count, assets.len());
            assert_eq!(run.status, CollectionRunStatus::Partial);
            assert_eq!(run.reason.as_deref(), Some("proc_net_rows_skipped"));
        }
    }
}
