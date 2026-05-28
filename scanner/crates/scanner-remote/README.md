# scanner-remote

Agentless remote scanner. Drives `scanner-asset` against a **snapshot** of a
remote host's filesystem, **without installing anything on the target**.

> Status: MVP-1 — **LVM snapshot** + **NBD over SSH** only.

## How it works

```
scanner host                           target host (no agent)
─────────────                          ────────────────────────
ssh ── ControlMaster ─────────────────▶ sshd
                                       sudo fsfreeze + lvcreate -s    (snapshot)
                                       sudo qemu-nbd --bind=127.0.0.1
ssh -L 10809:127.0.0.1:10809 ─────────▶ qemu-nbd
sudo nbd-client 127.0.0.1 10809 /dev/nbd0
sudo mount -o ro /dev/nbd0 /mnt/scdr-scan-<id>
scanner-asset -r /mnt/scdr-scan-<id> -t all -o ./reports/
                                       (drop order: umount → nbd-client -d →
                                       ssh -L close → kill qemu-nbd → lvremove)
```

All four remote/local resources (snapshot, qemu-nbd, ssh-L, mount) are RAII
guards: dropping the top-level `NbdMount` / `RemoteSnapshot` tears them down
in reverse, **even on error**.

## Requirements

### Target host

| Tool | Purpose |
| --- | --- |
| `lvcreate` / `lvremove` / `lvs` (`lvm2`) | Build & remove the snapshot |
| `qemu-nbd` (`qemu-utils` / `qemu-img`) | Expose the snapshot over loopback NBD |
| `fsfreeze` (`util-linux`) | Optional crash-consistency |
| `ss`, `awk`, `bash`, `base64` | Probe + script transport |

A low-privilege account with **sudo NOPASSWD** for the commands in
[`docs/scdr-scan.sudoers`](docs/scdr-scan.sudoers). The account never gets
shell-level root.

### Scanner host

| Tool | Purpose |
| --- | --- |
| `ssh` (OpenSSH) | Control + data channel (multiplexed via `ControlMaster`) |
| `nbd-client` (`nbd-client` package) | Attach the tunneled NBD export to `/dev/nbdN` |
| `nbd` kernel module | Provides `/dev/nbdN` (loaded on demand) |
| `mount`, `sudo` | Local read-only mount |

`scanner-remote` itself currently shells out to `sudo` for `nbd-client`,
`mount`, and `umount`. Run as a user with passwordless `sudo` for those, or
run as root.

## Install the sudoers fragment on the target

```bash
scp docs/scdr-scan.sudoers scdr@TARGET:/tmp/scdr-scan
ssh scdr@TARGET 'sudo install -m 0440 /tmp/scdr-scan /etc/sudoers.d/scdr-scan && sudo visudo -c'
```

## Verify target readiness

Run the pre-flight check on the target as the SSH account scanner-remote will
use (e.g. `scdr`). It validates commands, kernel, `dm-snapshot`, sudoers
whitelist, LVM free space, and qemu-nbd version.

```bash
scp docs/scdr-remote-precheck.sh scdr@TARGET:/tmp/
ssh scdr@TARGET 'bash /tmp/scdr-remote-precheck.sh'
```

Exits 0 only when every required item is `OK`. `MISS` lines list exactly what
to fix; `INFO`/`WARN` are non-blocking.

## CLI

```bash
scanner-remote \
    --ssh-host scdr@10.0.1.23 \
    --ssh-identity ~/.ssh/scdr_ed25519 \
    --lv /dev/vg0/root \
    --freeze-mount / \
    --target all \
    --output ./reports/10.0.1.23/
```

Useful flags:

| Flag | Default | Notes |
| --- | --- | --- |
| `--ssh-port` | `22` | SSH port |
| `--nbd-device` | `/dev/nbd0` | Local block device to attach |
| `--nbd-port` | `10809` | Tunnel TCP port (IANA NBD) |
| `--mount-base` | `/mnt` | Mount goes under `<base>/scdr-scan-<task-id>` |
| `--fs-type` | (auto) | `mount -t <type>` hint |
| `--task-id` | (random 8 hex) | Stable id for snapshot name + mount path |

Output mirrors `scanner-asset`: `host.json` / `packages.json` under
`--output`.

## Operational notes

- **Single-host, sequential** in MVP-1. Concurrent scans on the same scanner
  host need distinct `--nbd-device` and `--nbd-port` values.
- **Stale state recovery**: if a previous run was killed before cleanup,
  manually `sudo umount /mnt/scdr-scan-*`, `sudo nbd-client -d /dev/nbdN`,
  and `ssh target 'sudo lvremove -f /dev/VG/scdr-snap-*'` once.
- **Network sensitivity**: NBD does **per-block synchronous reads**, so RTT
  matters. Aim for RTT < 300 ms. For high-latency / lossy links, prefer the
  agent variant (future MVP-2).
- **Security**: snapshots can contain secrets. The local mount uses
  `ro,noexec,nodev,nosuid`. The target's NBD listener is bound to
  `127.0.0.1` and only reachable through the SSH tunnel.

## Limits in MVP-1

- LVM only (Btrfs / ZFS / qemu image planned via `SnapshotBackend` trait).
- Single target per invocation.
- No automatic stale-resource recovery between runs.
- No `--upload`/ingest yet (use the JSON output).
