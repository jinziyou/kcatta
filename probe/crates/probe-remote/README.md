# probe-remote

Agent 模式远端扫描器。架构说明见 [`../../docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md)，主文档见 [`../../README.md`](../../README.md)。

Ships a **static `probe-asset` binary** to a
target over SSH, runs it in place against the live filesystem, pulls the
per-asset JSON back, and removes all traces. The only requirements on the
target are SSH access and a writable directory — **no snapshot, NBD, or
kernel module**.

A **password→key bootstrap** means you provide a password once; the public
key is installed into the target's `authorized_keys`, and every subsequent
run is key-only.

## Quick start (only IP + credentials)

```bash
# 0. build the static agent binary once (pure Rust, no musl-gcc needed)
rustup target add x86_64-unknown-linux-musl
cargo build -p probe-asset --target x86_64-unknown-linux-musl --release

# 1. first run: provide the password (installs the key, then drops it)
SCDR_SSH_PASSWORD='...' cargo run -p probe-remote -- \
    --ssh-host root@10.22.0.243 --target host --output ./reports/10.22.0.243

# 2. subsequent runs: no password needed (key auth)
cargo run -p probe-remote -- \
    --ssh-host root@10.22.0.243 --target host --output ./reports/10.22.0.243
```

The managed key lives at
`~/.config/scdr/probe-remote/keys/<user>@<host>-<port>.ed25519`.

## Pipeline

```
scanner host                          target host
─────────────                         ───────────
ensure key auth (password → key, once)
ssh ControlMaster ──────────────────▶ sshd
probe uname -m  (must match binary arch)
pick writable non-noexec dir          /var/lib/scdr | /opt/scdr | ~/.cache | /tmp
scp probe-asset (static musl) ─────▶ <workdir>/probe-asset
                                       sha256 verify
ssh exec probe-asset -r / -t … ────▶ writes <workdir>/out/*.json
scp pull <workdir>/out/*.json ◀──────
                                       rm -rf <workdir>   (RAII, even on error)
```

The remote work dir is a RAII guard: it is `rm -rf`'d on drop, **even on
error**.

## Requirements

### Scanner host (where you run `probe-remote`)

| Tool | Purpose |
| --- | --- |
| `ssh` / `scp` (OpenSSH) | Control + transfer, multiplexed via `ControlMaster` |
| `ssh-keygen` | Generate the managed ed25519 key on first run |
| Rust + `x86_64-unknown-linux-musl` target | Build the static `probe-asset` to ship |

### Target host

| Requirement | Notes |
| --- | --- |
| SSH access (`user@host`) | Password once, then key |
| A writable, non-`noexec` directory | Auto-picked from `/var/lib/scdr`, `/opt/scdr`, `~/.cache/scdr`, `/tmp` |
| `sha256sum` (optional) | Used to verify the uploaded binary; skipped with a warning if absent |

No agent is installed permanently and no root privileges are required beyond
what the SSH login user already has — the binary runs as that user and is
deleted afterwards.

## CLI

```bash
probe-remote \
    --ssh-host root@10.22.0.243 \
    --asset-binary target/x86_64-unknown-linux-musl/release/probe-asset \
    --target all \
    --output ./reports/10.22.0.243/
```

| Flag | Default | Notes |
| --- | --- | --- |
| `--ssh-host` | (required) | `user@host` |
| `--ssh-port` | `22` | SSH port |
| `--ssh-identity` | managed key | Override the private key path |
| `--ssh-password` / `--ssh-password-stdin` | — | One-shot password (env `SCDR_SSH_PASSWORD`); only used if key auth fails |
| `--target` / `-t` | `host` | `host` \| `packages` \| `sbom` \| `services` \| `accounts` \| `credentials` \| `identity` \| `all` |
| `--output` / `-o` | `.` | Local dir for per-asset JSON (`host.json`, `packages.json`, …) |
| `--asset-binary` | `target/x86_64-unknown-linux-musl/release/probe-asset` | Static binary to ship |
| `--scan-root` | `/` | Filesystem root to scan on the target |
| `--task-id` | (random 8 hex) | Stable id for the remote work dir |
| `--upload` | — | POST assembled `AssetReport` to form (`/ingest/asset-report`); requires `host.json` |
| `--malware` | off | Also run `probe-malware` on the target (needs `clamd` there) |
| `--malware-binary` | musl `probe-malware` | Static binary shipped when `--malware` is set |
| `--malware-jobs` | CPU count | Parallel ClamAV workers on the target |
| `--clamd-socket` | auto-detect | `clamd` Unix socket path on the target |

For `--target host` or `all`, `asset_report.json` is written locally after each
run. With `--upload http://127.0.0.1:8000` the same report is POSTed to form.

```bash
cargo run -p probe-remote -- \
    --ssh-host root@10.22.0.243 --target all --output ./reports/host243 \
    --upload http://127.0.0.1:8000
```

## Compatibility notes

- **musl static** avoids glibc-version mismatch (e.g. building on a newer
  glibc host, running on AlmaLinux 8 / glibc 2.28).
- Ships **x86_64** only; other arches are rejected early with a clear message.
- rpm package collection supports sqlite (RHEL 8+), the ndb `Packages.db`
  backend (openSUSE etc.), and Berkeley DB `Packages` (RHEL 7 / CentOS 7).

```bash
cargo run -p probe-remote -- \
    --ssh-host root@10.22.0.243 --target all --output ./scan-out \
    --malware --upload http://127.0.0.1:8000
```

The target must have ClamAV installed and running (`clamd` + `freshclam`).
`malware.json` is merged into `asset_report.json`'s `vulnerabilities` before
upload to form.

## Limits

- Single target per invocation (sequential).
- Scans the live filesystem (no snapshot); for static assets the consistency
  window is negligible.
- `--upload` needs `host.json` (`--target host` or `all`); SBOM-only pulls are
  not uploaded as an `AssetReport`.
- `--malware` requires `clamd` listening on the **target** (not the scanner host).

## Tests

- Unit tests: `cargo test -p probe-remote`.
- Real-target bootstrap (ignored by default):

```bash
SCDR_TEST_TARGET=user@host SCDR_SSH_PASSWORD=... \
    cargo test -p probe-remote --test integration_bootstrap -- --ignored --nocapture
```
