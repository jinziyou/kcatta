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
# 0. build a STATIC agent binary once. probe-asset bundles SQLite (C), so pick one:

#    option A — musl static (needs a musl C compiler, e.g. `apt install musl-tools`)
rustup target add x86_64-unknown-linux-musl
cargo build -p probe-asset --target x86_64-unknown-linux-musl --release
#    -> target/x86_64-unknown-linux-musl/release/probe-asset  (the default --asset-binary)

#    option B — static glibc via the native gcc (no extra C toolchain); then pass
#    --asset-binary target/x86_64-unknown-linux-gnu/release/probe-asset
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build -p probe-asset --target x86_64-unknown-linux-gnu --release

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
| Rust toolchain + a static build | Build the static `probe-asset` to ship — musl target (`rustup target add x86_64-unknown-linux-musl` **plus a musl C compiler** for the bundled SQLite), or static-glibc via the native gcc (`-C target-feature=+crt-static`) |

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
| `--transport` | `ssh` | `ssh` (Linux / OpenSSH) or `winrm` (Windows PowerShell remoting) |
| `--ssh-port` | `22` | SSH port (ignored for WinRM) |
| `--ssh-identity` | managed key | Override the private key path |
| `--ssh-password` / `--ssh-password-stdin` | — | One-shot password (env `SCDR_SSH_PASSWORD`); only used if key auth fails |
| `--target` / `-t` | `host` | `host` \| `packages` \| `sbom` \| `services` \| `accounts` \| `credentials` \| `identity` \| `all` |
| `--output` / `-o` | `.` | Local dir for per-asset JSON (`host.json`, `packages.json`, …) |
| `--asset-binary` | transport-specific | musl Linux binary (SSH) or `probe-asset.exe` (WinRM) |
| `--scan-root` | `/` or `C:\` | Filesystem root on the target |
| `--windows-packages` | `apps` | `full` (include CBS updates) or `apps` (skip CBS noise) |
| `--winrm-password` | — | WinRM password (`PROBE_WINRM_PASSWORD` env); falls back to `--ssh-password` |
| `--winrm-port` | `5986` | WinRM HTTPS port; use `5985` with `--winrm-insecure` |
| `--winrm-insecure` | off | WinRM over HTTP instead of HTTPS |
| `--winrm-skip-cert-check` | off | Skip TLS validation (lab / self-signed) |
| `--task-id` | (random 8 hex) | Stable id for the remote work dir |
| `--upload` | — | POST assembled `AssetReport` to form (`/ingest/asset-report`); requires `host.json` |
| `--malware` | off | Also run `probe-malware` on the target (needs `clamd` there) |
| `--malware-binary` | musl `probe-malware` | Static binary shipped when `--malware` is set |
| `--malware-jobs` | CPU count | Parallel ClamAV workers on the target |
| `--clamd-socket` | auto-detect | `clamd` Unix socket path on the target |
| `--revoke-key` | off | Remove the managed key from the target's `authorized_keys` and exit (no scan); also deletes the local managed keypair |

For `--target host` or `all`, `asset_report.json` is written locally after each
run. With `--upload http://127.0.0.1:8000` the same report is POSTed to form.

## Windows targets (WinRM)

Build a Windows agent binary once:

```bash
rustup target add x86_64-pc-windows-msvc
cargo build -p probe-asset --target x86_64-pc-windows-msvc --release
# -> target/x86_64-pc-windows-msvc/release/probe-asset.exe
```

Run from a Linux or Windows scanner host with PowerShell (`pwsh` or `powershell`) on PATH:

```bash
PROBE_WINRM_PASSWORD='...' cargo run -p probe-remote -- \
    --transport winrm \
    --ssh-host Administrator@10.0.0.50 \
    --target all \
    --output ./reports/win50
```

Requirements on the **target**: WinRM enabled (HTTPS 5986 recommended), account
with remote PowerShell rights. The scanner host runs local PowerShell to open
`New-PSSession` / `Invoke-Command`; no SSH required.

Alternatively, install **OpenSSH Server** on Windows and use `--transport ssh`
with a Windows-built `probe-asset.exe` (same upload/exec pipeline as Linux).

## Cleanup / revoke

The password→key bootstrap leaves one managed key in the target's
`~/.ssh/authorized_keys` (that is what makes later runs key-only). To undo it
and leave no persistent trace on the target:

```bash
probe-remote --ssh-host root@10.22.0.243 --revoke-key
```

This removes **only** the exact line this tool added — every other authorized
key is untouched and the file keeps its mode/owner — then deletes the local
managed keypair under `~/.config/scdr/probe-remote/keys/`. It is a no-op if the
key is already gone, and authenticates with the managed key, falling back to the
password (`SCDR_SSH_PASSWORD`) when the key was already removed.

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
- `--malware` is SSH/Linux only; WinRM transport does not support remote ClamAV yet.
- WinRM uploads/downloads go through base64 over PowerShell; very large JSON pulls may be slow.

## Tests

- Unit tests: `cargo test -p probe-remote`.
- Real-target bootstrap (ignored by default):

```bash
SCDR_TEST_TARGET=user@host SCDR_SSH_PASSWORD=... \
    cargo test -p probe-remote --test integration_bootstrap -- --ignored --nocapture
```
