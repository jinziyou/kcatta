"""WinRM remote scan for Windows targets (optional, needs ``pywinrm``).

Mirrors the SSH agent pipeline over PowerShell remoting: ship ``agent.exe``,
run ``agent host`` against ``C:\\``, pull the per-asset JSON back (base64 over
WinRM), then clean up. Install the extra with ``pip install 'posture-fusion[winrm]'``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

from ._util import (
    expected_files,
    parse_marked_exit,
    sha256_file,
    short_id,
    validate_scan_options,
)

_UPLOAD_CHUNK = 192 * 1024


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace")


@dataclass
class WinRmOptions:
    """WinRM connection parameters (``user@host`` + TLS)."""

    user: str
    host: str
    password: str
    port: int = 5986
    use_ssl: bool = True
    skip_cert_check: bool = False

    @classmethod
    def from_user_host(
        cls,
        target: str,
        password: str,
        port: int = 5986,
        use_ssl: bool = True,
        skip_cert_check: bool = False,
    ) -> WinRmOptions:
        user, sep, host = target.rpartition("@")
        if not sep or not user or not host:
            raise ValueError(f"expected user@host, got {target!r}")
        return cls(user, host, password, port, use_ssl, skip_cert_check)


@dataclass
class WinRmAgentScanOptions:
    """Parameters for :func:`run_winrm_agent_scan`."""

    winrm: WinRmOptions
    agent_binary: Path
    output_dir: Path
    scan_target: str = "host"
    scan_root: str = "C:\\"
    task_id: str | None = None
    windows_packages: str = "apps"


class WinRmSession:
    """A pywinrm session that runs PowerShell script blocks on the target."""

    def __init__(self, opts: WinRmOptions) -> None:
        try:
            import winrm  # type: ignore
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "WinRM transport needs pywinrm — install with: pip install 'posture-fusion[winrm]'"
            ) from exc

        scheme = "https" if opts.use_ssl else "http"
        endpoint = f"{scheme}://{opts.host}:{opts.port}/wsman"
        self._session = winrm.Session(
            endpoint,
            auth=(opts.user, opts.password),
            transport="ntlm",
            server_cert_validation="ignore" if opts.skip_cert_check else "validate",
        )
        self.host = opts.host
        check = self.exec("Write-Output __ok")
        if "__ok" not in _text(check.std_out):
            raise RuntimeError(f"WinRM connectivity check failed: {_text(check.std_err).strip()}")

    def exec(self, ps_script: str):  # returns pywinrm Response
        return self._session.run_ps(ps_script)

    def _stdout(self, ps_script: str) -> str:
        result = self.exec(ps_script)
        return result.std_out.decode("utf-8", "replace")

    def upload_file(self, local: Path, remote: str) -> None:
        data = local.read_bytes()
        remote_ps = _ps_single_quote(remote)
        for index in range(0, max(len(data), 1), _UPLOAD_CHUNK):
            chunk = data[index : index + _UPLOAD_CHUNK]
            b64 = base64.b64encode(chunk).decode("ascii")
            if index == 0:
                script = (
                    f"[IO.File]::WriteAllBytes({remote_ps}, [Convert]::FromBase64String('{b64}'))"
                )
            else:
                script = (
                    f"$fs = [IO.File]::Open({remote_ps}, "
                    "[IO.FileMode]::Append, [IO.FileAccess]::Write); "
                    f"try {{ $b = [Convert]::FromBase64String('{b64}'); "
                    "$fs.Write($b, 0, $b.Length) } finally { $fs.Close() }"
                )
            result = self.exec(script)
            if result.status_code != 0:
                raise RuntimeError(
                    f"upload chunk to {remote} failed: {_text(result.std_err).strip()}"
                )

    def download_file(self, remote: str, local: Path) -> None:
        remote_ps = _ps_single_quote(remote)
        out = self._stdout(
            f"$b = [IO.File]::ReadAllBytes({remote_ps}); "
            "Write-Output '__b64_begin__'; "
            "Write-Output ([Convert]::ToBase64String($b)); "
            "Write-Output '__b64_end__'"
        )
        payload = _extract_b64_payload(out)
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(base64.b64decode(payload))


def run_winrm_agent_scan(opts: WinRmAgentScanOptions):
    """Run the WinRM agent pipeline: upload, exec, pull, cleanup."""
    from .agent import AgentScanReport  # reuse the SSH report shape

    task_id = opts.task_id or short_id()

    # Reject unknown scan_target / windows_packages before they reach the remote
    # PowerShell command (defense in depth alongside the _escape_ps quoting below).
    validate_scan_options(opts.scan_target, opts.windows_packages)

    if not opts.agent_binary.is_file():
        raise FileNotFoundError(
            f"agent binary not found: {opts.agent_binary}\n"
            "build it first: cargo build -p agent-runtime "
            "--target x86_64-pc-windows-msvc --release"
        )

    session = WinRmSession(opts.winrm)
    workdir = _create_workdir(session, task_id)
    try:
        remote_bin = f"{workdir}\\agent.exe"
        remote_out = f"{workdir}\\out"

        session.upload_file(opts.agent_binary, remote_bin)
        _verify_upload(session, opts.agent_binary, remote_bin)

        run = session.exec(
            f"New-Item -ItemType Directory -Force -Path '{_escape_ps(remote_out)}' | Out-Null; "
            f"& '{_escape_ps(remote_bin)}' host -r '{_escape_ps(opts.scan_root)}' "
            f"-t '{_escape_ps(opts.scan_target)}' "
            f"--windows-packages '{_escape_ps(opts.windows_packages)}' "
            f"-o '{_escape_ps(remote_out)}'; "
            'Write-Output "__exit=$LASTEXITCODE"'
        )
        stdout = _text(run.std_out)
        if parse_marked_exit(stdout) != 0:
            raise RuntimeError(
                f"remote agent host failed (exit {parse_marked_exit(stdout)})\n"
                f"stdout: {stdout.strip()}\nstderr: {_text(run.std_err).strip()}"
            )

        opts.output_dir.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []
        for fname in expected_files(opts.scan_target):
            remote_file = f"{remote_out}\\{fname}"
            if not _remote_exists(session, remote_file):
                continue
            local_file = opts.output_dir / fname
            session.download_file(remote_file, local_file)
            files.append(local_file)

        if not files:
            raise RuntimeError(
                f"remote scan produced no JSON under {remote_out} (target={opts.scan_target})"
            )
        return AgentScanReport(task_id=task_id, files=files)
    finally:
        if "scdr-scan-" in workdir:
            session.exec(
                f"Remove-Item -LiteralPath '{_escape_ps(workdir)}' -Recurse -Force "
                "-ErrorAction SilentlyContinue"
            )


def _create_workdir(session: WinRmSession, task_id: str) -> str:
    # task_id is escaped: a single quote in it would otherwise close the string
    # literal and inject PowerShell (and could also defeat the cleanup guard).
    out = session.exec(
        f"$p = Join-Path $env:TEMP 'scdr-scan-{_escape_ps(task_id)}'; "
        "New-Item -ItemType Directory -Force -Path $p | Out-Null; Write-Output $p"
    )
    resolved = out.std_out.decode("utf-8", "replace").strip().splitlines()
    path = resolved[-1].strip() if resolved else ""
    if not path:
        raise RuntimeError(
            f"failed to create remote work dir: {out.std_err.decode('utf-8', 'replace').strip()}"
        )
    return path


def _verify_upload(session: WinRmSession, local: Path, remote_path: str) -> None:
    local_sum = sha256_file(local)
    out = session.exec(
        f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{_escape_ps(remote_path)}').Hash.ToLower()"
    )
    remote_sum = out.std_out.decode("utf-8", "replace").strip().splitlines()
    remote_sum = remote_sum[-1].strip().lower() if remote_sum else ""
    if not remote_sum:
        print("[fusion.deploy/winrm] Get-FileHash returned empty; skipping integrity check")
        return
    if remote_sum != local_sum:
        raise RuntimeError(
            f"uploaded binary sha256 mismatch (local {local_sum}, remote {remote_sum})"
        )


def _remote_exists(session: WinRmSession, path: str) -> bool:
    out = session.exec(f"if (Test-Path -LiteralPath '{_escape_ps(path)}') {{ Write-Output __y }}")
    return "__y" in out.std_out.decode("utf-8", "replace")


def _ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _escape_ps(value: str) -> str:
    return value.replace("'", "''")


def _extract_b64_payload(stdout: str) -> str:
    lines: list[str] = []
    in_payload = False
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped == "__b64_begin__":
            in_payload = True
            continue
        if stripped == "__b64_end__":
            break
        if in_payload:
            lines.append(stripped)
    if not lines:
        raise RuntimeError("missing __b64_begin__/__b64_end__ markers in WinRM stdout")
    return "".join(lines)
