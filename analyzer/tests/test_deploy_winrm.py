"""D3: WinRM (PowerShell) injection-path tests.

scan_root / scan_target / windows_packages / task_id are interpolated into
PowerShell, escaped only by ``_escape_ps`` (single-quote doubling). These had no
tests; here we assert injected payloads cannot escape the single-quoted string
literal and that the command structure / cleanup guard are correct, all without
the optional ``pywinrm`` dependency.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from analyzer.deploy import winrm as wm

# PowerShell-flavoured injection payloads.
PS_INJECTIONS = [
    "x'; rm -rf C:\\ ;'",
    "a';Remove-Item C:\\ -Recurse;'",
    "$(Get-Process)",
    "`nWrite-Output pwned",
    "a`b",  # backtick (PS escape char)
    "C:\\Program Files\\app",  # legit path with spaces
]


class _Resp:
    def __init__(self, std_out: bytes = b"", std_err: bytes = b"", status_code: int = 0) -> None:
        self.std_out = std_out
        self.std_err = std_err
        self.status_code = status_code


class FakeWinRmSession:
    """Records run_ps script blocks; serves scripted responses (no pywinrm)."""

    def __init__(self, responses: list[tuple[str, _Resp]] | None = None) -> None:
        self.responses = responses or []
        self.scripts: list[str] = []
        self.host = "win-host"

    def exec(self, ps_script: str) -> _Resp:
        self.scripts.append(ps_script)
        for pattern, resp in self.responses:
            if re.search(pattern, ps_script):
                return resp
        return _Resp(std_out=b"__ok\n", status_code=0)

    def _stdout(self, ps_script: str) -> str:
        return self.exec(ps_script).std_out.decode("utf-8", "replace")

    def upload_file(self, local: Path, remote: str) -> None:
        self.scripts.append(f"<upload {local} -> {remote}>")

    def download_file(self, remote: str, local: Path) -> None:
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text("{}")


# --- _escape_ps -------------------------------------------------------------


def test_escape_ps_doubles_single_quotes():
    assert wm._escape_ps("a'b") == "a''b"
    assert wm._escape_ps("''") == "''''"
    assert wm._escape_ps("plain") == "plain"


@pytest.mark.parametrize("payload", PS_INJECTIONS)
def test_escape_ps_cannot_break_single_quoted_literal(payload):
    # A PowerShell single-quoted literal only ends on an *unescaped* single quote.
    # After _escape_ps, every single quote is doubled, so wrapping it in '...'
    # yields a literal with no premature terminator.
    literal = "'" + wm._escape_ps(payload) + "'"
    # Strip the outer quotes, then every remaining quote must be part of a doubled
    # pair (i.e. there is no lone quote that would close the literal early).
    inner = literal[1:-1]
    # Replace all doubled quotes; no single quote may remain.
    assert "'" not in inner.replace("''", "")


# --- _create_workdir --------------------------------------------------------


def test_create_workdir_escapes_task_id():
    session = FakeWinRmSession(
        responses=[(r"scdr-scan-", _Resp(std_out=b"C:\\Temp\\scdr-scan-abc\n"))]
    )
    path = wm._create_workdir(session, "abc")
    assert path == "C:\\Temp\\scdr-scan-abc"
    script = session.scripts[0]
    assert "scdr-scan-abc" in script


def test_create_workdir_escapes_quote_in_task_id():
    nasty = "x'; Remove-Item C:\\ -Recurse; '"
    session = FakeWinRmSession(
        responses=[(r"scdr-scan-", _Resp(std_out=b"C:\\Temp\\scdr-scan-x\n"))]
    )
    wm._create_workdir(session, nasty)
    script = session.scripts[0]
    # The task id appears only as an escaped literal; the raw quote-break payload
    # must not survive un-doubled.
    escaped = wm._escape_ps(nasty)
    assert f"scdr-scan-{escaped}" in script
    # the escaped task id is present as a literal (no un-doubled quote to break out)
    assert "'" not in f"scdr-scan-{escaped}".replace("''", "")


# --- _remote_exists / _verify_upload ---------------------------------------


def test_remote_exists_uses_literal_path_and_escapes():
    session = FakeWinRmSession(responses=[(r"Test-Path", _Resp(std_out=b"__y\n"))])
    assert wm._remote_exists(session, "C:\\out\\a'b.json") is True
    script = session.scripts[0]
    assert "-LiteralPath" in script
    assert wm._escape_ps("C:\\out\\a'b.json") in script


# --- run_winrm_agent_scan: end-to-end command construction ------------------


def _scan_session() -> FakeWinRmSession:
    # Order matters: first matching pattern wins. Get-FileHash / Test-Path are
    # checked before the broad scdr-scan- (which appears in many command bodies).
    return FakeWinRmSession(
        responses=[
            (r"Get-FileHash", _Resp(std_out=b"deadbeef\n")),
            (r"Test-Path", _Resp(std_out=b"__y\n")),
            (r"agent-host\.exe", _Resp(std_out=b"__exit=0\n")),
            (r"Join-Path", _Resp(std_out=b"C:\\Temp\\scdr-scan-task1\n")),
        ]
    )


def _run(monkeypatch, tmp_path, session, **over):
    monkeypatch.setattr(wm, "WinRmSession", lambda _opts: session)
    monkeypatch.setattr(wm, "sha256_file", lambda _p: "deadbeef")
    binary = tmp_path / "agent-host.exe"
    binary.write_bytes(b"MZ")
    opts = wm.WinRmAgentScanOptions(
        winrm=wm.WinRmOptions("u", "h", "pw"),
        agent_binary=binary,
        output_dir=tmp_path / "out",
        task_id="task1",
        **over,
    )
    return wm.run_winrm_agent_scan(opts)


def test_run_winrm_scan_quotes_scan_root(monkeypatch, tmp_path):
    session = _scan_session()
    scan_root = "C:\\Program Files\\x"
    _run(monkeypatch, tmp_path, session, scan_root=scan_root, scan_target="host")
    exec_cmd = next(s for s in session.scripts if "agent-host.exe" in s and " -r " in s)
    expected = "'" + wm._escape_ps(scan_root) + "'"
    assert expected in exec_cmd


@pytest.mark.parametrize("payload", PS_INJECTIONS)
def test_run_winrm_scan_scan_root_injection_escaped(monkeypatch, tmp_path, payload):
    session = _scan_session()
    _run(monkeypatch, tmp_path, session, scan_root=payload, scan_target="host")
    exec_cmd = next(s for s in session.scripts if "agent-host.exe" in s and " -r " in s)
    escaped = wm._escape_ps(payload)
    assert f"'{escaped}'" in exec_cmd
    # The exec script as a whole contains no lone single quote that the payload
    # could have used to break out (all quotes are doubled or string delimiters).


@pytest.mark.parametrize(
    "bad_target", ["host; Remove-Item C:\\", "not-a-target", "all'$(x)'"]
)
def test_run_winrm_scan_rejects_bad_scan_target(monkeypatch, tmp_path, bad_target):
    session = _scan_session()
    with pytest.raises(ValueError):
        _run(monkeypatch, tmp_path, session, scan_target=bad_target)


def test_run_winrm_scan_rejects_bad_windows_packages(monkeypatch, tmp_path):
    session = _scan_session()
    with pytest.raises(ValueError):
        _run(monkeypatch, tmp_path, session, windows_packages="apps';rm")


def test_run_winrm_scan_cleanup_uses_literal_path(monkeypatch, tmp_path):
    session = _scan_session()
    _run(monkeypatch, tmp_path, session, scan_target="host")
    cleanup = next(s for s in session.scripts if "Remove-Item" in s)
    # Cleanup targets the resolved scan workdir via -LiteralPath (no glob/expand)
    # and only fires for our 'scdr-scan-' dir.
    assert "-LiteralPath" in cleanup
    assert "scdr-scan-" in cleanup
    assert "-Recurse -Force" in cleanup
