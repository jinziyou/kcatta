"""Remote targets cannot turn scan artifacts into Form memory/disk exhaustion."""

from __future__ import annotations

import base64
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from kcatta_form.deploy.report import finalize_asset_report
from kcatta_form.deploy.ssh import SshSession
from kcatta_form.deploy.winrm import WinRmSession


class _FakeSftp:
    def __init__(
        self, payloads: dict[str, bytes], advertised: dict[str, int] | None = None
    ) -> None:
        self.payloads = payloads
        self.advertised = advertised or {}
        self.opened: list[str] = []

    def stat(self, path: str):
        return SimpleNamespace(st_size=self.advertised.get(path, len(self.payloads[path])))

    def open(self, path: str, mode: str):
        assert mode == "rb"
        self.opened.append(path)
        return io.BytesIO(self.payloads[path])


def _ssh_session(sftp: _FakeSftp) -> SshSession:
    session = object.__new__(SshSession)
    session.host = "test-host"
    session.user = "test-user"
    session.command_timeout = 1.0
    session._client = SimpleNamespace(close=lambda: None)
    session._sftp = sftp
    session._downloaded_artifact_bytes = 0
    return session


def test_ssh_download_stream_enforces_file_growth_and_aggregate_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("FORM_MAX_SCAN_ARTIFACT_BYTES", "8")
    monkeypatch.setenv("FORM_MAX_SCAN_TOTAL_BYTES", "12")
    sftp = _FakeSftp({"/a": b"a" * 7, "/b": b"b" * 7, "/grows": b"x" * 9}, {"/grows": 1})
    session = _ssh_session(sftp)

    session.download("/a", tmp_path / "a.json")
    assert (tmp_path / "a.json").read_bytes() == b"a" * 7
    with pytest.raises(RuntimeError, match="aggregate limit"):
        session.download("/b", tmp_path / "b.json")
    assert not (tmp_path / "b.json").exists()

    growing = _ssh_session(sftp)
    with pytest.raises(RuntimeError, match="grew beyond"):
        growing.download("/grows", tmp_path / "grows.json")
    assert not (tmp_path / "grows.json").exists()


def test_ssh_private_upload_streams_bytes_without_local_file() -> None:
    written: dict[str, bytes] = {}

    class Sink(io.BytesIO):
        def __init__(self, path: str) -> None:
            super().__init__()
            self.path = path

        def close(self) -> None:
            if not self.closed:
                written[self.path] = self.getvalue()
            super().close()

    class UploadSftp:
        def open(self, path: str, mode: str):  # type: ignore[no-untyped-def]
            assert mode == "wb"
            return Sink(path)

    payload = b"private-material" * 8_192
    session = _ssh_session(UploadSftp())  # type: ignore[arg-type]

    session.upload_bytes(payload, "/private/client-key.pem")

    assert written == {"/private/client-key.pem": payload}


def test_winrm_download_checks_open_stream_length_and_never_uses_read_all_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("FORM_MAX_SCAN_ARTIFACT_BYTES", "8")
    monkeypatch.setenv("FORM_MAX_SCAN_TOTAL_BYTES", "12")
    session = object.__new__(WinRmSession)
    session._downloaded_artifact_bytes = 0
    scripts: list[str] = []

    def exec_ok(script: str):
        scripts.append(script)
        payload = base64.b64encode(b"1234567")
        return SimpleNamespace(
            status_code=0,
            std_out=b"__b64_begin__\n" + payload + b"\n__b64_end__\n",
            std_err=b"",
        )

    session.exec = exec_ok
    session.download_file(r"C:\out\host.json", tmp_path / "host.json")

    assert (tmp_path / "host.json").read_bytes() == b"1234567"
    assert "ReadAllBytes" not in scripts[0]
    assert "$fs.Length" in scripts[0]
    assert "$fs.Read(" in scripts[0]
    assert "$total += $count" in scripts[0]
    assert "$remaining" in scripts[0]
    assert "$remaining + 1" in scripts[0]

    session.exec = lambda script: SimpleNamespace(
        status_code=42,
        std_out=b"__too_large=999\n",
        std_err=b"artifact too large",
    )
    with pytest.raises(RuntimeError, match="999 bytes; limit is 8"):
        session.download_file(r"C:\out\packages.json", tmp_path / "packages.json")
    assert not (tmp_path / "packages.json").exists()


def test_report_assembly_rechecks_aggregate_local_artifact_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    host = tmp_path / "host.json"
    packages = tmp_path / "packages.json"
    host.write_text('{"host_id":"h","hostname":"node","os":"Linux"}', encoding="utf-8")
    packages.write_text("[ ]" + " " * 40, encoding="utf-8")
    monkeypatch.setenv("FORM_MAX_SCAN_ARTIFACT_BYTES", "1024")
    monkeypatch.setenv("FORM_MAX_SCAN_TOTAL_BYTES", str(host.stat().st_size + 10))

    with pytest.raises(RuntimeError, match="artifacts total"):
        finalize_asset_report(tmp_path)
