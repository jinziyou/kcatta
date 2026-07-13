#!/usr/bin/env python3
"""Validate the rendered Compose topology for Form-only interactions."""

from __future__ import annotations

import json
import sys


def fail(message: str) -> None:
    raise SystemExit(f"component boundary violation: {message}")


def volume_sources(service: dict) -> set[str]:
    return {
        str(volume.get("source"))
        for volume in service.get("volumes", [])
        if volume.get("type") == "volume"
    }


def published_host_ips(service: dict) -> set[str]:
    return {str(port.get("host_ip", "")) for port in service.get("ports", [])}


def published_targets(service: dict) -> set[int]:
    return {int(port["target"]) for port in service.get("ports", [])}


def volume_mounts(service: dict) -> dict[str, dict]:
    return {
        str(volume.get("source")): volume
        for volume in service.get("volumes", [])
        if volume.get("type") == "volume"
    }


def main() -> None:
    config = json.load(sys.stdin)
    services = config["services"]
    admin = services["admin"]
    form = services["form"]
    form_agent = services["form-agent"]
    analyzer = services["analyzer"]

    if set(admin.get("networks", {})) != {"admin-form"}:
        fail("Admin must be attached only to admin-form")
    if set(analyzer.get("networks", {})) != {"form-analyzer"}:
        fail("Analyzer must be attached only to form-analyzer")
    if set(form.get("networks", {})) != {"admin-form", "form-analyzer"}:
        fail("Form must be the sole bridge between Admin and Analyzer networks")
    if set(form_agent.get("networks", {})) != {"form-analyzer"}:
        fail("Agent-facing Form must be attached only to form-analyzer")
    if not config.get("networks", {}).get("form-analyzer", {}).get("internal"):
        fail("form-analyzer network must be internal")
    if analyzer.get("ports"):
        fail("Analyzer must not publish a host port")
    if published_host_ips(admin) != {"127.0.0.1"}:
        fail("default Admin port must bind only to loopback (no built-in human authentication)")
    if published_host_ips(form) != {"127.0.0.1"}:
        fail("default Form port must bind only to loopback until explicitly exposed")
    if published_host_ips(form_agent) != {"127.0.0.1"}:
        fail("default Agent-facing mTLS port must bind only to loopback until explicitly exposed")
    if published_targets(form_agent) != {10443}:
        fail("Agent-facing Form must publish only the dedicated mTLS port 10443")

    secrets = {"form-admin-secret", "form-ingest-secret", "analyzer-internal-secret"}
    expected_mounts = {
        "admin": {"form-admin-secret"},
        "analyzer": {"analyzer-internal-secret"},
        "form": secrets,
        "form-agent": {"analyzer-internal-secret"},
    }
    for name, expected in expected_mounts.items():
        actual = volume_sources(services[name]) & secrets
        if actual != expected:
            fail(f"{name} secret mounts are {sorted(actual)}, expected {sorted(expected)}")

    admin_env = set(admin.get("environment", {}))
    analyzer_env = set(analyzer.get("environment", {}))
    form_env = set(form.get("environment", {}))
    form_agent_env = set(form_agent.get("environment", {}))
    if {"FORM_INGEST_TOKEN", "ANALYZER_INTERNAL_TOKEN"} & admin_env:
        fail("Admin must receive only the Form control credential")
    if {"FORM_API_TOKEN", "FORM_INGEST_TOKEN"} & analyzer_env:
        fail("Analyzer must receive only its internal service credential")
    if not {"FORM_API_TOKEN", "FORM_INGEST_TOKEN", "ANALYZER_INTERNAL_TOKEN"} <= form_env:
        fail("Form must terminate all three credential domains")
    if {"FORM_API_TOKEN", "FORM_INGEST_TOKEN"} & form_agent_env:
        fail("Agent-facing Form must not receive control or legacy fleet credentials")
    if "ANALYZER_INTERNAL_TOKEN" not in form_agent_env:
        fail("Agent-facing Form requires only the Analyzer internal service credential")
    if "FORM_AGENT_TLS_RENEW_CHECK_SECONDS" not in form_env:
        fail("control Form must periodically check and renew its Agent listener leaf")
    if "FORM_AGENT_TLS_RELOAD_POLL_SECONDS" not in form_agent_env:
        fail("Agent-facing Form must monitor published TLS generations")
    if form_agent.get("restart") != "unless-stopped":
        fail("Agent-facing Form must restart after an unexpected listener failure")

    identity_volume = "form-agent-identities"
    tls_volume = "form-agent-tls"
    form_mounts = volume_mounts(form)
    form_agent_mounts = volume_mounts(form_agent)
    agent_private_volumes = {identity_volume, tls_volume, "form-credentials"}
    for name in ("admin", "analyzer"):
        exposed = volume_sources(services[name]) & agent_private_volumes
        if exposed:
            fail(f"{name} must not mount Agent identity/PKI volumes: {sorted(exposed)}")
    if {identity_volume, tls_volume} - form_mounts.keys():
        fail("control Form must mount the Agent identity registry and TLS material")
    if {identity_volume, tls_volume} - form_agent_mounts.keys():
        fail("Agent-facing Form must mount the Agent identity registry and TLS material")
    if form_mounts[tls_volume].get("read_only"):
        fail("control Form needs write access to publish rotated Agent TLS material")
    if not form_agent_mounts[tls_volume].get("read_only"):
        fail("Agent-facing Form TLS material must be mounted read-only")
    if "form-credentials" in form_agent_mounts or "FORM_AGENT_PKI_DIR" in form_agent_env:
        fail("Agent-facing Form must not receive the Agent CA signing key")


if __name__ == "__main__":
    main()
