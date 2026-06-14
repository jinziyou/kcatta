"""Attack-path prediction: kcatta-graph build, forward-chaining, and API.

The synthetic environment is the canonical demo: an externally-reachable web
host with a high-severity vuln, plus an internal SSH host the web host can reach.
The predictor should chain web exploit -> internal discovery -> credential loot
-> SSH lateral -> local privesc, reaching admin on the internal host.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.predict import build_kcatta_graph, predict_paths
from analyzer.schemas import CapabilityGraph, TechniqueCapability

NOW = datetime(2026, 6, 6, 12, 0, 0, tzinfo=UTC)

WEB_IP = "10.0.0.10"
APP_IP = "10.0.0.20"


def _pilot_capabilities() -> list[TechniqueCapability]:
    return [
        TechniqueCapability(
            module_id="initial_access.exploit_public_app_nuclei",
            techniques=["T1190"],
            tactic="initial-access",
            preconditions=["service.http|service.https", "vuln.exploitable"],
            postconditions=["access.foothold"],
        ),
        TechniqueCapability(
            module_id="discovery.network_service_scan",
            techniques=["T1046"],
            tactic="discovery",
            preconditions=["access.foothold"],
            postconditions=["host.discovered", "port.open"],
        ),
        TechniqueCapability(
            module_id="credential_access.unsecured_credentials_scan",
            techniques=["T1552.001"],
            tactic="credential-access",
            preconditions=["access.foothold"],
            postconditions=["cred.password", "cred.ssh_key"],
        ),
        TechniqueCapability(
            module_id="lateral_movement.ssh_remote_exec",
            techniques=["T1021.004"],
            tactic="lateral-movement",
            preconditions=["service.ssh", "cred.password|cred.ssh_key"],
            postconditions=["access.user", "access.foothold"],
        ),
        TechniqueCapability(
            module_id="privilege_escalation.linux_kernel_exploit_suggester",
            techniques=["T1068"],
            tactic="privilege-escalation",
            preconditions=["access.user|access.foothold"],
            postconditions=["access.admin"],
        ),
        # noise: a recon module whose output nothing consumes — must not appear in paths
        TechniqueCapability(
            module_id="reconnaissance.tcp_port_scan",
            techniques=["T1595.001"],
            tactic="reconnaissance",
            preconditions=["net.reachable"],
            postconditions=["port.open"],
        ),
    ]


def _web_report() -> dict:
    return {
        "host": {"host_id": "h-web", "hostname": "web-01", "ip_addrs": [WEB_IP]},
        "assets": [{"kind": "port", "asset_id": "web-443", "proto": "tcp", "port": 443}],
        "vulnerabilities": [
            {"vuln_id": "CVE-2024-9999", "severity": "high", "affected_asset_id": "web-443"}
        ],
    }


def _app_report() -> dict:
    return {
        "host": {"host_id": "h-app", "hostname": "app-01", "ip_addrs": [APP_IP]},
        "assets": [{"kind": "port", "asset_id": "app-22", "proto": "tcp", "port": 22}],
        "vulnerabilities": [],
    }


def _flows() -> list[dict]:
    return [
        {
            "events": [
                {"src_ip": "203.0.113.5", "dst_ip": WEB_IP, "dst_port": 443},
                {"src_ip": WEB_IP, "dst_ip": APP_IP, "dst_port": 22},
            ]
        }
    ]


# --- pure engine / graph ---------------------------------------------------


def test_kcatta_graph_facts_and_edges():
    graph = build_kcatta_graph([_web_report(), _app_report()], [], _flows())
    assert "service.https" in graph.nodes["h-web"].facts
    assert "vuln.exploitable" in graph.nodes["h-web"].facts
    assert "service.ssh" in graph.nodes["h-app"].facts
    assert graph.nodes["h-web"].is_entry  # web-exposed
    assert not graph.nodes["h-app"].is_entry  # internal, only reachable via the edge
    assert "h-app" in graph.neighbors("h-web")


def test_predicts_lateral_chain_to_admin():
    graph = build_kcatta_graph([_web_report(), _app_report()], [], _flows())
    paths = predict_paths(graph, _pilot_capabilities())

    deep = [p for p in paths if p.goal_host == "h-app"]
    assert deep, f"expected a path reaching the internal host; got {[p.goal_host for p in paths]}"
    path = deep[0]
    assert path.goal == "access.admin"
    assert path.severity.value == "high"
    modules = [s.module_id for s in path.steps]
    assert modules == [
        "initial_access.exploit_public_app_nuclei",
        "credential_access.unsecured_credentials_scan",
        "discovery.network_service_scan",
        "lateral_movement.ssh_remote_exec",
        "privilege_escalation.linux_kernel_exploit_suggester",
    ]
    # noise recon module never contributes to a path
    assert "reconnaissance.tcp_port_scan" not in modules
    assert set(path.related_asset_ids) == {"h-web", "h-app"}
    assert path.related_vuln_ids == ["CVE-2024-9999"]


def test_no_paths_without_capabilities():
    graph = build_kcatta_graph([_web_report(), _app_report()], [], _flows())
    assert predict_paths(graph, []) == []


def test_no_paths_without_exploitable_entry():
    # Strip the vuln -> exploit precondition unmet -> no foothold -> no path.
    web = _web_report()
    web["vulnerabilities"] = []
    graph = build_kcatta_graph([web, _app_report()], [], _flows())
    assert predict_paths(graph, _pilot_capabilities()) == []


def test_converge_collapses_interchangeable_module_variants():
    # Two privesc modules both reach admin from a foothold: the same logical
    # route, so prediction must report ONE converged path (deterministic rep =
    # smallest module sequence), not one per module.
    graph = build_kcatta_graph([_web_report()], [], [])
    caps = [
        TechniqueCapability(
            module_id="initial_access.exploit_public_app_nuclei",
            techniques=["T1190"],
            tactic="initial-access",
            preconditions=["service.http|service.https", "vuln.exploitable"],
            postconditions=["access.foothold"],
        ),
        TechniqueCapability(
            module_id="privilege_escalation.aaa_privesc",
            techniques=["T1068"],
            tactic="privilege-escalation",
            preconditions=["access.foothold"],
            postconditions=["access.admin"],
        ),
        TechniqueCapability(
            module_id="privilege_escalation.zzz_privesc",
            techniques=["T1548"],
            tactic="privilege-escalation",
            preconditions=["access.foothold"],
            postconditions=["access.admin"],
        ),
    ]
    web_admin = [p for p in predict_paths(graph, caps) if p.goal_host == "h-web"]
    assert len(web_admin) == 1
    assert web_admin[0].steps[-1].module_id == "privilege_escalation.aaa_privesc"


def test_objective_goals_chain_collection_to_exfil_and_impact():
    # Objective facts drive paths to real campaign outcomes; exfil consumes the
    # data.collected produced by collection (collection -> exfiltration chain).
    graph = build_kcatta_graph([_web_report()], [], [])
    caps = [
        TechniqueCapability(
            module_id="initial_access.exploit_public_app_nuclei",
            techniques=["T1190"],
            tactic="initial-access",
            preconditions=["service.http|service.https", "vuln.exploitable"],
            postconditions=["access.foothold"],
        ),
        TechniqueCapability(
            module_id="collection.local_data_staging",
            techniques=["T1074"],
            tactic="collection",
            preconditions=["access.foothold"],
            postconditions=["data.collected"],
        ),
        TechniqueCapability(
            module_id="exfiltration.exfil_over_https",
            techniques=["T1048"],
            tactic="exfiltration",
            preconditions=["data.collected"],
            postconditions=["data.exfiltrated"],
        ),
        TechniqueCapability(
            module_id="impact.data_encrypt",
            techniques=["T1486"],
            tactic="impact",
            preconditions=["access.foothold"],
            postconditions=["impact.achieved"],
        ),
    ]
    by_goal = {p.goal: p for p in predict_paths(graph, caps)}

    assert "data.exfiltrated" in by_goal
    exfil = by_goal["data.exfiltrated"]
    assert [s.module_id for s in exfil.steps] == [
        "initial_access.exploit_public_app_nuclei",
        "collection.local_data_staging",
        "exfiltration.exfil_over_https",
    ]
    assert exfil.severity.value == "high"

    assert "impact.achieved" in by_goal
    assert by_goal["impact.achieved"].severity.value == "critical"


def _exploit_cap() -> TechniqueCapability:
    return TechniqueCapability(
        module_id="initial_access.exploit_public_app_nuclei",
        techniques=["T1190"],
        tactic="initial-access",
        preconditions=["service.http|service.https", "vuln.exploitable"],
        postconditions=["access.foothold"],
    )


def _privesc_cap() -> TechniqueCapability:
    return TechniqueCapability(
        module_id="privilege_escalation.kernel",
        techniques=["T1068"],
        tactic="privilege-escalation",
        preconditions=["access.user|access.foothold"],
        postconditions=["access.admin"],
    )


def test_perimeter_only_blocks_free_internal_foothold():
    # A no-precondition vector (phishing) may foothold the entry host but must
    # NOT hand a free foothold to an internal host reached via discovery.
    graph = build_kcatta_graph([_web_report(), _app_report()], [], _flows())
    caps = [
        _exploit_cap(),
        TechniqueCapability(
            module_id="discovery.network_service_scan",
            techniques=["T1046"],
            tactic="discovery",
            preconditions=["access.foothold"],
            postconditions=["host.discovered", "port.open"],
        ),
        TechniqueCapability(
            module_id="initial_access.phishing",
            techniques=["T1566"],
            tactic="initial-access",
            preconditions=[],
            postconditions=["access.foothold"],
        ),
        _privesc_cap(),
    ]
    goal_hosts = {p.goal_host for p in predict_paths(graph, caps)}
    assert "h-web" in goal_hosts  # web compromised via exploit -> privesc
    assert "h-app" not in goal_hosts  # internal not free-footholded by phishing


def test_score_reflects_cvss_and_length():
    web = _web_report()
    web["vulnerabilities"][0]["cvss_score"] = 9.8
    graph = build_kcatta_graph([web], [], [])
    admin = next(
        p
        for p in predict_paths(graph, [_exploit_cap(), _privesc_cap()])
        if p.goal == "access.admin"
    )
    # high tier (75) + CVSS 9.8 bonus (+6) - 2-step length penalty (0)
    assert admin.score == 81


def test_c2_and_persistence_are_goals():
    graph = build_kcatta_graph([_web_report()], [], [])
    caps = [
        _exploit_cap(),
        TechniqueCapability(
            module_id="command_and_control.http_c2_beacon",
            techniques=["T1071"],
            tactic="command-and-control",
            preconditions=["access.foothold"],
            postconditions=["c2.established"],
        ),
        TechniqueCapability(
            module_id="persistence.cron_job",
            techniques=["T1053"],
            tactic="persistence",
            preconditions=["access.foothold"],
            postconditions=["persistence.established"],
        ),
    ]
    goals = {p.goal for p in predict_paths(graph, caps)}
    assert "c2.established" in goals
    assert "persistence.established" in goals


# --- API integration -------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(data_dir=tmp_path)
    with TestClient(app) as test_client:
        yield test_client


def _full_asset_report(report_id: str, report: dict) -> dict:
    host = {
        "host_id": report["host"]["host_id"],
        "hostname": report["host"]["hostname"],
        "os": "Ubuntu 22.04",
        "ip_addrs": report["host"]["ip_addrs"],
    }
    assets = [
        {**a, "listen_addr": "0.0.0.0"} if a["kind"] == "port" else a for a in report["assets"]
    ]
    vulns = [{**v, "source": "nuclei"} for v in report["vulnerabilities"]]
    return {
        "report_id": report_id,
        "collected_at": NOW.isoformat(),
        "scanner_version": "0.1.0",
        "host": host,
        "assets": assets,
        "vulnerabilities": vulns,
    }


def _full_trace_batch() -> dict:
    events = []
    for i, f in enumerate(_flows()[0]["events"]):
        events.append(
            {
                "trace_id": f"f-{i}",
                "host_id": "col-1",
                "start_ts": NOW.isoformat(),
                "end_ts": NOW.isoformat(),
                "proto": "tcp",
                "src_ip": f["src_ip"],
                "dst_ip": f["dst_ip"],
                "dst_port": f["dst_port"],
                "bytes_sent": 100,
                "bytes_recv": 100,
            }
        )
    return {
        "batch_id": "b-1",
        "collected_at": NOW.isoformat(),
        "collector_id": "col-1",
        "collector_version": "0.1.0",
        "events": events,
    }


def _capability_graph_payload() -> dict:
    cg = CapabilityGraph(
        ontology_version="0.1",
        capabilities=_pilot_capabilities(),
        templates=[],
    )
    return cg.model_dump(mode="json")


def _post(c: TestClient, path: str, payload: dict) -> None:
    resp = c.post(path, json=payload)
    assert resp.status_code == 202, resp.text


def _seed_kcatta(c: TestClient) -> None:
    _post(c, "/ingest/asset-report", _full_asset_report("r-web", _web_report()))
    _post(c, "/ingest/asset-report", _full_asset_report("r-app", _app_report()))
    _post(c, "/ingest/trace-batch", _full_trace_batch())


def test_capability_graph_ingest_and_predict(client):
    _seed_kcatta(client)
    resp = client.post("/ingest/capability-graph", json=_capability_graph_payload())
    assert resp.status_code == 202, resp.text

    resp = client.get("/attack-paths")
    assert resp.status_code == 200, resp.text
    paths = resp.json()
    deep = [p for p in paths if p["goal_host"] == "h-app"]
    assert deep, f"expected internal-host path; got {paths}"
    path = deep[0]
    assert path["goal"] == "access.admin"
    assert path["steps"][0]["module_id"] == "initial_access.exploit_public_app_nuclei"
    assert path["steps"][-1]["module_id"] == "privilege_escalation.linux_kernel_exploit_suggester"
    assert path["generated_at"] is not None

    # fetch by id round-trips
    by_id = client.get(f"/attack-paths/{path['path_id']}")
    assert by_id.status_code == 200
    assert by_id.json()["path_id"] == path["path_id"]


def test_attack_paths_empty_without_capability_graph(client):
    _seed_kcatta(client)
    resp = client.get("/attack-paths")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_attack_path_404(client):
    _seed_kcatta(client)
    client.post("/ingest/capability-graph", json=_capability_graph_payload())
    assert client.get("/attack-paths/path-does-not-exist").status_code == 404
