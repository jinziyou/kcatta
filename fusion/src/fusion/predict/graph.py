"""Build a posture graph from observed telemetry for attack-path prediction.

Nodes are hosts; node *facts* are exposure/weakness facts mapped from real
assets and vulnerabilities (open ports → ``service.*`` / ``port.open``, high
severity vulns → ``vuln.exploitable``). Directed edges are network reachability
derived from observed flows (``src → dst:port``). These facts use the same
string vocabulary that the ingested capability graph speaks — fusion constructs them
from its own posture, never importing or naming the red tool.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

# fusion-owned port → service mapping (mirrors the shared ontology conventions;
# the fact strings themselves are the cross-tool contract).
PORT_SERVICE: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
}

_HIGH_SEVERITY = {"high", "critical"}
_WEB_SERVICES = {"service.http", "service.https"}


def service_fact_for_port(port: int | None) -> str | None:
    """Map a well-known port number to a ``service.<name>`` fact, else None."""
    if port is None:
        return None
    name = PORT_SERVICE.get(int(port))
    return f"service.{name}" if name else None


@dataclass
class PostureNode:
    """One host and the attack-relevant facts observed about it."""

    host_id: str
    label: str
    ips: set[str] = field(default_factory=set)
    # exposure facts: port.open / service.* / vuln.exploitable
    facts: set[str] = field(default_factory=set)
    vuln_ids: set[str] = field(default_factory=set)
    max_cvss: float = 0.0  # worst CVSS among this host's exploitable vulns
    is_entry: bool = False  # reachable by an external attacker at t0


@dataclass
class PostureGraph:
    """Hosts + directed reachability edges derived from posture."""

    nodes: dict[str, PostureNode] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def neighbors(self, host_id: str) -> set[str]:
        """Hosts directly reachable from ``host_id`` (observed flows)."""
        return self.edges.get(host_id, set())

    def entry_hosts(self) -> list[str]:
        """Hosts an external attacker can reach at the start (sorted, deterministic)."""
        return sorted(h for h, n in self.nodes.items() if n.is_entry)


def build_posture_graph(
    asset_reports: list[dict],
    detections: list[dict],
    flow_batches: list[dict],
) -> PostureGraph:
    """Assemble a :class:`PostureGraph` from stored telemetry (all plain dicts).

    - ``asset_reports``: ``AssetReport`` records (hosts, ports/services, vulns).
    - ``detections``: ``DetectionResult`` records (fusion-derived vulns per host).
    - ``flow_batches``: ``FlowBatch`` records (reachability edges).
    """
    graph = PostureGraph()

    def node_for(host_id: str, label: str | None = None) -> PostureNode:
        node = graph.nodes.get(host_id)
        if node is None:
            node = PostureNode(host_id=host_id, label=label or host_id)
            graph.nodes[host_id] = node
        return node

    for report in asset_reports:
        host = report.get("host", {})
        host_id = host.get("host_id")
        if not host_id:
            continue
        node = node_for(host_id, host.get("hostname"))
        node.ips.update(str(ip) for ip in host.get("ip_addrs", []))
        for asset in report.get("assets", []):
            kind = asset.get("kind")
            if kind == "port":
                node.facts.add("port.open")
                sf = service_fact_for_port(asset.get("port"))
                if sf:
                    node.facts.add(sf)
            elif kind == "service":
                name = (asset.get("name") or "").lower()
                for svc in PORT_SERVICE.values():
                    if svc in name:
                        node.facts.add(f"service.{svc}")
        _absorb_vulns(node, report.get("vulnerabilities", []))

    for det in detections:
        node = graph.nodes.get(det.get("host_id"))
        if node is not None:
            _absorb_vulns(node, det.get("vulnerabilities", []))

    # Resolve reachability edges via an IP → host index.
    ip_index: dict[str, str] = {}
    for host_id, node in graph.nodes.items():
        for ip in node.ips:
            ip_index[ip] = host_id

    for batch in flow_batches:
        for flow in batch.get("flows", []):
            src = ip_index.get(str(flow.get("src_ip")))
            dst = ip_index.get(str(flow.get("dst_ip")))
            if dst is None:
                continue
            sf = service_fact_for_port(flow.get("dst_port"))
            if sf:
                graph.nodes[dst].facts.add(sf)
            if src is None:
                # traffic from outside the known fleet → dst is externally reachable
                graph.nodes[dst].is_entry = True
            elif src != dst:
                graph.edges[src].add(dst)

    # A host exposing a web service is also treated as an external entry point.
    for node in graph.nodes.values():
        if node.facts & _WEB_SERVICES:
            node.is_entry = True

    return graph


def _absorb_vulns(node: PostureNode, vulns: list[dict]) -> None:
    """Fold high/critical vulnerabilities into a node's exposure facts."""
    for vuln in vulns:
        if (vuln.get("severity") or "").lower() in _HIGH_SEVERITY:
            node.facts.add("vuln.exploitable")
            if vuln.get("vuln_id"):
                node.vuln_ids.add(vuln["vuln_id"])
            node.max_cvss = max(node.max_cvss, float(vuln.get("cvss_score") or 0.0))
