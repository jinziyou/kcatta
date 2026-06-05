"""Posture-grounded attack-path prediction (forward-chaining, v0).

Given a :class:`PostureGraph` (real exposure facts + reachability) and a set of
red-team technique capabilities (each with ontology pre/postconditions), walk
the graph the way an adversary would: from external entry points, apply any
technique whose preconditions the current state satisfies, accrue its
postconditions (foothold / creds / discovered hosts), expand reachability, and
repeat to a fixpoint. Then reconstruct each chain that reaches a privileged goal
into an :class:`AttackPath`.

Deterministic and rule-based — no randomness, no search heuristics — so the same
inputs always yield the same paths and ids.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..schemas import AttackPath, AttackPathStep, Severity, TechniqueCapability
from .graph import PostureGraph

# Goal facts (campaign objectives), most-valuable first. Reaching any of these
# is a path worth reporting — privilege as well as real outcomes (impact/exfil).
_GOAL_FACTS = (
    "access.domain_admin",
    "impact.achieved",
    "access.admin",
    "data.exfiltrated",
)
# Objective/effect facts advance attacker state (host-scoped) so post-compromise
# chains link up — e.g. collection produces data.collected which exfiltration
# consumes — instead of dead-ending.
_OBJECTIVE_FACTS = frozenset(
    {
        "data.collected",
        "data.exfiltrated",
        "c2.established",
        "persistence.established",
        "impact.achieved",
    }
)
_GOAL_SEVERITY = {
    "access.domain_admin": Severity.CRITICAL,
    "impact.achieved": Severity.CRITICAL,
    "access.admin": Severity.HIGH,
    "data.exfiltrated": Severity.HIGH,
    "access.foothold": Severity.MEDIUM,
}
_SEVERITY_SCORE = {
    Severity.INFO: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 95,
}


@dataclass
class _Application:
    """One technique applied on one host during the forward chain."""

    idx: int
    host: str
    cap: TechniqueCapability
    preconditions_met: list[str]
    postconditions_gained: list[str]
    support: set[int] = field(default_factory=set)  # application indices this depends on


def _match_preconditions(preconditions: list[str], facts: set[str]) -> list[str] | None:
    """Return one satisfying fact per precondition element, or None if any is unmet.

    Each element may list ``|``-separated alternatives (any-of); all elements
    must be satisfied (and-of).
    """
    matched: list[str] = []
    for element in preconditions:
        alts = [a.strip() for a in element.split("|") if a.strip()]
        hit = next((a for a in alts if a in facts), None)
        if hit is None:
            return None
        matched.append(hit)
    return matched


def predict_paths(
    graph: PostureGraph,
    capabilities: list[TechniqueCapability],
) -> list[AttackPath]:
    """Predict posture-grounded attack paths. Returns paths sorted by score desc."""
    caps = sorted(
        (c for c in capabilities if c.preconditions or c.postconditions),
        key=lambda c: c.module_id,
    )
    entry = set(graph.entry_hosts())
    reached: set[str] = set(entry)
    host_access: dict[str, set[str]] = {}  # host_id -> {access.*}
    global_creds: set[str] = set()  # cred.* are reusable fleet-wide once looted
    applications: list[_Application] = []
    fact_producer: dict[tuple[str, str], int] = {}  # (scope, fact) -> app idx; scope=host or "*"
    reach_producer: dict[str, int] = {}  # discovered host -> app idx that reached it
    applied: set[tuple[str, str]] = set()  # (module_id, host) guard

    def available(host: str) -> set[str]:
        base = graph.nodes[host].facts | {"net.reachable"}
        return base | host_access.get(host, set()) | global_creds

    changed = True
    while changed:
        changed = False
        for host in sorted(reached):
            facts = available(host)
            for cap in caps:
                key = (cap.module_id, host)
                if key in applied:
                    continue
                matched = _match_preconditions(cap.preconditions, facts)
                if matched is None:
                    continue
                idx = len(applications)
                support: set[int] = set()
                for fact in matched:
                    producer = fact_producer.get((host, fact))
                    if producer is None:
                        producer = fact_producer.get(("*", fact))
                    if producer is not None:
                        support.add(producer)
                if host not in entry and host in reach_producer:
                    support.add(reach_producer[host])
                applications.append(
                    _Application(
                        idx=idx,
                        host=host,
                        cap=cap,
                        preconditions_met=matched,
                        postconditions_gained=list(cap.postconditions),
                        support=support,
                    )
                )
                applied.add(key)
                changed = True
                _apply_effects(
                    cap,
                    host,
                    idx,
                    graph,
                    reached,
                    host_access,
                    global_creds,
                    fact_producer,
                    reach_producer,
                )

    return _extract_paths(graph, applications, entry)


def _apply_effects(
    cap: TechniqueCapability,
    host: str,
    idx: int,
    graph: PostureGraph,
    reached: set[str],
    host_access: dict[str, set[str]],
    global_creds: set[str],
    fact_producer: dict[tuple[str, str], int],
    reach_producer: dict[str, int],
) -> None:
    """Fold a technique's postconditions into the attacker state."""
    for post in cap.postconditions:
        if post.startswith("cred."):
            fact_producer.setdefault(("*", post), idx)
            global_creds.add(post)
        elif post.startswith("access.") or post in _OBJECTIVE_FACTS:
            # access levels and objective milestones are host-scoped gains; the
            # latter let downstream steps (e.g. exfil after collection) chain.
            fact_producer.setdefault((host, post), idx)
            host_access.setdefault(host, set()).add(post)
        elif post == "host.discovered":
            for neighbor in graph.neighbors(host):
                if neighbor not in reached:
                    reached.add(neighbor)
                    reach_producer.setdefault(neighbor, idx)
        # port.open / service.* / resource.developed / defense.evaded are
        # informational — they don't advance the attacker's reachable state.


def _extract_paths(
    graph: PostureGraph,
    applications: list[_Application],
    entry: set[str],
) -> list[AttackPath]:
    """Turn goal-reaching applications into deduplicated, scored AttackPaths."""
    goals = [
        app for app in applications if any(g in app.postconditions_gained for g in _GOAL_FACTS)
    ]
    if not goals:
        # Fallback: a foothold gained on a non-entry host is still a real path.
        goals = [
            app
            for app in applications
            if app.host not in entry and "access.foothold" in app.postconditions_gained
        ]

    paths: dict[str, AttackPath] = {}
    for goal in goals:
        closure: set[int] = set()
        stack = [goal.idx]
        while stack:
            i = stack.pop()
            if i in closure:
                continue
            closure.add(i)
            stack.extend(applications[i].support)

        ordered = [applications[i] for i in sorted(closure)]
        goal_fact = next(
            g for g in (*_GOAL_FACTS, "access.foothold") if g in goal.postconditions_gained
        )
        path = _build_path(graph, ordered, goal, goal_fact)
        paths[path.path_id] = path

    return _converge(list(paths.values()))


def _converge(paths: list[AttackPath]) -> list[AttackPath]:
    """Collapse near-duplicate routes for a clean report.

    The full technique catalog otherwise yields one path per interchangeable
    module (e.g. one per privilege-escalation module that reaches admin on the
    same host). Paths that traverse the same ``(host, tactic)`` sequence are the
    same logical route, so keep a single deterministic representative (the
    lexicographically smallest module sequence). Sort by score desc, then fewest
    steps, then ``path_id``.
    """

    def _shape(p: AttackPath) -> tuple:
        return tuple((s.host_id, s.tactic) for s in p.steps)

    def _modules(p: AttackPath) -> tuple:
        return tuple(s.module_id for s in p.steps)

    best: dict[tuple, AttackPath] = {}
    for path in paths:
        key = _shape(path)
        rep = best.get(key)
        if rep is None or _modules(path) < _modules(rep):
            best[key] = path
    return sorted(best.values(), key=lambda p: (-p.score, len(p.steps), p.path_id))


def _build_path(
    graph: PostureGraph,
    ordered: list[_Application],
    goal: _Application,
    goal_fact: str,
) -> AttackPath:
    steps = [
        AttackPathStep(
            host_id=app.host,
            host_label=graph.nodes[app.host].label,
            module_id=app.cap.module_id,
            technique_id=app.cap.techniques[0] if app.cap.techniques else "",
            tactic=app.cap.tactic,
            preconditions_met=app.preconditions_met,
            postconditions_gained=app.postconditions_gained,
        )
        for app in ordered
    ]
    hosts = list(dict.fromkeys(app.host for app in ordered))  # ordered-unique
    vuln_ids = sorted({v for h in hosts for v in graph.nodes[h].vuln_ids})
    severity = _GOAL_SEVERITY.get(goal_fact, Severity.MEDIUM)
    entry_host = ordered[0].host
    module_chain = ",".join(app.cap.module_id for app in ordered)
    digest = hashlib.sha1(f"{entry_host}->{goal.host}:{module_chain}".encode()).hexdigest()[:10]
    return AttackPath(
        path_id=f"path-{digest}",
        severity=severity,
        score=_SEVERITY_SCORE[severity],
        entry_host=entry_host,
        goal_host=goal.host,
        goal=goal_fact,
        steps=steps,
        related_asset_ids=hosts,
        related_vuln_ids=vuln_ids,
    )
