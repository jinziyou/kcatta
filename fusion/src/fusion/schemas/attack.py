"""Attack-graph contracts: red-team capability import + predicted attack paths.

`CapabilityGraph` is the artifact a red-team capability exporter produces — every
technique's ATT&CK mapping plus its declarative pre/postconditions (the shared
ontology) and bundled playbook templates. fusion ingests it as OPAQUE JSON and never
imports or hard-codes the producing tool — it only consumes this contract.

`AttackPath` is fusion's own output: a posture-grounded chain of techniques that an
adversary could walk through the *observed* environment, derived by matching
capability preconditions against real assets / vulnerabilities / reachability.
"""

from __future__ import annotations

from pydantic import Field

from .common import Severity, StrictModel, Timestamp


class TechniqueCapability(StrictModel):
    """One red-team technique/module and the facts it consumes / produces."""

    module_id: str
    name: str = ""
    tactic: str = ""
    techniques: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(
        default_factory=list,
        description="Ontology facts required to run; an element may list "
        "`|`-separated alternatives (any-of), elements are AND-ed.",
    )
    postconditions: list[str] = Field(
        default_factory=list, description="Ontology facts produced on success"
    )
    requires_authorization: bool = False


class AttackTemplate(StrictModel):
    """A bundled playbook seen as a curated, ordered attack chain."""

    slug: str
    name: str = ""
    module_ids: list[str] = Field(default_factory=list)


class CapabilityGraph(StrictModel):
    """red-team -> fusion: the exported technique capability graph + templates."""

    source: str = Field(default="", description="Producing tool (opaque label)")
    ontology_version: str = Field(description="Shared fact-vocabulary version")
    exported_at: Timestamp | None = None
    capabilities: list[TechniqueCapability] = Field(default_factory=list)
    templates: list[AttackTemplate] = Field(default_factory=list)


class AttackPathStep(StrictModel):
    """One hop of a predicted attack path: a technique applied on a host."""

    host_id: str
    host_label: str = ""
    module_id: str
    technique_id: str = ""
    tactic: str = ""
    preconditions_met: list[str] = Field(default_factory=list)
    postconditions_gained: list[str] = Field(default_factory=list)


class AttackPath(StrictModel):
    """fusion-derived: a posture-grounded chain from an entry point to a goal.

    Deterministic — re-deriving from the same posture + capability graph yields
    the same `path_id` and steps, so the read endpoint is idempotent.
    """

    path_id: str
    severity: Severity
    score: int = Field(ge=0, le=100)
    entry_host: str
    goal_host: str
    goal: str = Field(description="The goal fact reached, e.g. access.admin")
    steps: list[AttackPathStep] = Field(default_factory=list)
    related_asset_ids: list[str] = Field(default_factory=list)
    related_vuln_ids: list[str] = Field(default_factory=list)
    generated_at: Timestamp | None = None
