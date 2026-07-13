"""Server-owned telemetry provenance and canonical host attribution."""

from __future__ import annotations

from typing import TypeVar

from .schemas import AssetReport, GuardEventBatch, TraceBatch

TelemetryEnvelope = AssetReport | TraceBatch | GuardEventBatch
T = TypeVar("T", AssetReport, TraceBatch, GuardEventBatch)


class ProvenanceConflict(ValueError):
    """An Agent attempted to claim provenance belonging to another identity."""


def bind_agent_envelope(
    payload: T,
    *,
    agent_id: str,
    target_id: str,
    canonical_host_id: str,
) -> T:
    """Return a deep copy bound to the authenticated Form Agent identity.

    Optional provenance is accepted only when it agrees with the TLS identity;
    old Agent binaries omit it.  Host attribution is always overwritten from
    Form's registry so a valid certificate for target A cannot inject events as
    target B by changing a payload field.
    """
    _reject_claim_conflict(payload.source_agent_id, agent_id, "source_agent_id")
    _reject_claim_conflict(payload.source_target_id, target_id, "source_target_id")
    return _bind(
        payload,
        canonical_host_id=canonical_host_id,
        source_agent_id=agent_id,
        source_target_id=target_id,
    )


def bind_form_envelope(payload: T, *, target_id: str, canonical_host_id: str) -> T:
    """Canonicalize an artifact Form itself pulled from a registered target."""
    return _bind(
        payload,
        canonical_host_id=canonical_host_id,
        source_agent_id=None,
        source_target_id=target_id,
    )


def _reject_claim_conflict(claimed: str | None, expected: str, field: str) -> None:
    if claimed is not None and claimed != expected:
        raise ProvenanceConflict(f"{field} does not match the authenticated Agent identity")


def _bind(
    payload: T,
    *,
    canonical_host_id: str,
    source_agent_id: str | None,
    source_target_id: str,
) -> T:
    common = {
        "source_agent_id": source_agent_id,
        "source_target_id": source_target_id,
    }
    if isinstance(payload, AssetReport):
        previous_host_id = payload.host.host_id
        host = payload.host.model_copy(update={"host_id": canonical_host_id}, deep=True)
        vulnerabilities = [
            vulnerability.model_copy(
                update={"affected_asset_id": canonical_host_id},
                deep=True,
            )
            if vulnerability.affected_asset_id == previous_host_id
            else vulnerability.model_copy(deep=True)
            for vulnerability in payload.vulnerabilities
        ]
        return payload.model_copy(  # type: ignore[return-value]
            update={**common, "host": host, "vulnerabilities": vulnerabilities},
            deep=True,
        )
    if isinstance(payload, TraceBatch):
        return payload.model_copy(  # type: ignore[return-value]
            update={
                **common,
                "events": [
                    event.model_copy(update={"host_id": canonical_host_id}, deep=True)
                    for event in payload.events
                ],
                "file_events": [
                    event.model_copy(update={"host_id": canonical_host_id}, deep=True)
                    for event in payload.file_events
                ],
                "process_events": [
                    event.model_copy(update={"host_id": canonical_host_id}, deep=True)
                    for event in payload.process_events
                ],
            },
            deep=True,
        )
    if isinstance(payload, GuardEventBatch):
        return payload.model_copy(  # type: ignore[return-value]
            update={
                **common,
                "host_id": canonical_host_id,
                "events": [
                    event.model_copy(update={"host_id": canonical_host_id}, deep=True)
                    for event in payload.events
                ],
            },
            deep=True,
        )
    raise TypeError(f"unsupported telemetry envelope: {type(payload).__name__}")
