"""Read-side endpoint that predicts attack paths from current posture.

Paths are derived on demand from the stored asset reports / detections / flows
and the latest ingested capability graph. Derivation is deterministic, so this
endpoint is idempotent — no separate prediction store is needed for v0.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request, status
from starlette.datastructures import State

from ..predict import build_posture_graph, predict_paths
from ..schemas import AttackPath, CapabilityGraph

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])


def _predict(state: State, limit: int = 500) -> list[AttackPath]:
    """Build the posture graph + capability graph and predict paths (stamped now)."""
    latest = state.capability_graph_store.tail(1)
    if not latest:
        return []
    capability_graph = CapabilityGraph.model_validate(latest[0])

    graph = build_posture_graph(
        state.asset_report_store.tail(limit),
        state.vulnerability_store.tail(limit),
        state.flow_batch_store.tail(limit),
    )
    paths = predict_paths(graph, capability_graph.capabilities)
    stamped = datetime.now(UTC)
    return [path.model_copy(update={"generated_at": stamped}) for path in paths]


@router.get("", response_model=list[AttackPath])
async def list_attack_paths(
    request: Request,
    limit: int = Query(default=200, ge=1, le=500),
) -> list[AttackPath]:
    """Predict attack paths from current posture + the latest capability graph.

    Returns an empty list when no capability graph has been ingested yet.
    """
    return _predict(request.app.state, limit)


@router.get("/{path_id}", response_model=AttackPath)
async def get_attack_path(path_id: str, request: Request) -> AttackPath:
    """Fetch a single predicted attack path by its deterministic ``path_id``."""
    for path in _predict(request.app.state):
        if path.path_id == path_id:
            return path
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="attack path not found")
