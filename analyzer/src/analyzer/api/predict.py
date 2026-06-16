"""Read-side endpoint that predicts attack paths from current posture.

Paths are derived on demand from the stored asset reports / detections / events
and the latest ingested capability graph. Derivation is deterministic, so this
endpoint is idempotent — no separate prediction store is needed for v0.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request, status
from starlette.datastructures import State

from ..predict import build_kcatta_graph, predict_paths
from ..schemas import AttackPath, CapabilityGraph

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])

# Both the list and the by-id endpoints derive paths from the same posture
# window, so they MUST share this default. Otherwise a path_id returned by the
# list (one window) could 404 or resolve to a different path when fetched by id
# (a different window). It also matches the Query upper bound (le), so the
# default scans the whole allowable window.
DEFAULT_PATH_LIMIT = 500


def _posture_fingerprint(state: State, limit: int) -> tuple:
    """A cheap signature of the inputs ``_predict`` reads.

    The attack-path fixpoint is a pure function of the three telemetry stores +
    the latest capability graph, so an unchanged fingerprint means the previous
    result is still valid (F1: avoid recomputing the whole fixpoint per GET).
    Uses each store's ``fingerprint`` (row count + max id / file size) — no
    record parsing — falling back to a tail-based signature for any store that
    predates the ``fingerprint`` method.
    """

    def _store_fp(store) -> tuple:
        fp = getattr(store, "fingerprint", None)
        if callable(fp):
            return fp()
        # Fallback: derive a signature from the newest record only.
        newest = store.tail(1)
        return (len(newest), str(newest[0]) if newest else "")

    return (
        limit,
        _store_fp(state.capability_graph_store),
        _store_fp(state.asset_report_store),
        _store_fp(state.vulnerability_store),
        _store_fp(state.trace_batch_store),
    )


def _predict(state: State, limit: int = DEFAULT_PATH_LIMIT) -> list[AttackPath]:
    """Build the kcatta graph + capability graph and predict paths (stamped now).

    Result is cached on ``state`` keyed by a cheap posture fingerprint; an
    unchanged fingerprint returns the cached paths without rebuilding the graph
    or rerunning the fixpoint.
    """
    fingerprint = _posture_fingerprint(state, limit)
    cache = getattr(state, "attack_path_cache", None)
    if cache is not None and cache[0] == fingerprint:
        return cache[1]

    latest = state.capability_graph_store.tail(1)
    if not latest:
        result: list[AttackPath] = []
        state.attack_path_cache = (fingerprint, result)
        return result
    capability_graph = CapabilityGraph.model_validate(latest[0])

    graph = build_kcatta_graph(
        state.asset_report_store.tail(limit),
        state.vulnerability_store.tail(limit),
        state.trace_batch_store.tail(limit),
    )
    paths = predict_paths(graph, capability_graph.capabilities)
    stamped = datetime.now(UTC)
    result = [path.model_copy(update={"generated_at": stamped}) for path in paths]
    state.attack_path_cache = (fingerprint, result)
    return result


@router.get("", response_model=list[AttackPath])
async def list_attack_paths(
    request: Request,
    limit: int = Query(default=DEFAULT_PATH_LIMIT, ge=1, le=DEFAULT_PATH_LIMIT),
) -> list[AttackPath]:
    """Predict attack paths from current posture + the latest capability graph.

    Returns an empty list when no capability graph has been ingested yet.
    """
    return _predict(request.app.state, limit)


@router.get("/{path_id}", response_model=AttackPath)
async def get_attack_path(path_id: str, request: Request) -> AttackPath:
    """Fetch a single predicted attack path by its deterministic ``path_id``.

    Uses the same default posture window as the list endpoint so a ``path_id``
    from the list resolves consistently here.
    """
    for path in _predict(request.app.state):
        if path.path_id == path_id:
            return path
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="attack path not found")
