"""Posture-grounded attack-path prediction.

Combines observed posture (assets, vulnerabilities, reachability) with an
ingested red-team capability graph to derive likely attack paths.
"""

from __future__ import annotations

from .engine import predict_paths
from .graph import KcattaGraph, KcattaNode, build_kcatta_graph

__all__ = [
    "KcattaGraph",
    "KcattaNode",
    "build_kcatta_graph",
    "predict_paths",
]
