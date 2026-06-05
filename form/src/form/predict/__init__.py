"""Posture-grounded attack-path prediction.

Combines observed posture (assets, vulnerabilities, reachability) with an
ingested red-team capability graph to derive likely attack paths.
"""

from __future__ import annotations

from .engine import predict_paths
from .graph import PostureGraph, PostureNode, build_posture_graph

__all__ = [
    "PostureGraph",
    "PostureNode",
    "build_posture_graph",
    "predict_paths",
]
