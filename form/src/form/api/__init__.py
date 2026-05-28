"""HTTP API surface for cyber-posture form.

The factory `create_app` is the single entry point. CLI launchers, test
clients, and ASGI servers all go through it so the wiring stays in one
place.
"""

from .app import create_app

__all__ = ["create_app"]
