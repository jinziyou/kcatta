"""kcatta Form control plane.

Form is the only integration boundary shared by admin, analyzer, and agent.
"""

from .api.app import create_app

__all__ = ["create_app"]
__version__ = "0.1.0"
