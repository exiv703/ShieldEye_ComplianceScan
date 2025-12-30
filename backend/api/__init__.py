from __future__ import annotations

try:
    from .rest import app, start_api_server
    __all__ = ["app", "start_api_server"]
except ImportError:
    __all__ = []
