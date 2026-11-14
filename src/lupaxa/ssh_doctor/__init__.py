"""lupaxa.ssh_doctor — read-only local SSH client diagnostics."""

from __future__ import annotations

from .model import CheckResult, Status
from .version import __version__, get_version

__all__ = [
    "CheckResult",
    "Status",
    "__version__",
    "get_version",
]
