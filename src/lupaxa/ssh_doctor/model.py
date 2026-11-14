"""Diagnostic result model."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Status(StrEnum):
    """Outcome of one diagnostic check."""

    PASS = "PASS"  # noqa: S105
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass(frozen=True)
class CheckResult:
    """One diagnostic check outcome."""

    check_id: str
    category: str
    status: Status
    message: str
    details: str | None = None
    recommendation: str | None = None


def worse(left: Status, right: Status) -> Status:
    """Return the more severe of two statuses."""
    rank = {Status.PASS: 0, Status.SKIP: 1, Status.WARN: 2, Status.FAIL: 3}
    return left if rank[left] >= rank[right] else right


def summary_counts(results: list[CheckResult]) -> dict[str, int]:
    """Count results by status."""
    counts = {"passed": 0, "warnings": 0, "failed": 0, "skipped": 0}
    for result in results:
        if result.status is Status.PASS:
            counts["passed"] += 1
        elif result.status is Status.WARN:
            counts["warnings"] += 1
        elif result.status is Status.FAIL:
            counts["failed"] += 1
        else:
            counts["skipped"] += 1
    return counts


def exit_code_for(results: list[CheckResult]) -> int:
    """Map diagnostic results to a process exit code.

    SKIP results alone do not change a successful exit.
    """
    counts = summary_counts(results)
    if counts["failed"]:
        return 2
    if counts["warnings"]:
        return 1
    return 0
