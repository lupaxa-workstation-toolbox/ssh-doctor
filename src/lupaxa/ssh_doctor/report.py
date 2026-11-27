"""Human and JSON diagnostic reports."""

from __future__ import annotations

import json
from typing import TextIO

from .model import CheckResult, Status, summary_counts

_COLOURS = {
    Status.PASS: "32",
    Status.WARN: "33",
    Status.FAIL: "31",
    Status.SKIP: "90",
}


def use_colour(stream: TextIO, environ: dict[str, str]) -> bool:
    """Return whether status labels should be coloured."""
    if "NO_COLOR" in environ or "NO_COLOUR" in environ:
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def render_text(results: list[CheckResult], *, verbose: bool, quiet: bool, colour: bool) -> str:
    """Render a human-readable report."""
    lines: list[str] = []
    category = ""
    shown = 0
    for result in results:
        if quiet and result.status in {Status.PASS, Status.SKIP}:
            continue
        shown += 1
        if result.category != category:
            category = result.category
            if lines:
                lines.append("")
            lines.append(_heading(category))
        lines.append(f"  {_paint(result.status, colour)}  {result.message}")
        if result.recommendation:
            lines.append(f"        {result.recommendation}")
        show_details = result.details and (verbose or result.status in {Status.WARN, Status.FAIL})
        if show_details and result.details:
            for detail in result.details.splitlines():
                lines.append(f"        {detail}")
    if lines:
        lines.append("")
    counts = summary_counts(results)
    lines.append(f"Summary: {counts['passed']} passed, {_plural(counts['warnings'], 'warning')}, {counts['failed']} failed, {counts['skipped']} skipped")
    if shown == 0 and quiet:
        lines.insert(0, "No warnings or failures.")
        lines.insert(1, "")
    return "\n".join(lines) + "\n"


def render_json(results: list[CheckResult], *, version: str, timestamp: str, system: str, release: str, machine: str) -> str:
    """Render the stable JSON report."""
    payload = {
        "version": version,
        "timestamp": timestamp,
        "os": {
            "system": system,
            "release": release,
            "machine": machine,
        },
        "results": [
            {
                "check_id": result.check_id,
                "category": result.category,
                "status": result.status.value,
                "message": result.message,
                "details": result.details,
                "recommendation": result.recommendation,
            }
            for result in results
        ],
        "summary": summary_counts(results),
    }
    return json.dumps(payload, indent=2) + "\n"


def _heading(category: str) -> str:
    names = {
        "system": "System",
        "permissions": "Permissions",
        "keys": "Keys",
        "config": "Config",
        "agent": "Agent",
        "known-hosts": "Known Hosts",
    }
    return names.get(category, category.title())


def _paint(status: Status, colour: bool) -> str:
    label = f"{status.value:<4}"
    if not colour:
        return label
    return f"\033[{_COLOURS[status]}m{label}\033[0m"


def _plural(count: int, word: str) -> str:
    if count == 1:
        return f"{count} {word}"
    return f"{count} {word}s"
