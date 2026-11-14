"""Subprocess helper for OpenSSH utilities."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CommandResult:
    """Captured output from one external command."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class CommandRunner(Protocol):
    """Run one command without a shell."""

    def run(
        self,
        argv: list[str],
        *,
        timeout: float,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        """Run ``argv`` and return the captured result."""
        ...


def redact(text: str) -> str:
    """Remove private-key blocks from command output."""
    kept: list[str] = []
    for line in text.splitlines():
        upper = line.upper()
        if "PRIVATE KEY" in upper or line.startswith("-----"):
            continue
        kept.append(line)
    return "\n".join(kept).strip()


class SubprocessRunner:
    """Run commands with a timeout and no shell."""

    def run(
        self,
        argv: list[str],
        *,
        timeout: float,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        """Run ``argv`` and capture stdout and stderr."""
        try:
            completed = subprocess.run(  # noqa: S603
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                list(argv),
                124,
                _text(exc.stdout),
                _text(exc.stderr),
                True,
            )
        except FileNotFoundError:
            return CommandResult(list(argv), 127, "", "command not found", False)
        except OSError as exc:
            return CommandResult(list(argv), 127, "", redact(str(exc)), False)
        return CommandResult(
            list(argv),
            completed.returncode,
            completed.stdout or "",
            completed.stderr or "",
            False,
        )


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value
