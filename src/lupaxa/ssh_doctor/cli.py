"""Command-line interface for SSH Doctor."""

from __future__ import annotations

import argparse
import math
import os
import platform
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from .diagnose import Context, run_diagnostics
from .model import CheckResult, exit_code_for
from .process import CommandRunner, SubprocessRunner
from .report import render_json, render_text, use_colour
from .settings import ConfigError, load_settings, resolve_config_path
from .version import get_version

Executor = Callable[..., list[CheckResult]]


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than 0")
    return timeout


def build_parser() -> argparse.ArgumentParser:
    """Build the ``ssh-doctor`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="ssh-doctor",
        description=(
            "Read-only diagnostics for local SSH client configuration, "
            "keys, permissions, and the agent."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ssh-doctor {get_version()}",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print a JSON report")
    common.add_argument("--verbose", action="store_true", help="include extra detail")
    common.add_argument("--quiet", action="store_true", help="hide passes and skips")
    common.add_argument("--timeout", type=_positive_timeout, help="seconds for external commands")
    common.add_argument("--config", type=Path, help="path to a TOML configuration file")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", parents=[common], help="run every local diagnostic")
    sub.add_parser("system", parents=[common], help="inspect the OpenSSH installation")
    sub.add_parser("permissions", parents=[common], help="inspect SSH file permissions")
    sub.add_parser("keys", parents=[common], help="inventory local SSH keys")
    config = sub.add_parser("config", parents=[common], help="validate SSH client configuration")
    config.add_argument("--host", help="report the effective configuration for this host")
    sub.add_parser("agent", parents=[common], help="inspect the SSH agent")
    known = sub.add_parser("known-hosts", parents=[common], help="inspect known-host files")
    known.add_argument("hostname", nargs="?", help="search known-host files for this name")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: CommandRunner | None = None,
    home: Path | None = None,
    environ: dict[str, str] | None = None,
    which: Callable[[str], str | None] | None = None,
    uid: int | None = None,
    platform_system: str | None = None,
    executor: Executor = run_diagnostics,
) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code
        if code is None or code == 0:
            return 0
        if code == 2:
            return 3
        return code if isinstance(code, int) else 1
    if args.verbose and args.quiet:
        print("ssh-doctor: error: --verbose and --quiet cannot be combined", file=sys.stderr)
        return 3
    env = dict(os.environ if environ is None else environ)
    home_path = Path.home() if home is None else home
    try:
        config_path = resolve_config_path(args.config, env, home_path)
        settings = load_settings(config_path)
    except ConfigError as exc:
        print(f"ssh-doctor: {exc}", file=sys.stderr)
        return 3
    if args.timeout is not None:
        settings.timeout = args.timeout
    ssh_dir = settings.ssh_directory or (home_path / ".ssh")
    ctx = Context(
        settings=settings,
        runner=runner or SubprocessRunner(),
        home=home_path,
        ssh_dir=ssh_dir,
        timeout=settings.timeout,
        environ=env,
        uid=os.getuid() if uid is None else uid,
        platform_system=platform_system or platform.system(),
        platform_release=platform.release(),
        platform_machine=platform.machine(),
        which=which or _which,
        path_value=env.get("PATH", ""),
        explicit_ssh_dir=settings.ssh_directory is not None,
    )
    try:
        results = executor(
            args.command,
            ctx,
            host=getattr(args, "host", None),
            known_host=getattr(args, "hostname", None),
        )
    except ConfigError as exc:
        print(f"ssh-doctor: {exc}", file=sys.stderr)
        return 3
    except Exception:
        print("ssh-doctor: diagnostic execution could not be completed.", file=sys.stderr)
        return 4
    as_json = args.json or settings.output_format == "json"
    if as_json:
        sys.stdout.write(
            render_json(
                results,
                version=get_version(),
                timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                system=ctx.platform_system,
                release=ctx.platform_release,
                machine=ctx.platform_machine,
            )
        )
    else:
        sys.stdout.write(
            render_text(
                results,
                verbose=args.verbose,
                quiet=args.quiet,
                colour=use_colour(sys.stdout, env),
            )
        )
    return exit_code_for(results)


def _which(name: str) -> str | None:
    from shutil import which

    return which(name)
