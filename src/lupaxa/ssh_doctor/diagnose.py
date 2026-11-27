"""Local SSH diagnostic checks."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .model import CheckResult, Status
from .process import CommandResult, CommandRunner, redact
from .settings import CATEGORIES, Settings
from .sshdata import (
    algorithm_label,
    algorithm_status,
    assess_mode,
    check_slug,
    classify_file,
    expand_ssh_path,
    find_on_path,
    is_encrypted_private_key,
    parse_config,
    parse_fingerprint,
    parse_known_host_line,
    parse_public_key,
    parse_ssh_g,
    read_prefix,
    split_arguments,
    symlink_problem,
    unsafe_reason,
)

Which = Callable[[str], str | None]


@dataclass
class Context:
    """Inputs for one diagnostic run."""

    settings: Settings
    runner: CommandRunner
    home: Path
    ssh_dir: Path
    timeout: float
    environ: dict[str, str]
    uid: int
    platform_system: str
    platform_release: str
    platform_machine: str
    which: Which
    path_value: str
    explicit_ssh_dir: bool


def run_diagnostics(command: str, ctx: Context, *, host: str | None = None, known_host: str | None = None) -> list[CheckResult]:
    """Run one command, or every local check for ``check``."""
    if command == "check":
        results: list[CheckResult] = []
        for category in CATEGORIES:
            if not ctx.settings.allows(category):
                results.append(CheckResult(f"{category}.disabled", category, Status.SKIP, f"{category} checks are disabled by configuration."))
                continue
            results.extend(_run_category(category, ctx, host=host, known_host=known_host))
        return _suppress(results, ctx.settings.suppressed_warnings)
    category = _command_category(command)
    results = _run_category(category, ctx, host=host, known_host=known_host)
    return _suppress(results, ctx.settings.suppressed_warnings)


def _command_category(command: str) -> str:
    if command == "known-hosts":
        return "known-hosts"
    return command


def _run_category(category: str, ctx: Context, *, host: str | None, known_host: str | None) -> list[CheckResult]:
    functions = {
        "system": lambda: check_system(ctx),
        "permissions": lambda: check_permissions(ctx),
        "keys": lambda: check_keys(ctx),
        "config": lambda: check_config(ctx, host=host),
        "agent": lambda: check_agent(ctx),
        "known-hosts": lambda: check_known_hosts(ctx, hostname=known_host),
    }
    try:
        return functions[category]()
    except Exception as exc:
        return [CheckResult(f"{category}.error", category, Status.FAIL, "Check could not be completed.", details=redact(str(exc))[:500] or exc.__class__.__name__)]


def check_system(ctx: Context) -> list[CheckResult]:
    """Inspect the local OpenSSH installation."""
    results: list[CheckResult] = []
    copies = find_on_path("ssh", ctx.path_value)
    ssh = ctx.which("ssh")
    if ssh and ssh not in copies:
        copies.insert(0, ssh)
    if not ssh and not copies:
        results.append(CheckResult("system.ssh_present", "system", Status.FAIL, "The ssh client was not found on PATH.", recommendation="Install OpenSSH and ensure ssh is on PATH."))
        results.append(CheckResult("system.ssh_version", "system", Status.SKIP, "OpenSSH version was not checked because ssh is missing."))
    else:
        binary = ssh or copies[0]
        results.append(CheckResult("system.ssh_present", "system", Status.PASS, "OpenSSH client found.", details=binary))
        results.append(_version_result(ctx, binary))
    for tool in ("ssh-keygen", "ssh-add", "ssh-agent"):
        located = ctx.which(tool)
        if located:
            results.append(CheckResult(f"system.{tool.replace('-', '_')}", "system", Status.PASS, f"{tool} found.", details=located))
        else:
            results.append(CheckResult(f"system.{tool.replace('-', '_')}", "system", Status.FAIL, f"{tool} was not found on PATH.", recommendation="Install the OpenSSH client package."))
    if len(copies) > 1:
        results.append(
            CheckResult("system.multiple_ssh", "system", Status.WARN, "More than one ssh executable is on PATH.", details="\n".join(copies), recommendation="Keep a single ssh client first on PATH.")
        )
    elif copies:
        results.append(CheckResult("system.multiple_ssh", "system", Status.PASS, "One ssh executable is on PATH.", details=copies[0]))
    else:
        results.append(CheckResult("system.multiple_ssh", "system", Status.SKIP, "Multiple ssh clients were not compared because ssh is missing."))
    results.append(CheckResult("system.platform", "system", Status.PASS, f"{ctx.platform_system} {ctx.platform_machine}.", details=ctx.platform_release))
    if ctx.home.is_dir():
        results.append(CheckResult("system.home", "system", Status.PASS, "Home directory is accessible.", details=str(ctx.home)))
    else:
        results.append(CheckResult("system.home", "system", Status.FAIL, "Home directory is not accessible.", details=str(ctx.home)))
    results.append(_ssh_dir_access(ctx))
    return results


def check_permissions(ctx: Context) -> list[CheckResult]:
    """Inspect SSH file and directory permissions."""
    results = [_ssh_dir_permission(ctx)]
    if not ctx.ssh_dir.is_dir():
        return results
    for path in _interesting_paths(ctx):
        results.extend(_path_permissions(ctx, path))
    return results


def check_keys(ctx: Context) -> list[CheckResult]:
    """Inventory local SSH keys."""
    directories = [ctx.ssh_dir, *ctx.settings.key_search_directories]
    seen: set[str] = set()
    files: list[Path] = []
    missing_dirs = 0
    for directory in directories:
        if not directory.exists():
            missing_dirs += 1
            continue
        if not directory.is_dir():
            files.append(directory)
            continue
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            return [CheckResult("keys.directory", "keys", Status.FAIL, f"Key directory is not accessible: {directory}", details=exc.strerror or "permission denied")]
        for entry in entries:
            if entry.name.startswith("."):
                continue
            resolved = _identity(entry)
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(entry)
    if not files:
        message = "No SSH keys were found."
        if missing_dirs == len(directories):
            message = "SSH directory does not exist, so no keys were inventoried."
        return [CheckResult("keys.inventory", "keys", Status.SKIP, message, details=str(ctx.ssh_dir))]
    agent_fps = _agent_fingerprints(ctx)
    results: list[CheckResult] = []
    fingerprints: dict[str, set[str]] = defaultdict(set)
    for path in files:
        kind = classify_file(path)
        if kind == "public_key":
            results.extend(_public_key(ctx, path, agent_fps, fingerprints))
        elif kind == "private_key":
            results.extend(_private_key(ctx, path, agent_fps, fingerprints))
    duplicates = {fp: names for fp, names in fingerprints.items() if len(names) > 1}
    if duplicates:
        lines = [f"{fp}: {', '.join(sorted(names))}" for fp, names in sorted(duplicates.items())]
        results.append(CheckResult("keys.duplicate", "keys", Status.WARN, "Duplicate public keys were found.", details="\n".join(lines)))
    if not results:
        results.append(CheckResult("keys.inventory", "keys", Status.SKIP, "No recognised SSH keys were found."))
    return results


def check_config(ctx: Context, *, host: str | None) -> list[CheckResult]:
    """Validate SSH client configuration without running proxy commands."""
    results: list[CheckResult] = []
    config_path = ctx.ssh_dir / "config"
    directives = _read_directives(ctx, config_path, results)
    results.extend(_include_results(ctx, directives, config_path))
    results.extend(_static_identity_results(ctx, directives))
    results.extend(_unsafe_results(directives))
    ssh = ctx.which("ssh")
    if ssh is None:
        results.append(CheckResult("config.syntax", "config", Status.SKIP, "SSH configuration syntax was not checked because ssh is missing."))
        return results
    argv = [ssh, "-G"]
    if ctx.explicit_ssh_dir:
        argv.extend(["-F", str(config_path)])
    argv.append(host or "ssh-doctor.invalid")
    completed = ctx.runner.run(argv, timeout=ctx.timeout, env=ctx.environ)
    if completed.timed_out:
        results.append(CheckResult("config.syntax", "config", Status.FAIL, "ssh -G timed out while reading configuration.", recommendation="Increase the command timeout and retry."))
        return results
    if completed.returncode != 0:
        results.append(
            CheckResult(
                "config.syntax",
                "config",
                Status.FAIL,
                "SSH configuration syntax is invalid.",
                details=redact(completed.stderr or completed.stdout)[:2000],
                recommendation=f"Review {config_path} and remove the invalid option.",
            )
        )
        return results
    results.append(CheckResult("config.syntax", "config", Status.PASS, "SSH configuration syntax is valid."))
    if host:
        results.extend(_effective_results(ctx, host, completed))
    return results


def check_agent(ctx: Context) -> list[CheckResult]:
    """Inspect the SSH agent without starting it or loading keys."""
    results: list[CheckResult] = []
    sock = ctx.environ.get("SSH_AUTH_SOCK", "")
    if not sock:
        results.append(CheckResult("agent.socket", "agent", Status.WARN, "SSH_AUTH_SOCK is not set.", recommendation="Start an agent or use key files directly. No agent was started."))
        results.append(CheckResult("agent.contact", "agent", Status.SKIP, "The agent was not contacted because SSH_AUTH_SOCK is unset."))
    else:
        socket_path = Path(sock)
        if not socket_path.exists():
            results.append(CheckResult("agent.socket", "agent", Status.FAIL, "SSH_AUTH_SOCK does not point at an existing socket.", details=sock))
            results.append(CheckResult("agent.contact", "agent", Status.SKIP, "The agent was not contacted because the socket is missing."))
        else:
            detail = sock
            if ctx.platform_system == "Darwin" and ("com.apple" in sock or "launchd" in sock):
                detail = f"{sock}\nApple SSH agent socket detected. Keychain settings were not changed."
            results.append(CheckResult("agent.socket", "agent", Status.PASS, "SSH_AUTH_SOCK points at an existing socket.", details=detail))
            results.extend(_agent_contact(ctx))
    if ctx.platform_system == "Darwin":
        results.append(_apple_keychain(ctx))
    else:
        results.append(CheckResult("agent.apple", "agent", Status.SKIP, "Apple Keychain integration does not apply on this operating system."))
    return results


def check_known_hosts(ctx: Context, *, hostname: str | None) -> list[CheckResult]:
    """Inspect known-host files without modifying them."""
    paths = _known_host_paths(ctx)
    if not paths:
        return [CheckResult("known_hosts.files", "known-hosts", Status.SKIP, "No known-host files were configured.")]
    results: list[CheckResult] = []
    found = False
    searched = False
    for path in paths:
        results.extend(_one_known_host_file(ctx, path))
        if hostname and path.is_file():
            searched = True
            if _host_in_file(ctx, path, hostname):
                found = True
    if hostname and searched:
        if found:
            results.append(CheckResult("known_hosts.search", "known-hosts", Status.PASS, f"A known-host entry was found for {hostname}."))
        else:
            results.append(
                CheckResult(
                    "known_hosts.search", "known-hosts", Status.WARN, f"No known-host entry was found for {hostname}.", recommendation="Connect once and verify the host key before trusting it."
                )
            )
    elif hostname:
        results.append(CheckResult("known_hosts.search", "known-hosts", Status.SKIP, f"{hostname} was not searched because no known-host file could be read."))
    return results


def _version_result(ctx: Context, binary: str) -> CheckResult:
    completed = ctx.runner.run([binary, "-V"], timeout=ctx.timeout, env=ctx.environ)
    if completed.timed_out:
        return CheckResult("system.ssh_version", "system", Status.FAIL, "Timed out while reading the OpenSSH version.", recommendation="Increase the command timeout and retry.")
    text = redact(completed.stderr or completed.stdout).splitlines()
    line = text[0] if text else ""
    if "OpenSSH" in line or (completed.returncode == 0 and line):
        return CheckResult("system.ssh_version", "system", Status.PASS, line or "OpenSSH version was reported.")
    return CheckResult("system.ssh_version", "system", Status.FAIL, "Could not read the OpenSSH version.", details=line or redact(completed.stderr))


def _ssh_dir_access(ctx: Context) -> CheckResult:
    path = ctx.ssh_dir
    if not path.exists():
        return CheckResult("system.ssh_dir", "system", Status.FAIL, "SSH directory does not exist.", details=str(path), recommendation=f"mkdir -m 700 {path}")
    if not path.is_dir():
        return CheckResult("system.ssh_dir", "system", Status.FAIL, "SSH directory path is not a directory.", details=str(path))
    try:
        next(path.iterdir(), None)
    except OSError as exc:
        return CheckResult("system.ssh_dir", "system", Status.FAIL, "SSH directory is not accessible.", details=exc.strerror or str(path))
    return CheckResult("system.ssh_dir", "system", Status.PASS, "SSH directory is accessible.", details=str(path))


def _ssh_dir_permission(ctx: Context) -> CheckResult:
    path = ctx.ssh_dir
    link = symlink_problem(path, ctx.home)
    if link == "broken":
        return CheckResult("permissions.directory", "permissions", Status.FAIL, "SSH directory symlink is broken.", details=str(path))
    if not path.exists():
        return CheckResult("permissions.directory", "permissions", Status.FAIL, "SSH directory does not exist.", details=str(path), recommendation=f"mkdir -m 700 {path}")
    if link == "outside-home":
        return CheckResult("permissions.symlink.directory", "permissions", Status.WARN, "SSH directory symlink resolves outside the home directory.", details=str(path.resolve()))
    try:
        info = path.stat()
    except OSError as exc:
        return CheckResult("permissions.directory", "permissions", Status.FAIL, "SSH directory is not accessible.", details=exc.strerror or str(path))
    assessment = assess_mode("directory", info.st_mode, info.st_uid, ctx.uid, path)
    return CheckResult("permissions.directory", "permissions", assessment.status, assessment.message, details=f"Expected: {assessment.expected}", recommendation=assessment.recommendation)


def _interesting_paths(ctx: Context) -> list[Path]:
    paths: list[Path] = []
    config_path = ctx.ssh_dir / "config"
    if config_path.exists() or config_path.is_symlink():
        paths.append(config_path)
        paths.extend(_included_files(ctx, config_path))
    try:
        entries = list(ctx.ssh_dir.iterdir())
    except OSError:
        return paths
    for entry in entries:
        if entry.name.startswith("."):
            continue
        kind = classify_file(entry)
        if kind in {"private_key", "public_key", "known_hosts", "config"} and entry not in paths:
            paths.append(entry)
    for extra in ctx.settings.known_host_files:
        if extra not in paths:
            paths.append(extra)
    return paths


def _included_files(ctx: Context, config_path: Path) -> list[Path]:
    text = _read_text(config_path)
    if text is None:
        return []
    found: list[Path] = []
    seen = {_identity(config_path)}
    pending = [config_path]
    while pending:
        current = pending.pop(0)
        body = text if current == config_path else _read_text(current)
        if body is None:
            continue
        for directive in parse_config(body):
            if directive.keyword != "include":
                continue
            for token in split_arguments(directive.argument):
                expanded = expand_ssh_path(token, ctx.home, ctx.ssh_dir)
                matches = _glob_matches(expanded, token)
                targets = matches or [expanded]
                for target in targets:
                    identity = _identity(target)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    found.append(target)
                    if target.is_file():
                        pending.append(target)
    return found


def _path_permissions(ctx: Context, path: Path) -> list[CheckResult]:
    link = symlink_problem(path, ctx.home)
    if link == "broken":
        return [CheckResult(check_slug("permissions.symlink", path.name), "permissions", Status.FAIL, f"Broken symlink: {path}", recommendation="Remove or replace the symlink. It was not followed.")]
    results: list[CheckResult] = []
    if link == "outside-home":
        results.append(CheckResult(check_slug("permissions.symlink", path.name), "permissions", Status.WARN, f"Symlink resolves outside the home directory: {path}", details=str(path.resolve())))
    if not path.exists():
        results.append(CheckResult(check_slug("permissions.missing", path.name), "permissions", Status.FAIL, f"SSH file does not exist: {path}"))
        return results
    try:
        info = path.stat()
    except OSError as exc:
        results.append(CheckResult(check_slug("permissions.access", path.name), "permissions", Status.FAIL, f"SSH file is not accessible: {path}", details=exc.strerror))
        return results
    kind = classify_file(path)
    mode_kind = {
        "private_key": "private_key",
        "public_key": "public_key",
        "config": "config",
        "known_hosts": "known_hosts",
    }.get(kind, "public_key")
    assessment = assess_mode(mode_kind, info.st_mode, info.st_uid, ctx.uid, path)
    results.append(
        CheckResult(
            check_slug(f"permissions.{mode_kind}", path.name),
            "permissions",
            assessment.status,
            assessment.message,
            details=f"Expected: {assessment.expected}",
            recommendation=assessment.recommendation,
        )
    )
    return results


def _public_key(ctx: Context, path: Path, agent_fps: set[str] | None, fingerprints: dict[str, set[str]]) -> list[CheckResult]:
    private = path.with_suffix("") if path.suffix == ".pub" else None
    if private is not None and not private.exists() and not private.is_symlink():
        results = [CheckResult(check_slug("keys.orphan_public", path.name), "keys", Status.WARN, f"Public key has no matching private key: {path.name}", details=str(path))]
    else:
        results = []
    parsed = parse_public_key(_read_text(path) or "")
    if parsed is None:
        results.append(CheckResult(check_slug("keys.invalid", path.name), "keys", Status.FAIL, f"Public key is invalid: {path.name}"))
        return results
    algorithm, _blob, comment = parsed
    fingerprint = _fingerprint_for(ctx, path)
    if fingerprint and (private is None or not private.exists()):
        fingerprints[fingerprint[1]].add(path.name)
    loaded = "unknown"
    if agent_fps is not None and fingerprint:
        loaded = "yes" if fingerprint[1] in agent_fps else "no"
    details = [
        f"path: {path}",
        f"algorithm: {algorithm}",
        f"comment: {comment or '-'}",
        f"fingerprint: {fingerprint[1] if fingerprint else 'unavailable'}",
        f"private key: {'yes' if private and private.exists() else 'no'}",
        f"loaded in agent: {loaded}",
    ]
    results.insert(0, CheckResult(check_slug("keys.public", path.name), "keys", Status.PASS, f"Public key {path.name}.", details="\n".join(details)))
    flagged = algorithm_status(algorithm)
    if flagged is Status.WARN and not (private is not None and private.exists()):
        results.append(CheckResult(check_slug("keys.obsolete", path.name), "keys", Status.WARN, algorithm_label(algorithm) + f" ({path.name}).", recommendation="Prefer an Ed25519 key for new use."))
    return results


def _private_key(ctx: Context, path: Path, agent_fps: set[str] | None, fingerprints: dict[str, set[str]]) -> list[CheckResult]:
    link = symlink_problem(path, ctx.home)
    if link == "broken":
        return [CheckResult(check_slug("keys.symlink", path.name), "keys", Status.FAIL, f"Private key symlink is broken: {path.name}", details=str(path))]
    prefix = read_prefix(path) or b""
    encrypted = is_encrypted_private_key(prefix)
    public = Path(str(path) + ".pub")
    public_exists = public.is_file()
    fingerprint = _fingerprint_for(ctx, public if public_exists else path)
    if fingerprint:
        fingerprints[fingerprint[1]].add(path.name)
    algorithm = fingerprint[3] if fingerprint else ""
    if public_exists:
        parsed = parse_public_key(_read_text(public) or "")
        if parsed:
            algorithm = parsed[0]
    loaded = "unknown"
    if agent_fps is not None and fingerprint:
        loaded = "yes" if fingerprint[1] in agent_fps else "no"
    try:
        info = path.stat()
        mode = f"{info.st_mode & 0o777:04o}"
        owner = str(info.st_uid)
    except OSError:
        mode = "unavailable"
        owner = "unavailable"
    details = [
        f"path: {path}",
        f"algorithm: {algorithm or 'unavailable'}",
        f"size: {fingerprint[0] if fingerprint else 'unavailable'}",
        f"fingerprint: {fingerprint[1] if fingerprint else 'unavailable'}",
        "private key: yes",
        f"public key: {'yes' if public_exists else 'no'}",
        f"owner uid: {owner}",
        f"mode: {mode}",
        f"loaded in agent: {loaded}",
    ]
    if link == "outside-home":
        details.append("symlink: resolves outside the home directory")
    results = [CheckResult(check_slug("keys.private", path.name), "keys", Status.PASS, f"Private key {path.name}.", details="\n".join(details))]
    if link == "outside-home":
        results.append(CheckResult(check_slug("keys.symlink", path.name), "keys", Status.WARN, f"Private key symlink resolves outside the home directory: {path.name}", details=str(path.resolve())))
    assessment = None
    try:
        info = path.stat()
        assessment = assess_mode("private_key", info.st_mode, info.st_uid, ctx.uid, path)
    except OSError as exc:
        results.append(CheckResult(check_slug("keys.permissions", path.name), "keys", Status.FAIL, f"Private key is not accessible: {path.name}", details=exc.strerror))
    if assessment is not None and assessment.status is not Status.PASS:
        results.append(
            CheckResult(check_slug("keys.permissions", path.name), "keys", assessment.status, assessment.message, details=f"Expected: {assessment.expected}", recommendation=assessment.recommendation)
        )
    if not public_exists:
        results.append(
            CheckResult(check_slug("keys.missing_public", path.name), "keys", Status.WARN, f"Private key has no public key file: {path.name}", recommendation=f"ssh-keygen -y -f {path} > {public}")
        )
    elif not encrypted:
        match = _pair_matches(ctx, path, public)
        if match is False:
            results.append(
                CheckResult(
                    check_slug("keys.mismatch", path.name),
                    "keys",
                    Status.FAIL,
                    f"Public and private keys do not match: {path.name}",
                    recommendation=f"Regenerate the public key with ssh-keygen -y -f {path}",
                )
            )
        elif match is None:
            results.append(CheckResult(check_slug("keys.invalid", path.name), "keys", Status.FAIL, f"Private key could not be read: {path.name}"))
    else:
        results.append(
            CheckResult(
                check_slug("keys.encrypted", path.name),
                "keys",
                Status.PASS,
                f"Private key is encrypted; pair verification was not performed: {path.name}",
                details=("Verification unavailable without a passphrase. No passphrase was requested."),
            )
        )
    if algorithm:
        flagged = algorithm_status(algorithm)
        if flagged is Status.WARN:
            results.append(
                CheckResult(check_slug("keys.obsolete", path.name), "keys", Status.WARN, algorithm_label(algorithm) + f" ({path.name}).", recommendation="Prefer an Ed25519 key for new use.")
            )
    unreadable = fingerprint is None and not encrypted and public_exists is False and b"PRIVATE KEY" in prefix and not any(item.check_id.startswith("keys.invalid") for item in results)
    if unreadable:
        results.append(CheckResult(check_slug("keys.invalid", path.name), "keys", Status.FAIL, f"Private key file is invalid: {path.name}"))
    return results


def _fingerprint_for(ctx: Context, path: Path) -> tuple[str, str, str, str] | None:
    keygen = ctx.which("ssh-keygen")
    if keygen is None or not path.is_file():
        return None
    completed = ctx.runner.run([keygen, "-l", "-f", str(path)], timeout=ctx.timeout, env=ctx.environ)
    if completed.timed_out or completed.returncode != 0:
        return None
    return parse_fingerprint(completed.stdout or completed.stderr)


def _pair_matches(ctx: Context, private: Path, public: Path) -> bool | None:
    keygen = ctx.which("ssh-keygen")
    parsed = parse_public_key(_read_text(public) or "")
    if keygen is None or parsed is None:
        return None
    completed = ctx.runner.run([keygen, "-y", "-P", "", "-f", str(private)], timeout=ctx.timeout, env=ctx.environ)
    if completed.timed_out:
        return None
    derived = parse_public_key(completed.stdout)
    if completed.returncode != 0 or derived is None:
        lowered = (completed.stderr or "").lower()
        if "passphrase" in lowered or "encrypted" in lowered:
            return None
        if "invalid" in lowered or "not a" in lowered or completed.returncode != 0:
            return None
        return None
    return derived[0] == parsed[0] and derived[1] == parsed[1]


def _agent_fingerprints(ctx: Context) -> set[str] | None:
    if "SSH_AUTH_SOCK" not in ctx.environ:
        return None
    ssh_add = ctx.which("ssh-add")
    if ssh_add is None:
        return None
    completed = ctx.runner.run([ssh_add, "-l"], timeout=ctx.timeout, env=ctx.environ)
    if completed.timed_out or completed.returncode not in {0, 1}:
        return None
    fingerprints: set[str] = set()
    for line in completed.stdout.splitlines():
        parsed = parse_fingerprint(line)
        if parsed:
            fingerprints.add(parsed[1])
    return fingerprints


def _read_directives(ctx: Context, config_path: Path, results: list[CheckResult]) -> list:
    if not config_path.exists() and not config_path.is_symlink():
        results.append(CheckResult("config.file", "config", Status.PASS, "No user SSH configuration file. OpenSSH defaults apply.", details=str(config_path)))
        return []
    if symlink_problem(config_path, ctx.home) == "broken":
        results.append(CheckResult("config.file", "config", Status.FAIL, "SSH configuration symlink is broken.", details=str(config_path)))
        return []
    text = _read_text(config_path)
    if text is None:
        results.append(CheckResult("config.file", "config", Status.FAIL, "SSH configuration file is not readable.", details=str(config_path)))
        return []
    results.append(CheckResult("config.file", "config", Status.PASS, "SSH configuration file is readable.", details=str(config_path)))
    return parse_config(text)


def _include_results(ctx: Context, directives: list, config_path: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    for directive in directives:
        if directive.keyword != "include":
            continue
        for token in split_arguments(directive.argument):
            expanded = expand_ssh_path(token, ctx.home, ctx.ssh_dir)
            matches = _glob_matches(expanded, token)
            if any(char in token for char in "*?["):
                if not matches:
                    results.append(CheckResult(check_slug("config.include", token), "config", Status.WARN, f"Include pattern matched no files: {token}", details=f"{config_path}:{directive.line_no}"))
                continue
            if not expanded.exists():
                results.append(
                    CheckResult(
                        check_slug("config.include", expanded.name), "config", Status.FAIL, f"Included configuration file does not exist: {expanded}", details=f"{config_path}:{directive.line_no}"
                    )
                )
    return results


def _static_identity_results(ctx: Context, directives: list) -> list[CheckResult]:
    results: list[CheckResult] = []
    for directive in directives:
        if directive.keyword != "identityfile" or directive.context != "global":
            continue
        for token in split_arguments(directive.argument):
            path = expand_ssh_path(token, ctx.home, ctx.ssh_dir)
            if path.is_file():
                continue
            results.append(
                CheckResult(
                    check_slug("config.identity", path.name), "config", Status.WARN, f"Global IdentityFile does not exist: {path}", recommendation="Create the key or remove the IdentityFile line."
                )
            )
    return results


def _unsafe_results(directives: list) -> list[CheckResult]:
    results: list[CheckResult] = []
    for directive in directives:
        reason = unsafe_reason(directive.keyword, directive.argument)
        if reason is None:
            continue
        where = directive.context if directive.context == "global" else (f"{directive.context} {directive.context_arg}")
        details = f"Line {directive.line_no}, {where}."
        if directive.keyword == "proxycommand":
            details += " The command was not executed."
        results.append(
            CheckResult(check_slug("config.unsafe", f"{directive.keyword}.{directive.line_no}"), "config", Status.WARN, f"Unsafe SSH option {directive.keyword}: {reason}.", details=details)
        )
    return results


def _effective_results(ctx: Context, host: str, completed: CommandResult) -> list[CheckResult]:
    values = parse_ssh_g(completed.stdout)
    fields = {
        "HostName": _first(values, "hostname"),
        "User": _first(values, "user"),
        "Port": _first(values, "port"),
        "IdentityFile": ", ".join(values.get("identityfile", [])) or "-",
        "IdentitiesOnly": _first(values, "identitiesonly"),
        "ProxyJump": _first(values, "proxyjump"),
        "ProxyCommand": "configured" if _configured(values.get("proxycommand", [])) else "none",
        "PreferredAuthentications": _first(values, "preferredauthentications"),
        "StrictHostKeyChecking": _first(values, "stricthostkeychecking"),
        "UserKnownHostsFile": ", ".join(values.get("userknownhostsfile", [])) or "-",
    }
    details = "\n".join(f"{name}: {value}" for name, value in fields.items())
    results = [CheckResult("config.effective", "config", Status.PASS, f"Effective configuration for {host}.", details=details)]
    for token in values.get("identityfile", []):
        if token.lower() == "none":
            continue
        path = expand_ssh_path(token, ctx.home, ctx.ssh_dir)
        if path.is_file():
            continue
        results.append(CheckResult(check_slug("config.effective_identity", path.name), "config", Status.WARN, f"Effective IdentityFile does not exist: {path}"))
    for keyword, argument in (("stricthostkeychecking", fields["StrictHostKeyChecking"]), ("proxycommand", _first(values, "proxycommand")), ("forwardagent", _first(values, "forwardagent"))):
        reason = unsafe_reason(keyword, argument)
        if reason is None:
            continue
        results.append(CheckResult(check_slug("config.effective_unsafe", keyword), "config", Status.WARN, f"Effective {keyword} for {host}: {reason}."))
    return results


def _agent_contact(ctx: Context) -> list[CheckResult]:
    ssh_add = ctx.which("ssh-add")
    if ssh_add is None:
        return [CheckResult("agent.contact", "agent", Status.FAIL, "ssh-add was not found, so the agent could not be contacted.")]
    completed = ctx.runner.run([ssh_add, "-l"], timeout=ctx.timeout, env=ctx.environ)
    if completed.timed_out:
        return [CheckResult("agent.contact", "agent", Status.FAIL, "Timed out while contacting the SSH agent.")]
    if completed.returncode == 2:
        return [CheckResult("agent.contact", "agent", Status.FAIL, "The SSH agent could not be contacted.", details=redact(completed.stderr)[:500])]
    if completed.returncode == 1:
        return [
            CheckResult("agent.contact", "agent", Status.PASS, "SSH agent is reachable."),
            CheckResult("agent.identities", "agent", Status.WARN, "The SSH agent has no identities.", recommendation="An empty agent is not a failure if key files are used directly."),
        ]
    if completed.returncode != 0:
        return [CheckResult("agent.contact", "agent", Status.FAIL, "The SSH agent returned an unexpected error.", details=redact(completed.stderr or completed.stdout)[:500])]
    lines = []
    fingerprints: set[str] = set()
    for raw in completed.stdout.splitlines():
        parsed = parse_fingerprint(raw)
        if parsed is None:
            continue
        bits, fingerprint, comment, algorithm = parsed
        fingerprints.add(fingerprint)
        lines.append(f"{algorithm or 'key'} {bits} {fingerprint} {comment}".strip())
    results = [
        CheckResult("agent.contact", "agent", Status.PASS, "SSH agent is reachable."),
        CheckResult(
            "agent.identities",
            "agent",
            Status.PASS,
            f"SSH agent has {len(lines)} loaded identity." if len(lines) == 1 else f"SSH agent has {len(lines)} loaded identities.",
            details="\n".join(lines) or None,
        ),
    ]
    missing = _configured_not_loaded(ctx, fingerprints)
    if missing:
        results.append(
            CheckResult(
                "agent.not_loaded",
                "agent",
                Status.WARN,
                "Some configured identity files are not loaded in the agent.",
                details="\n".join(str(path) for path in missing),
                recommendation="SSH can still use the key files directly. No key was loaded.",
            )
        )
    return results


def _configured_not_loaded(ctx: Context, fingerprints: set[str]) -> list[Path]:
    config_path = ctx.ssh_dir / "config"
    text = _read_text(config_path)
    if text is None:
        return []
    missing: list[Path] = []
    for directive in parse_config(text):
        if directive.keyword != "identityfile":
            continue
        for token in split_arguments(directive.argument):
            path = expand_ssh_path(token, ctx.home, ctx.ssh_dir)
            if not path.is_file():
                continue
            public = path if path.suffix == ".pub" else Path(str(path) + ".pub")
            target = public if public.is_file() else path
            parsed = _fingerprint_for(ctx, target)
            if parsed and parsed[1] not in fingerprints:
                missing.append(path)
    return missing


def _apple_keychain(ctx: Context) -> CheckResult:
    config_path = ctx.ssh_dir / "config"
    text = (_read_text(config_path) or "").lower()
    notes = ["Keychain settings were not changed."]
    if "usekeychain" in text:
        notes.append("UseKeychain is present in the SSH configuration.")
    if "addkeystoagent" in text:
        notes.append("AddKeysToAgent is present in the SSH configuration.")
    return CheckResult("agent.apple", "agent", Status.PASS, "macOS SSH agent integration was inspected.", details="\n".join(notes))


def _known_host_paths(ctx: Context) -> list[Path]:
    paths: list[Path] = []
    config_path = ctx.ssh_dir / "config"
    text = _read_text(config_path)
    if text:
        for directive in parse_config(text):
            if directive.keyword != "userknownhostsfile":
                continue
            for token in split_arguments(directive.argument):
                if token.lower() in {"none", "/dev/null"}:
                    continue
                paths.append(expand_ssh_path(token, ctx.home, ctx.ssh_dir))
    if not paths:
        paths.append(ctx.ssh_dir / "known_hosts")
    for extra in ctx.settings.known_host_files:
        paths.append(expand_ssh_path(str(extra), ctx.home, ctx.ssh_dir))
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _one_known_host_file(ctx: Context, path: Path) -> list[CheckResult]:
    if symlink_problem(path, ctx.home) == "broken":
        return [CheckResult(check_slug("known_hosts.symlink", path.name), "known-hosts", Status.FAIL, f"Known-host symlink is broken: {path}")]
    if not path.exists():
        return [CheckResult(check_slug("known_hosts.file", path.name), "known-hosts", Status.SKIP, f"Known-host file does not exist: {path}")]
    try:
        info = path.stat()
    except OSError as exc:
        return [CheckResult(check_slug("known_hosts.file", path.name), "known-hosts", Status.FAIL, f"Known-host file is not accessible: {path}", details=exc.strerror)]
    assessment = assess_mode("known_hosts", info.st_mode, info.st_uid, ctx.uid, path)
    results = [
        CheckResult(
            check_slug("known_hosts.permissions", path.name), "known-hosts", assessment.status, assessment.message, details=f"Expected: {assessment.expected}", recommendation=assessment.recommendation
        )
    ]
    text = _read_text(path)
    if text is None:
        results.append(CheckResult(check_slug("known_hosts.read", path.name), "known-hosts", Status.FAIL, f"Known-host file is not readable: {path}"))
        return results
    malformed: list[str] = []
    seen: dict[str, int] = {}
    hosts: dict[str, set[str]] = defaultdict(set)
    for line_no, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            seen[stripped] = seen.get(stripped, 0) + 1
        entry = parse_known_host_line(raw, line_no)
        if entry is None:
            continue
        if not entry.ok:
            malformed.append(f"line {entry.line_no}: {entry.reason}")
            continue
        if entry.hashed:
            continue
        for host in entry.hosts:
            hosts[host].add(entry.key_type)
    if malformed:
        results.append(CheckResult(check_slug("known_hosts.malformed", path.name), "known-hosts", Status.FAIL, f"Malformed known-host entries in {path.name}.", details="\n".join(malformed)))
    else:
        results.append(CheckResult(check_slug("known_hosts.entries", path.name), "known-hosts", Status.PASS, f"Known-host entries in {path.name} are readable."))
    duplicates = [line for line, count in seen.items() if count > 1]
    if duplicates:
        results.append(
            CheckResult(
                check_slug("known_hosts.duplicate", path.name), "known-hosts", Status.WARN, f"Exact duplicate known-host entries in {path.name}.", details=f"{len(duplicates)} duplicated line(s)."
            )
        )
    multi = [f"{host}: {', '.join(sorted(types))}" for host, types in sorted(hosts.items()) if len(types) > 1]
    if multi:
        results.append(CheckResult(check_slug("known_hosts.types", path.name), "known-hosts", Status.PASS, f"Some hosts in {path.name} have more than one key type.", details="\n".join(multi)))
    return results


def _host_in_file(ctx: Context, path: Path, hostname: str) -> bool:
    keygen = ctx.which("ssh-keygen")
    if keygen is None:
        return False
    completed = ctx.runner.run([keygen, "-F", hostname, "-f", str(path)], timeout=ctx.timeout, env=ctx.environ)
    return completed.returncode == 0 and not completed.timed_out


def _glob_matches(expanded: Path, token: str) -> list[Path]:
    if not any(char in token for char in "*?["):
        return []
    try:
        return sorted(expanded.parent.glob(expanded.name))
    except OSError:
        return []


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _identity(path: Path) -> str:
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _first(values: dict[str, list[str]], key: str) -> str:
    items = values.get(key, [])
    return items[0] if items else "-"


def _configured(values: list[str]) -> bool:
    return any(item and item.lower() != "none" for item in values)


def _suppress(results: list[CheckResult], suppressed: set[str]) -> list[CheckResult]:
    if not suppressed:
        return results
    return [result for result in results if not (result.status is Status.WARN and result.check_id in suppressed)]
