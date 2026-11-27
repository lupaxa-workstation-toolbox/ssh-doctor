"""Parsers and path helpers for local SSH files."""

from __future__ import annotations

import base64
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .model import Status

_FINGERPRINT = re.compile(r"^(?P<bits>\d+)\s+(?P<fp>SHA256:\S+)\s*(?P<rest>.*)$")
_OBSOLETE = {"ssh-dss", "ssh-dsa", "dss", "dsa"}
_DEPRECATED = {"ssh-rsa", "rsa"}


@dataclass(frozen=True)
class Directive:
    """One SSH client configuration directive."""

    context: str
    context_arg: str
    keyword: str
    argument: str
    line_no: int


@dataclass(frozen=True)
class KnownHostEntry:
    """One parsed known-host line."""

    ok: bool
    hosts: tuple[str, ...]
    key_type: str
    hashed: bool
    line_no: int
    reason: str


@dataclass(frozen=True)
class ModeAssessment:
    """Permission judgement for one path."""

    status: Status
    message: str
    expected: str
    recommendation: str | None


def check_slug(prefix: str, name: str) -> str:
    """Build a stable check id from a file name."""
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")
    return f"{prefix}.{safe or 'item'}"


def find_on_path(name: str, path_value: str) -> list[str]:
    """Return executable ``name`` matches on ``path_value``, in order."""
    found: list[str] = []
    for entry in path_value.split(os.pathsep):
        if not entry:
            continue
        candidate = Path(entry) / name
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                resolved = str(candidate.resolve())
                if resolved not in found:
                    found.append(resolved)
        except OSError:
            continue
    return found


def expand_user(value: str, home: Path) -> Path:
    """Expand a leading ``~`` against ``home``."""
    if value == "~":
        return home
    if value.startswith("~/"):
        return home / value[2:]
    return Path(value)


def expand_ssh_path(value: str, home: Path, ssh_dir: Path) -> Path:
    """Resolve a config path against the SSH directory when it is relative."""
    expanded = expand_user(value, home)
    if expanded.is_absolute():
        return expanded
    return ssh_dir / expanded


def strip_comment(line: str) -> str:
    """Remove an unquoted ``#`` comment."""
    out: list[str] = []
    quote = ""
    for char in line:
        if quote:
            out.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            out.append(char)
            continue
        if char == "#":
            break
        out.append(char)
    return "".join(out).strip()


def split_arguments(argument: str) -> list[str]:
    """Split a directive argument on unquoted whitespace."""
    parts: list[str] = []
    current: list[str] = []
    quote = ""
    for char in argument.strip():
        if quote:
            if char == quote:
                quote = ""
            else:
                current.append(char)
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char.isspace():
            if current:
                parts.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current))
    return parts


def parse_config(text: str) -> list[Directive]:
    """Parse SSH client configuration directives.

    ``Host`` and ``Match`` blocks are recorded so later checks do not treat
    conditional settings as global errors.
    """
    context = "global"
    context_arg = ""
    directives: list[Directive] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = strip_comment(raw)
        if not line:
            continue
        keyword, argument = _split_directive(line)
        if keyword in {"host", "match"}:
            context = keyword
            context_arg = argument
        directives.append(Directive(context, context_arg, keyword, argument, line_no))
    return directives


def parse_ssh_g(text: str) -> dict[str, list[str]]:
    """Parse ``ssh -G`` key/value output."""
    values: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or " " not in line:
            continue
        key, value = line.split(maxsplit=1)
        values.setdefault(key.lower(), []).append(value.strip())
    return values


def unsafe_reason(keyword: str, argument: str) -> str | None:
    """Return why a directive is unsafe, or ``None`` when it is acceptable."""
    value = argument.strip().lower()
    if keyword == "stricthostkeychecking" and value in {"no", "off", "accept-new"}:
        return "host keys may be accepted without a strict check"
    if keyword == "userknownhostsfile":
        tokens = {item.lower() for item in split_arguments(argument)}
        if tokens & {"none", "/dev/null"}:
            return "known-host checks are disabled"
    if keyword == "forwardagent" and value == "yes":
        return "the SSH agent is forwarded to the remote host"
    if keyword == "permitlocalcommand" and value == "yes":
        return "local commands from the remote host are permitted"
    if keyword == "proxycommand" and value and value != "none":
        return "a proxy command is configured and was not executed"
    if keyword == "protocol" and value == "1":
        return "SSH protocol 1 is obsolete"
    if keyword == "ciphers":
        weak = [item for item in _comma_tokens(value) if item in {"arcfour", "3des-cbc", "blowfish-cbc"}]
        if weak:
            return "weak ciphers are enabled: " + ", ".join(weak)
    return None


def parse_known_host_line(line: str, line_no: int) -> KnownHostEntry | None:
    """Parse one known-host line. Blank lines and comments return ``None``."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split()
    if parts and parts[0] in {"@cert-authority", "@revoked"}:
        parts = parts[1:]
    if len(parts) < 3:
        return KnownHostEntry(False, (), "", False, line_no, "too few fields")
    hosts = tuple(part for part in parts[0].split(",") if part)
    key_type = parts[1]
    hashed = hosts[0].startswith("|1|") if hosts else False
    if not _looks_like_key_type(key_type):
        return KnownHostEntry(False, hosts, key_type, hashed, line_no, "unrecognised key type")
    return KnownHostEntry(True, hosts, key_type, hashed, line_no, "")


def assess_mode(kind: str, mode: int, owner_uid: int, user_uid: int, path: Path) -> ModeAssessment:
    """Judge a path against OpenSSH permission rules."""
    bits = stat.S_IMODE(mode)
    octal = f"{bits:04o}"
    owned = owner_uid == user_uid
    group_write = bool(bits & 0o020)
    other_write = bool(bits & 0o002)
    group_or_other = bool(bits & 0o077)
    if kind == "directory":
        expected = "owned by you and not writable by group or others (0700 is typical)"
        if not owned:
            return _bad(path, octal, expected, "chown", "directory owner is not you")
        if group_write or other_write:
            return _bad(path, octal, expected, "chmod 700", "directory is writable by group or others")
        return ModeAssessment(Status.PASS, f"{path} mode {octal} is acceptable.", expected, None)
    if kind == "private_key":
        expected = "owned by you with no group or other access (0600)"
        if not owned:
            return _bad(path, octal, expected, "chown", "private key owner is not you")
        if group_or_other:
            return _bad(path, octal, expected, "chmod 600", "private key is accessible by group or others")
        return ModeAssessment(Status.PASS, f"{path} mode {octal} is acceptable.", expected, None)
    if kind == "config":
        expected = "owned by you and not writable by group or others (0644 is acceptable)"
        if not owned:
            return _bad(path, octal, expected, "chown", "configuration owner is not you")
        if group_write or other_write:
            return _bad(path, octal, expected, "chmod 644", "configuration is writable by group or others")
        return ModeAssessment(Status.PASS, f"{path} mode {octal} is acceptable.", expected, None)
    expected = "not writable by others (0644 is acceptable)"
    if other_write:
        label = kind.replace("_", " ")
        return _bad(path, octal, expected, "chmod 644", f"{label} is writable by others")
    if not owned:
        return ModeAssessment(Status.WARN, f"{path} is not owned by you (mode {octal}).", expected, f"chown {user_uid} {path}")
    return ModeAssessment(Status.PASS, f"{path} mode {octal} is acceptable.", expected, None)


def read_prefix(path: Path, size: int = 4096) -> bytes | None:
    """Read the start of a file without raising for missing or unreadable files."""
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return None


def is_encrypted_private_key(data: bytes) -> bool:
    """Return whether a private-key blob is encrypted."""
    head = data[:4096]
    if b"ENCRYPTED" in head or b"Proc-Type: 4,ENCRYPTED" in head:
        return True
    if b"OPENSSH PRIVATE KEY" not in head:
        return False
    body = b"".join(line.strip() for line in data.splitlines() if line and not line.startswith(b"-----"))
    try:
        decoded = base64.b64decode(body, validate=False)
    except ValueError:
        return False
    magic = b"openssh-key-v1\x00"
    if not decoded.startswith(magic):
        return False
    rest = decoded[len(magic) :]
    if len(rest) < 4:
        return False
    length = int.from_bytes(rest[:4], "big")
    if length < 0 or 4 + length > len(rest):
        return False
    return rest[4 : 4 + length] != b"none"


def classify_file(path: Path) -> str:
    """Classify an SSH directory entry."""
    name = path.name
    if name == "config" or name.startswith("config."):
        return "config"
    if name == "known_hosts" or name.startswith("known_hosts"):
        return "known_hosts"
    if name in {"authorized_keys", "authorized_keys2", "environment", "rc", "moduli"}:
        return "ignore"
    if name.endswith(".pub"):
        return "public_key"
    if path.is_symlink() and not path.is_file() and not path.is_dir():
        return "private_key"
    prefix = read_prefix(path)
    if prefix is None:
        return "unreadable"
    if b"PRIVATE KEY" in prefix:
        return "private_key"
    text = prefix.decode("ascii", "ignore").lstrip()
    if text.startswith(("ssh-", "ecdsa-", "sk-ssh-", "sk-ecdsa-")):
        return "public_key"
    if name.startswith("id_"):
        return "private_key"
    return "ignore"


def parse_public_key(text: str) -> tuple[str, str, str] | None:
    """Return algorithm, blob, and comment from a public-key line."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-----"):
            continue
        parts = line.split()
        if len(parts) < 2 or not _looks_like_key_type(parts[0]):
            continue
        return parts[0], parts[1], " ".join(parts[2:])
    return None


def parse_fingerprint(text: str) -> tuple[str, str, str, str] | None:
    """Return bits, fingerprint, comment, and algorithm from ``ssh-keygen -l``."""
    for raw in text.splitlines():
        match = _FINGERPRINT.match(raw.strip())
        if match is None:
            continue
        rest = match.group("rest").strip()
        comment = rest
        algorithm = ""
        trailing = re.match(r"^(.*)\(([^)]+)\)\s*$", rest)
        if trailing:
            comment = trailing.group(1).strip()
            algorithm = trailing.group(2).strip()
        return match.group("bits"), match.group("fp"), comment, algorithm
    return None


def algorithm_status(algorithm: str) -> Status | None:
    """Return WARN for obsolete or deprecated algorithms."""
    name = algorithm.strip().lower()
    if name in _OBSOLETE:
        return Status.WARN
    if name in _DEPRECATED:
        return Status.WARN
    return None


def algorithm_label(algorithm: str) -> str:
    """Describe why an algorithm was flagged."""
    name = algorithm.strip().lower()
    if name in _OBSOLETE:
        return f"{algorithm} is an obsolete SSH algorithm"
    return f"{algorithm} is a deprecated SSH algorithm"


def symlink_problem(path: Path, home: Path) -> str | None:
    """Return ``broken`` or ``outside-home`` for an unsafe symlink."""
    if not path.is_symlink():
        return None
    try:
        if not path.is_file() and not path.is_dir():
            return "broken"
        target = path.resolve(strict=True)
    except OSError:
        return "broken"
    try:
        target.relative_to(home.resolve())
    except ValueError:
        return "outside-home"
    return None


def _split_directive(line: str) -> tuple[str, str]:
    if "=" in line:
        left, right = line.split("=", 1)
        if " " not in left.strip():
            return left.strip().lower(), right.strip().strip("\"'")
    pieces = line.split(None, 1)
    keyword = pieces[0].lower()
    argument = pieces[1].strip() if len(pieces) > 1 else ""
    return keyword, argument


def _comma_tokens(argument: str) -> list[str]:
    tokens: list[str] = []
    for part in split_arguments(argument):
        tokens.extend(item for item in part.split(",") if item)
    return tokens


def _looks_like_key_type(value: str) -> bool:
    return value.startswith(("ssh-", "ecdsa-", "sk-ssh-", "sk-ecdsa-"))


def _bad(path: Path, octal: str, expected: str, command: str, message: str) -> ModeAssessment:
    recommendation = f"{command} {path}" if command.startswith("chmod") else f"chown $(whoami) {path}"
    return ModeAssessment(Status.FAIL, f"{message}: {path} mode {octal}.", expected, recommendation)
