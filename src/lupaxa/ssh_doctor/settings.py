"""Optional TOML configuration."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CATEGORIES = (
    "system",
    "permissions",
    "keys",
    "config",
    "agent",
    "known-hosts",
)


class ConfigError(Exception):
    """The application configuration or arguments are invalid."""


@dataclass
class Settings:
    """Runtime settings, including built-in defaults."""

    ssh_directory: Path | None = None
    key_search_directories: list[Path] = field(default_factory=list)
    known_host_files: list[Path] = field(default_factory=list)
    enabled_categories: set[str] | None = None
    disabled_categories: set[str] = field(default_factory=set)
    timeout: float = 10.0
    output_format: str = "text"
    suppressed_warnings: set[str] = field(default_factory=set)

    def allows(self, category: str) -> bool:
        """Return whether ``category`` runs as part of ``check``."""
        if category in self.disabled_categories:
            return False
        enabled = self.enabled_categories
        return enabled is None or category in enabled


def resolve_config_path(
    explicit: Path | None,
    environ: dict[str, str],
    home: Path,
) -> Path | None:
    """Find the configuration file, if the user has one."""
    if explicit is not None:
        path = explicit.expanduser()
        if not path.is_file():
            raise ConfigError(f"Configuration file not found: {path}")
        return path
    env_path = environ.get("SSH_DOCTOR_CONFIG")
    if env_path:
        path = Path(env_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"Configuration file not found: {path}")
        return path
    xdg = environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else home / ".config"
    default = base / "ssh-doctor" / "config.toml"
    if default.is_file():
        return default
    return None


def load_settings(path: Path | None) -> Settings:
    """Load settings from ``path``, or return defaults."""
    if path is None:
        return Settings()
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Could not read configuration: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid configuration: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError("Invalid configuration: expected a TOML table")
    return _settings_from_table(payload)


def _settings_from_table(payload: dict[str, object]) -> Settings:
    settings = Settings()
    ssh_directory = payload.get("ssh_directory")
    if ssh_directory is not None:
        settings.ssh_directory = _as_path(ssh_directory, "ssh_directory")
    settings.key_search_directories = _path_list(
        payload.get("key_search_directories", []),
        "key_search_directories",
    )
    settings.known_host_files = _path_list(
        payload.get("known_host_files", []),
        "known_host_files",
    )
    enabled = payload.get("enabled_categories")
    if enabled is not None:
        settings.enabled_categories = set(_categories(enabled, "enabled_categories"))
    disabled = payload.get("disabled_categories", [])
    settings.disabled_categories = set(_categories(disabled, "disabled_categories"))
    timeout = payload.get("timeout", settings.timeout)
    if isinstance(timeout, bool) or not isinstance(timeout, int | float):
        raise ConfigError("timeout must be a number")
    if timeout <= 0:
        raise ConfigError("timeout must be greater than 0")
    settings.timeout = float(timeout)
    output_format = payload.get("output_format", "text")
    if output_format not in {"text", "json"}:
        raise ConfigError("output_format must be text or json")
    settings.output_format = str(output_format)
    suppressed = payload.get("suppressed_warnings", [])
    if not isinstance(suppressed, list) or not all(isinstance(item, str) for item in suppressed):
        raise ConfigError("suppressed_warnings must be a list of strings")
    settings.suppressed_warnings = set(suppressed)
    return settings


def _as_path(value: object, name: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{name} must be a path")
    return Path(value).expanduser()


def _path_list(value: object, name: str) -> list[Path]:
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be a list of paths")
    return [_as_path(item, name) for item in value]


def _categories(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{name} must be a list of category names")
    unknown = [item for item in value if item not in CATEGORIES]
    if unknown:
        raise ConfigError(f"Unknown diagnostic category: {unknown[0]}")
    return list(value)
