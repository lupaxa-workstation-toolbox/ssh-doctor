"""CLI entrypoint."""

from __future__ import annotations

from pathlib import Path

import pytest

from lupaxa.ssh_doctor.cli import main
from lupaxa.ssh_doctor.model import CheckResult, Status
from lupaxa.ssh_doctor.version import get_version


def test_help_exits_zero() -> None:
    assert main(["--help"]) == 0


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    captured = capsys.readouterr().out
    assert "ssh-doctor" in captured
    assert get_version() in captured


def test_missing_command_is_invalid() -> None:
    assert main([]) == 3


def test_verbose_and_quiet_conflict(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", "--verbose", "--quiet"]) == 3
    assert "cannot be combined" in capsys.readouterr().err


def test_bad_config_exits_3(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "bad.toml"
    config.write_text("timeout = [\n", encoding="utf-8")
    assert main(["check", "--config", str(config)], home=tmp_path / "home") == 3
    assert "Invalid configuration" in capsys.readouterr().err


def test_execution_failure_exits_4(tmp_path: Path) -> None:
    def explode(*_args: object, **_kwargs: object) -> list[CheckResult]:
        raise RuntimeError("boom")

    code = main(["system"], home=tmp_path, executor=explode)
    assert code == 4


def test_json_report_shape(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    code = main(["system", "--json"], home=home, environ={"PATH": "", "HOME": str(home)}, which=lambda _name: None, platform_system="Linux")
    assert code == 2
    import json

    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == get_version()
    assert payload["os"]["system"] == "Linux"
    assert set(payload["summary"]) == {"passed", "warnings", "failed", "skipped"}
    assert payload["results"]
    assert {"check_id", "category", "status", "message", "details", "recommendation"} <= set(payload["results"][0])


def test_suppressed_warning_is_omitted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    ssh.chmod(0o700)
    private = ssh / "id_dsa"
    private.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    private.chmod(0o600)
    public = ssh / "id_dsa.pub"
    public.write_text("ssh-dss AAAAkey comment\n", encoding="utf-8")
    public.chmod(0o644)
    config = tmp_path / "config.toml"
    config.write_text('enabled_categories = ["keys"]\nsuppressed_warnings = ["keys.obsolete.id_dsa"]\n', encoding="utf-8")

    from lupaxa.ssh_doctor.process import CommandResult

    def runner_run(argv: list[str], *, timeout: float, env: dict[str, str] | None = None) -> CommandResult:
        del timeout, env
        if "-l" in argv:
            return CommandResult(argv, 0, "1024 SHA256:abc comment (DSA)\n", "", False)
        if "-y" in argv:
            return CommandResult(argv, 0, "ssh-dss AAAAkey comment\n", "", False)
        return CommandResult(argv, 0, "", "", False)

    class Runner:
        def run(self, argv: list[str], *, timeout: float, env: dict[str, str] | None = None) -> CommandResult:
            return runner_run(argv, timeout=timeout, env=env)

    code = main(["check", "--config", str(config)], home=home, environ={"PATH": "/usr/bin", "HOME": str(home)}, which=lambda name: f"/usr/bin/{name}", runner=Runner(), platform_system="Linux")
    assert code == 0
    assert "obsolete" not in capsys.readouterr().out.lower()


def test_result_type_is_exported() -> None:
    item = CheckResult("system.ssh_present", "system", Status.PASS, "ok")
    assert item.status is Status.PASS
