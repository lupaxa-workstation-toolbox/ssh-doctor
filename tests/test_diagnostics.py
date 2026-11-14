"""Local diagnostic checks."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from lupaxa.ssh_doctor.diagnose import (
    Context,
    check_config,
    check_keys,
    check_permissions,
    run_diagnostics,
)
from lupaxa.ssh_doctor.model import Status, exit_code_for
from lupaxa.ssh_doctor.process import CommandResult
from lupaxa.ssh_doctor.settings import Settings
from lupaxa.ssh_doctor.sshdata import assess_mode, parse_known_host_line


class FakeRunner:
    """Return scripted command results and record the argv list."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.by_flag: dict[str, CommandResult] = {}

    def run(
        self,
        argv: list[str],
        *,
        timeout: float,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        del timeout, env
        self.calls.append(list(argv))
        for flag, result in self.by_flag.items():
            if flag in argv:
                return result
        return CommandResult(list(argv), 0, "", "", False)


def _which_map(names: set[str] | None = None) -> Callable[[str], str | None]:
    available = names if names is not None else {"ssh", "ssh-keygen", "ssh-add", "ssh-agent"}

    def which(name: str) -> str | None:
        if name in available:
            return f"/usr/bin/{name}"
        return None

    return which


def _ctx(
    tmp_path: Path,
    *,
    runner: FakeRunner | None = None,
    which: Callable[[str], str | None] | None = None,
    environ: dict[str, str] | None = None,
    settings: Settings | None = None,
    make_ssh: bool = True,
    platform_system: str = "Linux",
) -> Context:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    ssh = home / ".ssh"
    if make_ssh:
        ssh.mkdir(exist_ok=True)
        ssh.chmod(0o700)
    env = {"PATH": str(tmp_path / "bin"), "HOME": str(home)}
    if environ:
        env.update(environ)
    chosen = settings or Settings()
    return Context(
        settings=chosen,
        runner=runner or FakeRunner(),
        home=home,
        ssh_dir=chosen.ssh_directory or ssh,
        timeout=2.0,
        environ=env,
        uid=os.getuid(),
        platform_system=platform_system,
        platform_release="test",
        platform_machine="arm64",
        which=which or _which_map(),
        path_value=env["PATH"],
        explicit_ssh_dir=chosen.ssh_directory is not None,
    )


def _pem(body: str = "AAAA") -> str:
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"


def _statuses(results: list, prefix: str) -> dict[str, Status]:
    return {item.check_id: item.status for item in results if item.check_id.startswith(prefix)}


def test_private_key_mode_rules(tmp_path: Path) -> None:
    path = tmp_path / "id_ed25519"
    loose = assess_mode("private_key", 0o644, 1, 1, path)
    tight = assess_mode("private_key", 0o600, 1, 1, path)
    public = assess_mode("public_key", 0o644, 1, 1, path)
    directory = assess_mode("directory", 0o755, 1, 1, path)
    assert loose.status is Status.FAIL
    assert tight.status is Status.PASS
    assert public.status is Status.PASS
    assert directory.status is Status.PASS
    assert "0600" in loose.expected


def test_missing_ssh_and_directory(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, which=_which_map(set()), make_ssh=False)
    results = run_diagnostics("check", ctx)
    found = {item.check_id: item for item in results}
    assert found["system.ssh_present"].status is Status.FAIL
    assert found["system.ssh_version"].status is Status.SKIP
    assert found["system.ssh_dir"].status is Status.FAIL
    assert found["permissions.directory"].status is Status.FAIL
    assert exit_code_for(results) == 2


def test_loose_private_key_permissions(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    key = ctx.ssh_dir / "id_ed25519"
    key.write_text(_pem(), encoding="utf-8")
    key.chmod(0o644)
    results = check_permissions(ctx)
    match = [item for item in results if item.check_id == "permissions.private_key.id_ed25519"]
    assert match[0].status is Status.FAIL
    assert match[0].recommendation is not None
    assert "chmod 600" in match[0].recommendation


def test_broken_symlink(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    link = ctx.ssh_dir / "id_ed25519"
    link.symlink_to(ctx.ssh_dir / "missing-target")
    results = check_permissions(ctx)
    assert any(item.status is Status.FAIL and "Broken symlink" in item.message for item in results)


def test_symlink_outside_home(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    target = tmp_path / "outside"
    target.write_text(_pem(), encoding="utf-8")
    target.chmod(0o600)
    link = ctx.ssh_dir / "id_ed25519"
    link.symlink_to(target)
    results = check_keys(ctx)
    assert any(item.status is Status.WARN and "outside" in item.message for item in results)


def test_key_inventory_cases(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    runner = ctx.runner
    assert isinstance(runner, FakeRunner)
    runner.by_flag["-l"] = CommandResult([], 0, "256 SHA256:abc comment (ED25519)\n", "", False)
    runner.by_flag["-y"] = CommandResult([], 0, "ssh-ed25519 AAAAOther comment\n", "", False)
    private = ctx.ssh_dir / "id_ed25519"
    private.write_text(_pem(), encoding="utf-8")
    private.chmod(0o600)
    public = ctx.ssh_dir / "id_ed25519.pub"
    public.write_text("ssh-ed25519 AAAAPublic comment\n", encoding="utf-8")
    public.chmod(0o644)
    orphan = ctx.ssh_dir / "orphan.pub"
    orphan.write_text("ssh-ed25519 AAAAOrphan comment\n", encoding="utf-8")
    orphan.chmod(0o644)
    encrypted = ctx.ssh_dir / "id_encrypted"
    encrypted.write_text(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "SECRET-KEY-MATERIAL\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    encrypted.chmod(0o600)
    (ctx.ssh_dir / "id_encrypted.pub").write_text("ssh-ed25519 AAAAEnc comment\n", encoding="utf-8")
    (ctx.ssh_dir / "id_encrypted.pub").chmod(0o644)
    dsa = ctx.ssh_dir / "id_dsa"
    dsa.write_text(_pem("BBBB"), encoding="utf-8")
    dsa.chmod(0o600)
    (ctx.ssh_dir / "id_dsa.pub").write_text("ssh-dss AAAAdsa comment\n", encoding="utf-8")
    (ctx.ssh_dir / "id_dsa.pub").chmod(0o644)
    dup_a = ctx.ssh_dir / "dup_a.pub"
    dup_b = ctx.ssh_dir / "dup_b.pub"
    dup_a.write_text("ssh-ed25519 AAAASame comment\n", encoding="utf-8")
    dup_b.write_text("ssh-ed25519 AAAASame comment\n", encoding="utf-8")
    dup_a.chmod(0o644)
    dup_b.chmod(0o644)

    def selective(
        argv: list[str],
        *,
        timeout: float,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        del timeout, env
        runner.calls.append(list(argv))
        if "-y" in argv:
            name = Path(argv[-1]).name
            if name == "id_ed25519":
                blob = "AAAAOther"
                algo = "ssh-ed25519"
            elif name == "id_dsa":
                blob = "AAAAdsa"
                algo = "ssh-dss"
            else:
                blob = "AAAAPublic"
                algo = "ssh-ed25519"
            return CommandResult(argv, 0, f"{algo} {blob} comment\n", "", False)
        if "-l" in argv:
            name = Path(argv[-1]).name
            fingerprint = "SHA256:same" if name.startswith("dup_") else f"SHA256:{name}"
            algo = "DSA" if "dsa" in name else "ED25519"
            return CommandResult(argv, 0, f"256 {fingerprint} comment ({algo})\n", "", False)
        return CommandResult(argv, 0, "", "", False)

    runner.run = selective  # type: ignore[method-assign]
    results = check_keys(ctx)
    rendered = "\n".join(item.message for item in results)
    assert "do not match" in rendered
    assert "no public key" not in rendered
    assert "no matching private key" in rendered
    assert "encrypted" in rendered.lower()
    assert "obsolete" in rendered or "deprecated" in rendered
    assert any(item.check_id == "keys.duplicate" for item in results)
    joined = "\n".join((item.details or "") + item.message for item in results)
    assert "SECRET-KEY-MATERIAL" not in joined
    assert not any("-y" in call and "id_encrypted" in call[-1] for call in runner.calls)


def test_config_syntax_include_and_conditional(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    config = ctx.ssh_dir / "config"
    config.write_text(
        "\n".join(
            [
                "Include missing.conf",
                "Host only.example",
                "  IdentityFile ~/.ssh/missing_for_host",
                "Match host only.example",
                "  IdentityFile ~/.ssh/also_missing",
                "FooBar yes",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config.chmod(0o644)
    runner = ctx.runner
    assert isinstance(runner, FakeRunner)
    runner.by_flag["-G"] = CommandResult([], 255, "", "Bad configuration option: foobar", False)
    results = check_config(ctx, host=None)
    assert any(item.check_id == "config.syntax" and item.status is Status.FAIL for item in results)
    assert any(item.status is Status.FAIL and "missing.conf" in item.message for item in results)
    assert not any("missing_for_host" in item.message for item in results)


def test_effective_host_config(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    config = ctx.ssh_dir / "config"
    config.write_text("Host github.com\n  User git\n", encoding="utf-8")
    config.chmod(0o644)
    runner = ctx.runner
    assert isinstance(runner, FakeRunner)
    runner.by_flag["-G"] = CommandResult(
        [],
        0,
        "\n".join(
            [
                "user git",
                "hostname github.com",
                "port 22",
                "identityfile ~/.ssh/id_missing",
                "identitiesonly yes",
                "proxyjump none",
                "proxycommand none",
                "preferredauthentications publickey",
                "stricthostkeychecking ask",
                "userknownhostsfile ~/.ssh/known_hosts",
            ]
        )
        + "\n",
        "",
        False,
    )
    results = check_config(ctx, host="github.com")
    effective = next(item for item in results if item.check_id == "config.effective")
    assert effective.details is not None
    fields = dict(line.split(": ", 1) for line in effective.details.splitlines())
    assert fields["HostName"] == "github.com"
    assert fields["User"] == "git"
    assert any("id_missing" in item.message for item in results)
    assert all("proxycommand" not in " ".join(call) for call in runner.calls)


def test_agent_states(tmp_path: Path) -> None:
    unset = _ctx(tmp_path, environ={"SSH_AUTH_SOCK": ""})
    unset.environ.pop("SSH_AUTH_SOCK", None)
    results = run_diagnostics("agent", unset)
    assert any(item.check_id == "agent.socket" and item.status is Status.WARN for item in results)

    missing = _ctx(tmp_path, environ={"SSH_AUTH_SOCK": str(tmp_path / "no-socket")})
    results = run_diagnostics("agent", missing)
    assert any(item.check_id == "agent.socket" and item.status is Status.FAIL for item in results)

    sock = tmp_path / "agent.sock"
    sock.write_text("", encoding="utf-8")
    runner = FakeRunner()
    runner.by_flag["-l"] = CommandResult([], 1, "", "The agent has no identities.", False)
    empty = _ctx(tmp_path, runner=runner, environ={"SSH_AUTH_SOCK": str(sock)})
    results = run_diagnostics("agent", empty)
    identities = [item for item in results if item.check_id == "agent.identities"]
    assert identities[0].status is Status.WARN

    runner = FakeRunner()
    runner.by_flag["-l"] = CommandResult([], 2, "", "Could not open a connection", False)
    dead = _ctx(tmp_path, runner=runner, environ={"SSH_AUTH_SOCK": str(sock)})
    results = run_diagnostics("agent", dead)
    assert any(item.check_id == "agent.contact" and item.status is Status.FAIL for item in results)
    assert all(call[:2] != ["/usr/bin/ssh-agent", "start"] for call in runner.calls)


def test_known_hosts_entries(tmp_path: Path) -> None:
    hashed = parse_known_host_line("|1|salt|hash ssh-ed25519 AAAAone comment", 1)
    assert hashed is not None
    assert hashed.ok
    assert hashed.hashed
    bad = parse_known_host_line("not a valid line", 2)
    assert bad is not None
    assert not bad.ok

    ctx = _ctx(tmp_path)
    known = ctx.ssh_dir / "known_hosts"
    known.write_text(
        "\n".join(
            [
                "example.com ssh-ed25519 AAAAone one",
                "example.com ssh-rsa AAAAtwo two",
                "example.com ssh-ed25519 AAAAone one",
                "bad line",
                "|1|salt|hash ssh-ed25519 AAAAhash comment",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    known.chmod(0o644)
    runner = ctx.runner
    assert isinstance(runner, FakeRunner)
    runner.by_flag["-F"] = CommandResult([], 0, "found\n", "", False)
    results = run_diagnostics("known-hosts", ctx, known_host="example.com")
    assert any("Malformed" in item.message for item in results)
    assert any(item.check_id.startswith("known_hosts.duplicate") for item in results)
    typed = [item for item in results if item.check_id.startswith("known_hosts.types")]
    assert typed[0].status is Status.PASS
    searched = [item for item in results if item.check_id == "known_hosts.search"]
    assert searched[0].status is Status.PASS


def test_timeout_does_not_stop_later_checks(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    runner = ctx.runner
    assert isinstance(runner, FakeRunner)
    runner.by_flag["-V"] = CommandResult([], 124, "", "", True)
    results = run_diagnostics("check", ctx)
    version = [item for item in results if item.check_id == "system.ssh_version"]
    assert version[0].status is Status.FAIL
    assert any(item.category == "permissions" for item in results)
    assert any(item.category == "known-hosts" for item in results)


def test_unsafe_option_is_a_warning_not_a_syntax_error(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    config = ctx.ssh_dir / "config"
    config.write_text("StrictHostKeyChecking no\nProxyCommand /bin/false\n", encoding="utf-8")
    config.chmod(0o644)
    results = check_config(ctx, host=None)
    assert any(item.check_id == "config.syntax" and item.status is Status.PASS for item in results)
    assert any("stricthostkeychecking" in item.check_id for item in results)
    assert any("proxycommand" in item.check_id for item in results)
    assert all("bin/false" not in " ".join(call) for call in ctx.runner.calls)  # type: ignore[attr-defined]


def test_disabled_category_is_skipped(tmp_path: Path) -> None:
    settings = Settings(disabled_categories={"agent"})
    ctx = _ctx(tmp_path, settings=settings)
    results = run_diagnostics("check", ctx)
    assert any(item.check_id == "agent.disabled" and item.status is Status.SKIP for item in results)
    assert not any(item.check_id == "agent.socket" for item in results)
