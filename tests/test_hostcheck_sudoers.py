"""Optional least-privilege sudoers path for root-only read queries. No sudo runs."""

import json
import subprocess
import uuid
from pathlib import Path

import pytest
from pydantic import SecretStr

from acsc_cli import agent, main
from acsc_cli.hostcheck import collector, privileged

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "sudoers" / "rakis-hostcheck.example"


def test_drop_in_grants_exactly_the_four_read_only_command_lines():
    text = privileged.sudoers_text("rakis")
    rules = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert rules == [
        "rakis ALL=(root) NOPASSWD: /usr/sbin/sshd -T, /usr/sbin/nft list ruleset, "
        "/usr/sbin/ufw status verbose, /usr/sbin/iptables -S"
    ]
    # No wildcards, shells, environment passing or extra runas targets.
    for forbidden in ("*", "ALL ", "SETENV", "sh ", "bash", "(ALL", "!", "\\"):
        assert forbidden not in rules[0].split("NOPASSWD:")[1]
    for name, path in privileged.ROOT_QUERIES.items():
        assert privileged.privileged_argv(name)[1:] == collector.ALLOWLIST[name][1:]
        assert path.startswith("/usr/sbin/")


def test_shipped_example_matches_generated_drop_in():
    assert EXAMPLE.read_text() == privileged.sudoers_text("rakis")


@pytest.mark.parametrize("user", ["", "root ALL", "a,b", "x\nALL", "Rakis", "a" * 40, "-x"])
def test_user_name_is_strict(user):
    with pytest.raises(ValueError):
        privileged.sudoers_text(user)


def test_unknown_or_unprivileged_queries_cannot_use_sudo():
    with pytest.raises(collector.CollectorError):
        privileged.privileged_argv("dpkg")
    with pytest.raises(collector.CollectorError):
        privileged.privileged_argv("id")


def test_runner_uses_sudo_n_only_for_granted_queries(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, b"permitrootlogin no\n", b"")

    monkeypatch.setattr(privileged.shutil, "which", lambda name: name)
    monkeypatch.setattr(privileged.subprocess, "run", fake_run)
    base_calls = []
    run = privileged.runner(lambda argv: base_calls.append(argv) or "base")
    assert run(collector.ALLOWLIST["sshd"]) == "permitrootlogin no\n"
    assert run(collector.ALLOWLIST["sockets"]) == "base"
    args, kwargs = calls[0]
    assert args == ("/usr/bin/sudo", "-n", "--", "/usr/sbin/sshd", "-T")
    assert kwargs["env"] == dict(collector.SAFE_ENV) and "shell" not in kwargs
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert base_calls == [collector.ALLOWLIST["sockets"]]
    assert len(calls) == 1


def test_runner_falls_back_when_sudo_is_not_granted(monkeypatch):
    monkeypatch.setattr(privileged.shutil, "which", lambda name: name)
    monkeypatch.setattr(
        privileged.subprocess,
        "run",
        lambda args, **kw: subprocess.CompletedProcess(args, 1, b"", b"a password is required"),
    )
    run = privileged.runner(lambda argv: None)
    assert run(collector.ALLOWLIST["nft"]) is None


def test_runner_ignores_a_sudo_not_at_the_fixed_path(monkeypatch):
    monkeypatch.setattr(privileged.shutil, "which", lambda name: "/tmp/sudo")
    monkeypatch.setattr(privileged.subprocess, "run", lambda *a, **k: pytest.fail("no sudo"))
    assert privileged.runner(lambda argv: "base")(collector.ALLOWLIST["ufw"]) == "base"


def test_cli_prints_drop_in_and_never_writes(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(main.getpass, "getuser", lambda: "rakis")
    monkeypatch.setattr(Path, "write_text", lambda *a, **k: pytest.fail("must not write"))
    assert main.main(["--config", str(tmp_path / "c.json"), "sudoers-file"]) == 0
    assert capsys.readouterr().out == privileged.sudoers_text("rakis")


def test_cli_remembers_sudo_choice_for_background_runs(tmp_path, monkeypatch, capsys):
    from tests.test_host_checks import AGENT_TOKEN, API, ASSET, ENROLLMENT, ORG

    identity = agent.AgentIdentity(
        api_url=API,
        org_id=ORG,
        asset_id=ASSET,
        enrollment_id=uuid.UUID(ENROLLMENT),
        token=SecretStr(AGENT_TOKEN),
        private_key=SecretStr("A" * 43 + "="),
    )
    config = tmp_path / "rakis" / "config.json"
    agent.save_identity(agent.default_path(config), identity)
    used = []
    monkeypatch.setattr(main, "_collect", lambda use_sudo: used.append(use_sudo) or {})
    args = ["--config", str(config), "host-checks", "--dry-run"]
    assert main.main([*args, "--sudo-queries", "on", "--remember"]) == 0
    assert agent.load_identity(agent.default_path(config)).sudo_queries is True
    assert main.main(args) == 0
    assert main.main([*args, "--sudo-queries", "off"]) == 0
    assert used == [True, True, False]
    assert main.main([*args, "--remember"]) == 2
    out = capsys.readouterr().out
    assert AGENT_TOKEN not in out
    json.loads(out.splitlines()[0])
