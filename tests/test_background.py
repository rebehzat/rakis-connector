"""User service lifecycle never puts credentials into systemd or command arguments."""

import json
import os
import stat
import subprocess

import pytest
from pydantic import SecretStr

from acsc_cli import background, main
from acsc_cli.config import Config, save

TOKEN = "acsc_a_" + "a" * 12 + "_" + "b" * 43


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(background.os, "getuid", lambda: 1000)
    monkeypatch.setattr(background.sys, "platform", "linux")
    # The fixture uses the real runner's ownership for private-file checks.
    real_uid = tmp_path.stat().st_uid
    monkeypatch.setattr(background.os, "getuid", lambda: real_uid or 1000)
    monkeypatch.setattr(background, "load", lambda *args, **kwargs: None)
    calls = []
    lingering = [True]

    def command(name, *args):
        calls.append((name, *args))
        if name == "loginctl":
            if args[0] == "show-user":
                return subprocess.CompletedProcess(args, 0, "yes\n" if lingering[0] else "no\n", "")
            lingering[0] = True
        output = "active\n" if "show" in args else ""
        return subprocess.CompletedProcess(args, 0, output, "")

    monkeypatch.setattr(background, "_command", command)
    return calls, lingering


def test_prepare_service_directory_creates_private_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(background.os, "getuid", lambda: os.stat(tmp_path).st_uid)
    directory = tmp_path / "nested" / "systemd" / "user"

    background._prepare_service_directory(directory)

    assert directory.is_dir()
    assert stat.S_IMODE(directory.stat().st_mode) & 0o077 == 0


def test_prepare_service_directory_repairs_owned_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(background.os, "getuid", lambda: os.stat(tmp_path).st_uid)
    directory = tmp_path / "user"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)

    background._prepare_service_directory(directory)

    assert stat.S_IMODE(directory.stat().st_mode) == 0o755


def test_prepare_service_directory_refuses_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(background.os, "getuid", lambda: os.stat(tmp_path).st_uid)
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(background.BackgroundError, match="real directory"):
        background._prepare_service_directory(linked)


def test_prepare_service_directory_refuses_foreign_owner_without_chmod(tmp_path, monkeypatch):
    directory = tmp_path / "user"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    before = stat.S_IMODE(directory.stat().st_mode)
    monkeypatch.setattr(background.os, "getuid", lambda: directory.stat().st_uid + 1)

    with pytest.raises(background.BackgroundError, match="owned by UID"):
        background._prepare_service_directory(directory)

    assert stat.S_IMODE(directory.stat().st_mode) == before


def test_non_root_start_installs_private_secret_free_unit(service, tmp_path, monkeypatch):
    calls, _ = service
    # CI may be root; simulate ownership consistently for the generated directory.
    monkeypatch.setattr(background.os, "getuid", lambda: os.stat(tmp_path).st_uid)
    if os.stat(tmp_path).st_uid == 0:
        pytest.skip("real service-file ownership test requires a non-root test runner")
    cfg = tmp_path / 'path with space % and " quote.json'
    result = background.manage("start", cfg, 60)
    unit_path = background._unit_path()
    unit = unit_path.read_text()
    assert result == {
        "background": "active",
        "survives_logout": True,
        "service": background.UNIT,
        "runs_as_root": False,
    }
    assert unit_path.stat().st_mode & 0o777 == 0o600
    assert " -m acsc_cli --config " in unit and " run --interval 60" in unit
    assert "%%" in unit and '\\"' in unit
    assert TOKEN not in unit and TOKEN not in repr(calls)
    assert "NoNewPrivileges=yes" in unit
    assert all(call[1] == "--user" for call in calls if call[0] == "systemctl")
    assert [call[2] for call in calls if call[0] == "systemctl"] == [
        "daemon-reload",
        "enable",
        "restart",
        "show",
    ]


def test_root_start_is_rejected_before_any_commands(monkeypatch, tmp_path):
    monkeypatch.setattr(background.os, "getuid", lambda: 0)
    monkeypatch.setattr(background, "_command", lambda *args: pytest.fail("no root service"))
    with pytest.raises(background.BackgroundError, match="without sudo"):
        background.manage("start", tmp_path / "config.json", 60)


def test_denied_linger_never_writes_or_starts_service(service, tmp_path, monkeypatch):
    def denied(name, *args):
        assert name == "loginctl"
        return subprocess.CompletedProcess(args, 1, "", "private policy error")

    monkeypatch.setattr(background, "_command", denied)
    with pytest.raises(background.BackgroundError, match="host denied"):
        background.manage("start", tmp_path / "config.json", 60)
    assert not background._unit_path().exists()


def test_stop_does_not_remove_credentials_or_disable_other_users(service, tmp_path):
    calls, _ = service
    target = background._unit_path()
    target.parent.mkdir(parents=True, mode=0o700)
    target.write_text("# Managed by the Rakis passive connector\n")
    token_file = tmp_path / "credentials"
    token_file.write_text("private")
    assert background.manage("stop", token_file, 60) == {
        "background": "stopped",
        "token_retained": True,
    }
    assert token_file.read_text() == "private"
    assert calls == [("systemctl", "--user", "disable", "--now", background.UNIT)]


def test_status_reports_missing_linger_without_enabling_it(service, tmp_path):
    calls, lingering = service
    lingering[0] = False
    assert background.manage("status", tmp_path / "missing", 60)["survives_logout"] is False
    assert not any("enable-linger" in call for call in calls)


@pytest.mark.parametrize("value", ["bad\npath", "bad\tpath", "bad\x00path"])
def test_service_paths_reject_control_characters(value):
    with pytest.raises(background.BackgroundError, match="control characters"):
        background._quote(value)


def test_command_timeout_does_not_expose_subprocess_output(monkeypatch):
    monkeypatch.setattr(background.shutil, "which", lambda name: "/usr/bin/" + name)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 30, output=TOKEN)

    monkeypatch.setattr(background.subprocess, "run", timeout)
    with pytest.raises(background.BackgroundError) as caught:
        background._command("systemctl", "--user", "status")
    assert TOKEN not in str(caught.value)


def test_run_reads_private_saved_config_ignoring_token_environment(tmp_path, monkeypatch, capsys):
    cfg = Config(api_url="https://api.example.test", token=SecretStr(TOKEN))
    path = tmp_path / "private" / "config.json"
    save(path, cfg)
    monkeypatch.setenv("RAKIS_CONNECT_TOKEN", "different-invalid-token")
    calls = []

    class FakeClient:
        def __init__(self, loaded):
            assert loaded == cfg

        def heartbeat(self):
            calls.append("heartbeat")
            return {"connected": True}

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(main, "Client", FakeClient)
    monkeypatch.setattr(
        main.time, "sleep", lambda delay: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    assert main.main(["--config", str(path), "run"]) == 130
    assert calls == ["heartbeat", "closed"]
    assert TOKEN not in capsys.readouterr().out


def test_background_error_is_actionable_and_no_network(tmp_path, monkeypatch, capsys):
    def denied(*args):
        raise background.BackgroundError("This host denied enabling it")

    monkeypatch.setattr(main, "manage", denied)
    monkeypatch.setattr(main, "Client", lambda cfg: pytest.fail("no API needed"))
    assert main.main(["background", "start"]) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "This host denied enabling it"


def test_start_enables_only_current_users_linger(service, tmp_path):
    calls, lingering = service
    lingering[0] = False
    background.manage("start", tmp_path / "saved.json", 30)
    assert ("loginctl", "enable-linger", str(os.getuid())) in calls
    assert background._unit_path().read_text().count("run --interval 30") == 1


def test_start_refuses_unrelated_service(service, tmp_path):
    target = background._unit_path()
    target.parent.mkdir(parents=True, mode=0o700)
    target.write_text("[Service]\nExecStart=/bin/sleep infinity\n")
    with pytest.raises(background.BackgroundError, match="unrelated"):
        background.manage("start", tmp_path / "saved.json", 60)
    assert target.read_text().startswith("[Service]")
    assert not any(call[0] == "systemctl" for call in service[0])


def test_start_refuses_symlink_service(service, tmp_path):
    other = tmp_path / "other"
    other.write_text("untouched")
    target = background._unit_path()
    target.parent.mkdir(parents=True, mode=0o700)
    target.symlink_to(other)
    with pytest.raises(background.BackgroundError, match="regular file"):
        background.manage("start", tmp_path / "saved.json", 60)
    assert other.read_text() == "untouched"


def test_invalid_saved_configuration_does_not_enable_linger(service, tmp_path, monkeypatch):
    def invalid(*args, **kwargs):
        assert kwargs == {"use_environment": False}
        raise ValueError("invalid")

    monkeypatch.setattr(background, "load", invalid)
    with pytest.raises(ValueError):
        background.manage("start", tmp_path / "saved.json", 60)
    assert service[0] == []


def test_start_does_not_claim_active_when_process_failed(service, tmp_path, monkeypatch):
    original = background._command

    def inactive(name, *args):
        result = original(name, *args)
        if name == "systemctl" and "show" in args:
            result.stdout = "failed\n"
        return result

    monkeypatch.setattr(background, "_command", inactive)
    with pytest.raises(background.BackgroundError, match="did not stay active"):
        background.manage("start", tmp_path / "saved.json", 60)


def test_service_quotes_dollars_not_environment_expansion():
    assert (
        background._quote("/home/user/$NAME/${TOKEN}/100%") == '"/home/user/$$NAME/$${TOKEN}/100%%"'
    )


def test_ai_requires_roots_before_credential_prompt(monkeypatch, capsys):
    monkeypatch.setattr(main.getpass, "getpass", lambda _: pytest.fail("must not ask token"))
    assert main.main(["connect", "--api-url", "https://api.example.test", "--ai"]) == 2
    assert "--config-root" in capsys.readouterr().err


def test_ai_scan_sends_only_safe_observations_and_does_not_persist_optin(
    tmp_path, monkeypatch, capsys
):
    root = tmp_path / "chosen"
    root.mkdir()
    private_value = "synthetic-password-that-must-stay-local"
    (root / ".env").write_text("PASSWORD=" + private_value)
    cfg = Config(
        api_url="https://api.example.test", token=SecretStr(TOKEN), config_roots=[str(root)]
    )
    path = tmp_path / "private" / "config.json"
    save(path, cfg)
    original = path.read_bytes()
    received = []

    class FakeClient:
        def __init__(self, loaded):
            assert loaded == cfg

        def configuration(self, observations, *, ai=False, retry_ai=False):
            received.append((observations, ai, retry_ai))
            return {"status": "succeeded", "ai_triage_status": "queued"}

        def close(self):
            pass

    monkeypatch.setattr(main, "Client", FakeClient)
    assert main.main(["--config", str(path), "scan", "--ai"]) == 0
    assert received[0][1:] == (True, True)
    assert main.main(["--config", str(path), "scan"]) == 0
    assert received[1][1:] == (False, False)
    assert private_value not in json.dumps(received)
    assert TOKEN not in capsys.readouterr().out
    assert path.read_bytes() == original


def test_saved_ai_configuration_requires_explicit_boolean_and_roots():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Config(api_url="https://api.example.test", token=SecretStr(TOKEN), ai_configuration=True)
    with pytest.raises(ValidationError):
        Config(
            api_url="https://api.example.test",
            token=SecretStr(TOKEN),
            config_roots=["/chosen"],
            ai_configuration="true",
        )


def test_client_ai_response_is_separate_from_local_success_and_redacts_unknown_errors():
    import httpx

    from acsc_cli.client import Client

    response = {
        "job_id": "11111111-1111-4111-8111-111111111111",
        "status": "succeeded",
        "changed": True,
        "complete": True,
        "findings_count": 1,
        "files_inspected": 1,
        "skipped_files": 0,
        "ai_triage_status": "queued",
        "ai_triage_error": TOKEN,
    }
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=response)

    cfg = Config(api_url="https://api.example.test", token=SecretStr(TOKEN))
    client = Client(cfg, transport=httpx.MockTransport(handler))
    observations = {"files": [], "complete": True, "skipped_files": 0}
    try:
        result = client.configuration(observations, ai=True)
        assert requests[0]["ai"] is True
        assert result["status"] == "succeeded" and result["ai_triage_status"] == "queued"
        assert result["ai_triage_error"] == "ai_review_unavailable"
        assert TOKEN not in json.dumps(result)
        client.configuration(observations)
        assert "ai" not in requests[1] and "retry_ai" not in requests[1]
        assert "retry_ai" not in requests[0]
        client.configuration(observations, ai=True, retry_ai=True)
        assert requests[2]["retry_ai"] is True
        client.configuration(observations, ai=True, retry_ai=False)
        assert "retry_ai" not in requests[3]
    finally:
        client.close()


@pytest.mark.parametrize("status", ["totally-safe", {}, None, 1])
def test_invalid_ai_status_is_bounded_client_error(status):
    from acsc_cli.client import ClientError, _inspection

    with pytest.raises(ClientError, match="Invalid AI"):
        _inspection(
            {
                "job_id": "11111111-1111-4111-8111-111111111111",
                "status": "succeeded",
                "changed": False,
                "complete": True,
                "findings_count": 0,
                "files_inspected": 0,
                "skipped_files": 0,
                "ai_triage_status": status,
            }
        )


def test_stop_refuses_unrelated_service_without_commands(service, tmp_path):
    target = background._unit_path()
    target.parent.mkdir(parents=True, mode=0o700)
    target.write_text("[Service]\nExecStart=/bin/sleep infinity\n")
    with pytest.raises(background.BackgroundError, match="unrelated"):
        background.manage("stop", tmp_path / "saved.json", 60)
    assert service[0] == []


def test_stop_absent_service_is_idempotent_without_commands(service, tmp_path):
    assert background.manage("stop", tmp_path / "saved.json", 60)["background"] == "stopped"
    assert service[0] == []


def test_disconnect_stops_installed_connector_before_deleting_secret(
    service, tmp_path, monkeypatch
):
    path = tmp_path / "private" / "config.json"
    save(path, Config(api_url="https://api.example.test", token=SecretStr(TOKEN)))
    target = background._unit_path()
    target.parent.mkdir(parents=True, mode=0o700)
    target.write_text("# Managed by the Rakis passive connector\n")
    original = background._command

    def assert_present(name, *args):
        assert path.exists(), "credential must remain until service is stopped"
        return original(name, *args)

    monkeypatch.setattr(background, "_command", assert_present)
    assert main.main(["--config", str(path), "disconnect"]) == 0
    assert not path.exists()
    assert service[0] == [("systemctl", "--user", "disable", "--now", background.UNIT)]


def test_disconnect_failed_stop_preserves_credential(service, tmp_path, monkeypatch, capsys):
    path = tmp_path / "private" / "config.json"
    save(path, Config(api_url="https://api.example.test", token=SecretStr(TOKEN)))
    target = background._unit_path()
    target.parent.mkdir(parents=True, mode=0o700)
    target.write_text("# Managed by the Rakis passive connector\n")
    monkeypatch.setattr(
        background, "_systemctl", lambda *args: subprocess.CompletedProcess(args, 1, "", TOKEN)
    )
    assert main.main(["--config", str(path), "disconnect"]) == 2
    assert path.exists()
    assert TOKEN not in capsys.readouterr().err


def test_retry_without_ai_is_rejected_before_network():
    import httpx

    from acsc_cli.client import Client, ClientError

    client = Client(
        Config(api_url="https://api.example.test", token=SecretStr(TOKEN)),
        transport=httpx.MockTransport(lambda request: pytest.fail("no network")),
    )
    try:
        with pytest.raises(ClientError, match="explicit AI opt-in"):
            client.configuration({}, retry_ai=True)
    finally:
        client.close()
