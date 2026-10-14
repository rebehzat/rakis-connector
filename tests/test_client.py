"""Public connector lifecycle, least privilege, secret handling, and packaging."""

import hashlib
import json
import os
import zipfile
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from acsc_cli import __version__, main
from acsc_cli.client import Client, ClientError
from acsc_cli.config import Config, disconnect, load, save

TOKEN = "acsc_a_" + "a" * 12 + "_" + "b" * 43
ASSET = "11111111-1111-4111-8111-111111111111"
CFG = Config(api_url="https://api.example.test", token=SecretStr(TOKEN))


def connection(**overrides):
    return {
        "connected": True,
        "asset_id": ASSET,
        "name": "My server",
        "last_seen_at": "2026-10-13T10:00:00+00:00",
        "server_time": "2026-10-13T10:00:00+00:00",
        **overrides,
    }


@pytest.fixture
def api(monkeypatch):
    calls = []

    def handler(req):
        calls.append(req)
        assert req.headers["Authorization"] == "Bearer " + TOKEN
        if req.url.path == "/agent/v1/heartbeat":
            assert req.method == "POST"
            assert json.loads(req.content) == {"agent_version": __version__}
        else:
            assert req.method == "GET" and req.url.path == "/agent/v1/connection"
        return httpx.Response(200, json=connection(private=TOKEN))

    monkeypatch.setattr(
        main, "Client", lambda config: Client(config, transport=httpx.MockTransport(handler))
    )
    monkeypatch.setenv("RAKIS_CONNECT_TOKEN", TOKEN)
    monkeypatch.setenv("RAKIS_API_URL", CFG.api_url)
    return calls


def test_connect_status_disconnect_and_private_credentials(api, tmp_path, monkeypatch, capsys):
    path = tmp_path / "private" / "config.json"
    assert main.main(["--config", str(path), "connect", "--api-url", CFG.api_url]) == 0
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert load(path) == CFG
    output = capsys.readouterr()
    assert json.loads(output.out)["stored"]
    assert TOKEN not in output.out + output.err
    monkeypatch.delenv("RAKIS_CONNECT_TOKEN")
    assert main.main(["--config", str(path), "status"]) == 0
    assert main.main(["--config", str(path), "disconnect"]) == 0
    assert not path.exists()
    assert [request.url.path for request in api] == ["/agent/v1/heartbeat", "/agent/v1/connection"]
    assert TOKEN not in str(CFG)


def test_masked_token_no_store_and_watch_only_send_heartbeat(api, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("RAKIS_CONNECT_TOKEN")
    prompt = []
    monkeypatch.setattr(main.getpass, "getpass", lambda label: prompt.append(label) or TOKEN)
    sleep_count = []

    def sleep(delay):
        sleep_count.append(delay)
        if len(sleep_count) == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(main.time, "sleep", sleep)
    path = tmp_path / "config.json"
    assert (
        main.main(
            [
                "--config",
                str(path),
                "connect",
                "--api-url",
                CFG.api_url,
                "--no-store",
                "--watch",
                "--interval",
                "30",
            ]
        )
        == 130
    )
    assert prompt == ["Server connection token: "]
    assert sleep_count == [30, 30]
    assert len(api) == 2 and all(req.url.path == "/agent/v1/heartbeat" for req in api)
    assert not path.exists()
    assert TOKEN not in capsys.readouterr().out


@pytest.mark.parametrize("command", ["login", "assets", "scans", "wait", "execute", "upload"])
def test_control_commands_are_removed(command, monkeypatch):
    monkeypatch.setattr(main, "Client", lambda config: pytest.fail("must not contact API"))
    with pytest.raises(SystemExit) as caught:
        main.main([command])
    assert caught.value.code == 2
    assert not any(
        hasattr(Client, attr) for attr in ("scan", "wait", "assets", "findings", "scans")
    )


@pytest.mark.parametrize("interval", ["0", "29", "301", "bad"])
def test_invalid_watch_interval_fails_before_network(interval, monkeypatch):
    monkeypatch.setattr(main, "Client", lambda config: pytest.fail("must not contact API"))
    with pytest.raises(SystemExit):
        main.main(["connect", "--api-url", CFG.api_url, "--interval", interval])


@pytest.mark.parametrize(
    "url",
    [
        "http://remote.test",
        "https://user:secret@example.test",
        "https://example.test/api",
        "https://example.test?token=secret",
        "https://example.test#secret",
        "https://example.test:bad",
    ],
)
def test_origin_rejects_plaintext_or_credential_redirection(url):
    with pytest.raises(ValidationError):
        Config(api_url=url, token=SecretStr(TOKEN))


def test_only_asset_agent_tokens_and_explicit_loopback_http_are_accepted():
    with pytest.raises(ValidationError):
        Config(api_url=CFG.api_url, token=SecretStr("acsc_k_" + "a" * 12 + "_" + "b" * 43))
    with pytest.raises(ValidationError):
        Config(api_url="http://127.0.0.1:8000", token=SecretStr(TOKEN))
    assert (
        Config(
            api_url="http://127.0.0.1:8000", token=SecretStr(TOKEN), allow_local_http=True
        ).api_url
        == "http://127.0.0.1:8000"
    )


def test_config_rejects_links_shared_files_and_loose_permissions(tmp_path, monkeypatch):
    monkeypatch.delenv("RAKIS_CONNECT_TOKEN", raising=False)
    path = tmp_path / "private" / "config.json"
    save(path, CFG)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        load(path)
    with pytest.raises(ValueError):
        disconnect(path)
    path.chmod(0o600)
    link = path.parent / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        load(link)
    with pytest.raises(ValueError):
        save(link, CFG)
    with pytest.raises(ValueError):
        disconnect(link)
    os.link(path, path.parent / "shared.json")
    with pytest.raises(ValueError):
        load(path)


@pytest.mark.parametrize("status", [301, 401, 403, 500])
def test_transport_refuses_redirects_and_masks_server_errors(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, text=TOKEN, headers={"Location": "https://other.test"})

    client = Client(CFG, transport=httpx.MockTransport(handler))
    with pytest.raises(ClientError) as caught:
        client.heartbeat()
    assert TOKEN not in str(caught.value)
    assert len(calls) == 1
    assert caught.value.code == (3 if status in {401, 403} else 4)
    client.close()


@pytest.mark.parametrize(
    "response",
    [
        [],
        {},
        connection(connected=False),
        connection(asset_id="bad"),
        connection(name=[]),
        connection(name="a" * 501),
        connection(server_time="bad"),
        connection(last_seen_at="2026-10-13T10:00:00"),
    ],
)
def test_connection_response_fails_closed(response):
    client = Client(
        CFG, transport=httpx.MockTransport(lambda req: httpx.Response(200, json=response))
    )
    with pytest.raises(ClientError, match="Invalid connection response"):
        client.status()
    client.close()


def test_bounded_response_and_invalid_token_do_not_echo_secrets(monkeypatch, capsys):
    client = Client(
        CFG, transport=httpx.MockTransport(lambda req: httpx.Response(200, text="x" * 16385))
    )
    with pytest.raises(ClientError, match="exceeds limit"):
        client.status()
    client.close()
    monkeypatch.setenv("RAKIS_CONNECT_TOKEN", "synthetic-secret")
    monkeypatch.setenv("RAKIS_API_URL", CFG.api_url)
    assert main.main(["status"]) == 2
    assert "synthetic-secret" not in capsys.readouterr().err


def test_public_wheel_contains_client_only():
    downloads = Path(__file__).resolve().parents[1] / "dist"
    release = json.loads((downloads / "connector-release.json").read_text())
    wheels = [downloads / release["filename"]]
    assert wheels[0].exists()
    if not wheels:
        pytest.fail("run build_public_release.py to produce release artifact")
    with zipfile.ZipFile(wheels[0]) as wheel:
        names = wheel.namelist()
        assert all(name.startswith(("acsc_cli/", "rakis_connector-")) for name in names)
        assert not any("sarif" in name or ".env" in name for name in names)
        assert all("scans:write" not in wheel.read(name).decode() for name in names)

    source = downloads.parent / "acsc_cli"
    with zipfile.ZipFile(wheels[0]) as wheel:
        for path in source.glob("*.py"):
            assert wheel.read("acsc_cli/" + path.name) == path.read_bytes()
    release = json.loads((downloads / "connector-release.json").read_text())
    assert release["version"] == __version__
    assert release["filename"] == wheels[0].name
    assert release["sha256"] == hashlib.sha256(wheels[0].read_bytes()).hexdigest()


def test_reflected_token_in_server_metadata_is_redacted():
    client = Client(
        CFG,
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=connection(name=TOKEN))),
    )
    assert client.status()["name"] == "[redacted]"
    client.close()


def test_opted_in_cli_inspection_sends_only_safe_observations(tmp_path, monkeypatch, capsys):
    root = tmp_path / "chosen"
    root.mkdir()
    (root / ".env").write_text(
        "PASSWORD=private-password-fixture\nNORMAL_ENV=private-env-fixture\nDEBUG=true"
    )
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == "/agent/v1/configuration":
            payload = json.loads(request.content)
            assert payload["files"][0]["checks"] == ["debug_enabled", "embedded_credentials"]
            assert "private-password-fixture" not in request.content.decode()
            assert "private-env-fixture" not in request.content.decode()
            assert str(root) not in request.content.decode()
            assert set(payload) == {"agent_version", "files", "complete", "skipped_files"}
            return httpx.Response(
                200,
                json={
                    "job_id": ASSET,
                    "status": "succeeded",
                    "changed": True,
                    "complete": True,
                    "files_inspected": 1,
                    "findings_count": 2,
                    "skipped_files": 0,
                },
            )
        assert request.url.path == "/agent/v1/heartbeat"
        return httpx.Response(200, json=connection())

    monkeypatch.setenv("RAKIS_CONNECT_TOKEN", TOKEN)
    monkeypatch.setattr(
        main, "Client", lambda config: Client(config, transport=httpx.MockTransport(handler))
    )
    assert (
        main.main(["connect", "--api-url", CFG.api_url, "--no-store", "--config-root", str(root)])
        == 0
    )
    assert len(calls) == 2
    output = capsys.readouterr()
    assert TOKEN not in output.out and "private-password-fixture" not in output.out
    assert (root / ".env").read_text().startswith("PASSWORD=private-password-fixture")
