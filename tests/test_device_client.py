"""Device protection uploads signatures and counters only, never content."""

import json

import httpx
import pytest
from pydantic import SecretStr

from acsc_cli import __version__, main
from acsc_cli.client import Client, ClientError
from acsc_cli.config import Config, load, save

TOKEN = "acsc_a_" + "a" * 12 + "_" + "b" * 43
ASSET = "11111111-1111-4111-8111-111111111111"
CFG = Config(api_url="https://api.example.test", token=SecretStr(TOKEN))
REPORT = {
    "signature_db": {
        "version": "daily.hdb@2026-10-20",
        "updated_at": "2026-10-20T03:12:00Z",
        "files": 4,
    },
    "files_scanned": 1234,
    "directories_scanned": 2,
    "skipped_files": 0,
    "complete": True,
    "detections": [
        {
            "path": "root-1/www/shell.php",
            "signature": "Php.Webshell.Gen-1",
            "match_type": "hash",
            "size_bytes": 4096,
        }
    ],
}
RESPONSE = {
    "job_id": ASSET,
    "status": "succeeded",
    "checked_at": "2026-10-20T03:12:00+00:00",
    "files_scanned": 1234,
    "directories_scanned": 2,
    "skipped_files": 0,
    "complete": True,
    "engine": "clamav",
    "detections_count": 1,
    "signature_db_version": "daily.hdb@2026-10-20",
    "signature_db_updated_at": "2026-10-20T03:12:00+00:00",
    "changed": True,
}


class FakeIndex:
    """A signature index that finds nothing in the scanned files."""

    def match(self, stream, size):
        return []


class FakeDatabase:
    """A signature database that never reaches the network."""

    def __init__(self, *args, **kwargs):
        self.closed = False

    def refresh(self, **kwargs):
        return None

    def index(self):
        return FakeIndex()

    def status(self):
        return dict(REPORT["signature_db"])

    def close(self):
        self.closed = True


def test_device_scan_sends_only_the_contract_fields():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=RESPONSE)

    client = Client(CFG, transport=httpx.MockTransport(handler))
    try:
        result = client.device_scan(REPORT)
    finally:
        client.close()
    payload = json.loads(requests[0].content)
    assert requests[0].url.path == "/agent/v1/device-scan"
    assert requests[0].method == "POST"
    assert set(payload) == {
        "agent_version",
        "engine",
        "signature_db",
        "files_scanned",
        "directories_scanned",
        "skipped_files",
        "complete",
        "detections",
    }
    assert payload["agent_version"] == __version__
    assert payload["engine"] == "clamav"
    assert payload["detections"] == REPORT["detections"]
    assert result["detections_count"] == 1
    assert result["signature_db_version"] == "daily.hdb@2026-10-20"


def test_an_incomplete_device_report_is_refused_before_the_network():
    client = Client(
        CFG,
        transport=httpx.MockTransport(lambda request: pytest.fail("no network")),
    )
    try:
        with pytest.raises(ClientError, match="Invalid device scan report"):
            client.device_scan({"engine": "clamav"})
    finally:
        client.close()


@pytest.mark.parametrize(
    "response",
    [
        {**RESPONSE, "engine": "other"},
        {**RESPONSE, "job_id": "bad"},
        {**RESPONSE, "changed": "yes"},
        {**RESPONSE, "detections_count": -1},
        {**RESPONSE, "signature_db_version": ""},
        {**RESPONSE, "checked_at": "2026-10-20T03:12:00"},
    ],
)
def test_an_invalid_device_response_fails_closed(response):
    client = Client(
        CFG, transport=httpx.MockTransport(lambda req: httpx.Response(200, json=response))
    )
    try:
        with pytest.raises(ClientError, match="Invalid device scan response"):
            client.device_scan(REPORT)
    finally:
        client.close()


def test_the_device_command_uploads_a_report_and_prints_a_summary(tmp_path, monkeypatch, capsys):
    chosen = tmp_path / "chosen"
    chosen.mkdir()
    (chosen / "readme.txt").write_text("nothing to see here")
    path = tmp_path / "private" / "config.json"
    save(path, CFG)
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/agent/v1/device-scan":
            return httpx.Response(200, json=RESPONSE)
        return httpx.Response(200, json={"connected": True})

    monkeypatch.setattr(main, "ClamavDatabase", FakeDatabase)
    monkeypatch.setattr(
        main, "Client", lambda config: Client(config, transport=httpx.MockTransport(handler))
    )
    assert main.main(["--config", str(path), "device", "scan", "--path", str(chosen)]) == 0
    payload = json.loads(requests[0].content)
    assert requests[0].url.path == "/agent/v1/device-scan"
    assert payload["files_scanned"] == 1
    assert payload["detections"] == []
    summary = json.loads(capsys.readouterr().out)
    assert summary["files_scanned"] == 1
    assert summary["detections"] == 0
    assert summary["signature_db_version"] == "daily.hdb@2026-10-20"
    assert TOKEN not in capsys.readouterr().out


def test_the_device_command_needs_a_path(tmp_path, monkeypatch, capsys):
    path = tmp_path / "private" / "config.json"
    save(path, CFG)
    monkeypatch.setattr(main, "Client", lambda config: pytest.fail("no API needed"))
    assert main.main(["--config", str(path), "device", "scan"]) == 2
    assert "--device-path" in capsys.readouterr().err


def test_connect_stores_the_device_paths_with_the_configuration_roots(
    tmp_path, monkeypatch, capsys
):
    root = tmp_path / "config"
    root.mkdir()
    (root / "app.yaml").write_text("debug: true\n")
    chosen = tmp_path / "device"
    chosen.mkdir()
    (chosen / "readme.txt").write_text("nothing to see here")
    path = tmp_path / "private" / "config.json"
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/agent/v1/device-scan":
            return httpx.Response(200, json=RESPONSE)
        if request.url.path == "/agent/v1/configuration":
            return httpx.Response(
                200,
                json={
                    "job_id": ASSET,
                    "status": "succeeded",
                    "changed": True,
                    "complete": True,
                    "files_inspected": 1,
                    "findings_count": 1,
                    "skipped_files": 0,
                },
            )
        return httpx.Response(
            200,
            json={
                "connected": True,
                "asset_id": ASSET,
                "name": "My server",
                "last_seen_at": "2026-10-20T03:12:00+00:00",
                "server_time": "2026-10-20T03:12:00+00:00",
            },
        )

    monkeypatch.setenv("RAKIS_CONNECT_TOKEN", TOKEN)
    monkeypatch.setattr(main, "ClamavDatabase", FakeDatabase)
    monkeypatch.setattr(
        main, "Client", lambda config: Client(config, transport=httpx.MockTransport(handler))
    )
    assert (
        main.main(
            [
                "--config",
                str(path),
                "connect",
                "--api-url",
                CFG.api_url,
                "--config-root",
                str(root),
                "--device-path",
                str(chosen),
            ]
        )
        == 0
    )
    saved = load(path, use_environment=False)
    assert saved.config_roots == [str(root)]
    assert saved.device_paths == [str(chosen)]
    assert [request.url.path for request in requests] == [
        "/agent/v1/heartbeat",
        "/agent/v1/configuration",
        "/agent/v1/device-scan",
    ]
    assert TOKEN not in capsys.readouterr().out


def test_more_than_sixteen_device_paths_are_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("RAKIS_CONNECT_TOKEN", raising=False)
    monkeypatch.setattr(main.getpass, "getpass", lambda label: TOKEN)
    monkeypatch.setattr(main, "Client", lambda config: pytest.fail("no API needed"))
    assert (
        main.main(
            [
                "connect",
                "--api-url",
                CFG.api_url,
                *[argument for _ in range(17) for argument in ("--device-path", "/chosen")],
            ]
        )
        == 2
    )
    assert "sixteen" in capsys.readouterr().err


def _sleep_once(monkeypatch):
    """Let the first interval pass and stop the loop on the second one."""
    calls = []

    def sleep(delay):
        calls.append(delay)
        if len(calls) > 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(main.time, "sleep", sleep)
    # The device scan repeats on its own slower cadence. The tests drive the
    # clock, so they ask for the shorter one.
    monkeypatch.setattr(main, "DEVICE_RESCAN_SECONDS", 0)


def test_the_background_loop_repeats_the_device_scan_and_uploads_only_changes(
    tmp_path, monkeypatch
):
    chosen = tmp_path / "chosen"
    chosen.mkdir()
    (chosen / "readme.txt").write_text("nothing to see here")
    path = tmp_path / "private" / "config.json"
    save(
        path,
        Config(api_url=CFG.api_url, token=SecretStr(TOKEN), device_paths=[str(chosen)]),
    )
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/agent/v1/device-scan":
            return httpx.Response(200, json=RESPONSE)
        return httpx.Response(
            200,
            json={
                "connected": True,
                "asset_id": ASSET,
                "name": "My server",
                "last_seen_at": "2026-10-20T03:12:00+00:00",
                "server_time": "2026-10-20T03:12:00+00:00",
            },
        )

    monkeypatch.setattr(main, "ClamavDatabase", FakeDatabase)
    monkeypatch.setattr(
        main, "Client", lambda config: Client(config, transport=httpx.MockTransport(handler))
    )
    _sleep_once(monkeypatch)
    assert main.main(["--config", str(path), "run"]) == 130
    assert [request.url.path for request in requests] == [
        "/agent/v1/heartbeat",
        "/agent/v1/device-scan",
        "/agent/v1/heartbeat",
    ]


def test_the_background_loop_waits_for_its_own_cadence_before_rescanning(tmp_path, monkeypatch):
    chosen = tmp_path / "chosen"
    chosen.mkdir()
    (chosen / "readme.txt").write_text("nothing to see here")
    path = tmp_path / "private" / "config.json"
    save(
        path,
        Config(api_url=CFG.api_url, token=SecretStr(TOKEN), device_paths=[str(chosen)]),
    )
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/agent/v1/device-scan":
            return httpx.Response(200, json=RESPONSE)
        return httpx.Response(
            200,
            json={
                "connected": True,
                "asset_id": ASSET,
                "name": "My server",
                "last_seen_at": "2026-10-20T03:12:00+00:00",
                "server_time": "2026-10-20T03:12:00+00:00",
            },
        )

    monkeypatch.setattr(main, "ClamavDatabase", FakeDatabase)
    monkeypatch.setattr(main, "DEVICE_RESCAN_SECONDS", 600)
    monkeypatch.setattr(
        main, "Client", lambda config: Client(config, transport=httpx.MockTransport(handler))
    )
    calls = []

    def sleep(delay):
        calls.append(delay)
        if len(calls) > 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(main.time, "sleep", sleep)
    assert main.main(["--config", str(path), "run"]) == 130
    # The scan ran once. The next interval is too short for a second one.
    assert [request.url.path for request in requests] == [
        "/agent/v1/heartbeat",
        "/agent/v1/device-scan",
        "/agent/v1/heartbeat",
    ]


def test_the_background_loop_uploads_a_changed_device_report(tmp_path, monkeypatch):
    chosen = tmp_path / "chosen"
    chosen.mkdir()
    (chosen / "readme.txt").write_text("nothing to see here")
    path = tmp_path / "private" / "config.json"
    save(
        path,
        Config(api_url=CFG.api_url, token=SecretStr(TOKEN), device_paths=[str(chosen)]),
    )
    requests = []

    class ChangingDatabase(FakeDatabase):
        def status(self):
            status = dict(REPORT["signature_db"])
            status["version"] = f"daily.hdb@2026-10-{len(requests)}"
            return status

    def handler(request):
        requests.append(request)
        if request.url.path == "/agent/v1/device-scan":
            return httpx.Response(200, json=RESPONSE)
        return httpx.Response(
            200,
            json={
                "connected": True,
                "asset_id": ASSET,
                "name": "My server",
                "last_seen_at": "2026-10-20T03:12:00+00:00",
                "server_time": "2026-10-20T03:12:00+00:00",
            },
        )

    monkeypatch.setattr(main, "ClamavDatabase", ChangingDatabase)
    monkeypatch.setattr(
        main, "Client", lambda config: Client(config, transport=httpx.MockTransport(handler))
    )
    _sleep_once(monkeypatch)
    assert main.main(["--config", str(path), "run"]) == 130
    assert [request.url.path for request in requests] == [
        "/agent/v1/heartbeat",
        "/agent/v1/device-scan",
        "/agent/v1/heartbeat",
        "/agent/v1/device-scan",
    ]
