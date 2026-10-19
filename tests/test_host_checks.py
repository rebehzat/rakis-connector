"""Opt-in enrollment, attestation and read-only host checks. No live calls."""

import base64
import json
import os
import stat
import uuid
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import SecretStr

from acsc_cli import __version__, agent, main
from acsc_cli.client import ClientError
from acsc_cli.hostcheck import collector

COLLECT = collector.collect

ORG = uuid.UUID("22222222-2222-4222-8222-222222222222")
ASSET = uuid.UUID("11111111-1111-4111-8111-111111111111")
ENROLLMENT = "33333333-3333-4333-8333-333333333333"
JOB = "44444444-4444-4444-8444-444444444444"
ENROLL_TOKEN = "acsc_e_" + "c" * 12 + "_" + "d" * 43
AGENT_TOKEN = "acsc_a_" + "a" * 12 + "_" + "b" * 43
CHALLENGE = "e" * 43
API = "https://api.example.test"

OUTPUTS = {
    "dpkg-query": "openssh-server\t1:9.6p1-3ubuntu13\tii \topenssh\t1:9.6p1-3ubuntu13\n",
    "ss": "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n",
    "sshd": "permitrootlogin yes\npasswordauthentication no\nhostkey /etc/ssh/k\n",
}


def fake_runner(calls):
    def run(argv):
        assert argv in collector.ALLOWLIST.values()
        calls.append(argv)
        return OUTPUTS.get(argv[0])

    return run


def os_release(tmp_path):
    path = tmp_path / "os-release"
    path.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    return path


class Server:
    """In-process stand-in for the dashboard API that verifies signatures."""

    def __init__(self, observed_ip="203.0.113.7"):
        self.observed_ip = observed_ip
        self.public_key = None
        self.requests = []

    def verify(self, kind, body):
        message = agent.signed_document(
            kind,
            org_id=str(ORG),
            asset_id=str(ASSET),
            enrollment_id=ENROLLMENT,
            observed_ip=self.observed_ip,
            challenge=body["challenge"],
            public_key=self.public_key,
        )
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key))
        key.verify(base64.b64decode(body["signature"]), message)

    def __call__(self, request):
        body = json.loads(request.content or b"{}")
        self.requests.append((request.url.path, request.headers["Authorization"], body))
        path = request.url.path
        challenge = {
            "enrollment_id": ENROLLMENT,
            "challenge": CHALLENGE,
            "observed_ip": self.observed_ip,
            "challenge_expires_at": "2026-10-19T10:00:00+00:00",
        }
        if path == "/agent/v1/enrollment/start":
            assert request.headers["Authorization"] == "Bearer " + ENROLL_TOKEN
            assert set(body) == {"org_id", "asset_id", "public_key", "agent_version"}
            self.public_key = body["public_key"]
            return httpx.Response(200, json={**challenge, "sign": agent.ENROLLMENT_KIND})
        if path == "/agent/v1/enrollment/complete":
            assert request.headers["Authorization"] == "Bearer " + ENROLL_TOKEN
            self.verify(agent.ENROLLMENT_KIND, body)
            return httpx.Response(
                200,
                json={
                    "agent_token": AGENT_TOKEN,
                    "scopes": ["agent:heartbeat", "agent:attest", "agent:host_check"],
                    "asset_id": str(ASSET),
                    "reverify_due_at": "2026-11-18T10:00:00+00:00",
                },
            )
        assert request.headers["Authorization"] == "Bearer " + AGENT_TOKEN
        if path == "/agent/v1/attestation/challenge":
            return httpx.Response(200, json={**challenge, "sign": agent.ATTESTATION_KIND})
        if path == "/agent/v1/attestation":
            self.verify(agent.ATTESTATION_KIND, body)
            return httpx.Response(
                200,
                json={"enrollment_id": ENROLLMENT, "reverify_due_at": "2026-11-18T10:00:00+00:00"},
            )
        if path == "/agent/v1/host-checks":
            return httpx.Response(
                200,
                json={
                    "job_id": JOB,
                    "status": "succeeded",
                    "advisory_status": "pending",
                    "findings_count": 1,
                    "changed": True,
                },
            )
        return httpx.Response(404)


def enrolled(server):
    return agent.enroll(
        api_url=API,
        org_id=ORG,
        asset_id=ASSET,
        enrollment_token=SecretStr(ENROLL_TOKEN),
        transport=httpx.MockTransport(server),
    )


def test_allowlist_is_fixed_and_unknown_queries_are_refused():
    with pytest.raises(TypeError):
        collector.ALLOWLIST["extra"] = ("id",)  # type: ignore[index]
    for name in ("id", "sh", "dpkg-query", "../dpkg", "", None):
        with pytest.raises(collector.CollectorError):
            collector.run(name, lambda argv: pytest.fail("must not run"))
    assert {argv[0] for argv in collector.ALLOWLIST.values()} == {
        "dpkg-query",
        "rpm",
        "ss",
        "sshd",
        "nft",
        "ufw",
        "iptables",
    }


def test_collect_builds_v0_report_from_allowlisted_queries_only(tmp_path):
    calls = []
    report = collector.collect(fake_runner(calls), os_release(tmp_path))
    assert report["schema"] == "rakis.host_checks.v0"
    assert report["packages"]["collected"] is True
    assert report["packages"]["manager"] == "dpkg"
    assert report["packages"]["distro"] == "ubuntu"
    assert report["sockets"]["listeners"] == [{"proto": "tcp", "address": "0.0.0.0", "port": 22}]
    # Only allowlisted sshd keys leave the host.
    assert report["sshd"]["settings"] == {
        "permitrootlogin": "yes",
        "passwordauthentication": "no",
    }
    # Root-only queries that fail as a normal user are reported as not collected.
    assert report["firewall"]["collected"] is False
    assert all(argv in collector.ALLOWLIST.values() for argv in calls)


def test_default_runner_uses_no_shell_and_minimal_environment(monkeypatch):
    seen = {}

    def fake_run(args, **kwargs):
        seen.update(kwargs, args=args)
        return collector.subprocess.CompletedProcess(args, 0, b"ok", b"")

    monkeypatch.setattr(collector.shutil, "which", lambda name, path: "/usr/bin/" + name)
    monkeypatch.setattr(collector.subprocess, "run", fake_run)
    assert collector.run("sockets") == "ok"
    assert seen["args"] == ("/usr/bin/ss", "-H", "-l", "-n", "-t", "-u")
    assert "shell" not in seen and seen["env"] == dict(collector.SAFE_ENV)
    assert seen["stdin"] is collector.subprocess.DEVNULL and seen["timeout"] == 20


def test_enrollment_signs_server_challenge_and_attestation_reproves(tmp_path):
    server = Server()
    identity = enrolled(server)
    assert identity.token.get_secret_value() == AGENT_TOKEN
    assert str(identity.enrollment_id) == ENROLLMENT
    start = server.requests[0][2]
    assert start["agent_version"] == __version__
    assert agent.public_key(identity.key()) == start["public_key"]
    due = agent.attest(identity, transport=httpx.MockTransport(server))
    assert due.startswith("2026-11-18")
    assert [path for path, _, _ in server.requests] == [
        "/agent/v1/enrollment/start",
        "/agent/v1/enrollment/complete",
        "/agent/v1/attestation/challenge",
        "/agent/v1/attestation",
    ]


@pytest.mark.parametrize(
    "start",
    [
        {"sign": "something-else"},
        {"challenge": "short"},
        {"observed_ip": None},
        {"enrollment_id": "not-a-uuid"},
    ],
)
def test_malformed_challenge_is_refused_before_signing(start):
    def handler(request):
        if request.url.path.endswith("/start"):
            body = {
                "enrollment_id": ENROLLMENT,
                "challenge": CHALLENGE,
                "observed_ip": "203.0.113.7",
                "sign": agent.ENROLLMENT_KIND,
                **start,
            }
            return httpx.Response(200, json=body)
        pytest.fail("must not sign a malformed challenge")

    with pytest.raises(ClientError):
        agent.enroll(
            api_url=API,
            org_id=ORG,
            asset_id=ASSET,
            enrollment_token=SecretStr(ENROLL_TOKEN),
            transport=httpx.MockTransport(handler),
        )


def test_attestation_for_another_enrollment_is_refused():
    server = Server()
    identity = enrolled(server)

    def other(request):
        return httpx.Response(
            200,
            json={
                "enrollment_id": str(uuid.uuid4()),
                "challenge": CHALLENGE,
                "observed_ip": "203.0.113.7",
                "sign": agent.ATTESTATION_KIND,
            },
        )

    with pytest.raises(ClientError):
        agent.attest(identity, transport=httpx.MockTransport(other))


@pytest.mark.parametrize("api_url", ["http://api.example.test", "https://u:p@api.example.test"])
def test_enrollment_requires_https_origin_and_valid_token(api_url):
    with pytest.raises(ValueError):
        agent.enroll(
            api_url=api_url,
            org_id=ORG,
            asset_id=ASSET,
            enrollment_token=SecretStr(ENROLL_TOKEN),
            transport=httpx.MockTransport(lambda r: pytest.fail("no network")),
        )
    with pytest.raises(ClientError):
        agent.enroll(
            api_url=API,
            org_id=ORG,
            asset_id=ASSET,
            enrollment_token=SecretStr(AGENT_TOKEN),
            transport=httpx.MockTransport(lambda r: pytest.fail("no network")),
        )


def test_redirects_and_errors_do_not_follow_or_echo_secrets():
    server = Server()
    identity = enrolled(server)

    def redirect(request):
        return httpx.Response(307, headers={"Location": "https://evil.example/"})

    with pytest.raises(ClientError) as caught:
        agent.publish_host_checks(identity, {}, transport=httpx.MockTransport(redirect))
    assert AGENT_TOKEN not in str(caught.value)

    def denied(request):
        return httpx.Response(409, json={"detail": AGENT_TOKEN})

    with pytest.raises(ClientError) as caught:
        agent.publish_host_checks(identity, {}, transport=httpx.MockTransport(denied))
    assert "re-enroll" in str(caught.value) and AGENT_TOKEN not in str(caught.value)


def test_host_checks_post_report_with_agent_token(tmp_path):
    server = Server()
    identity = enrolled(server)
    collected = collector.collect(fake_runner([]), os_release(tmp_path))
    result = agent.publish_host_checks(identity, collected, transport=httpx.MockTransport(server))
    assert result == {
        "job_id": JOB,
        "changed": True,
        "findings_count": 1,
        "advisory_status": "pending",
    }
    path, auth, body = server.requests[-1]
    assert path == "/agent/v1/host-checks" and auth == "Bearer " + AGENT_TOKEN
    assert body["agent_version"] == __version__ and body["schema"] == "rakis.host_checks.v0"
    assert set(body) == {"agent_version", "schema", "packages", "sockets", "sshd", "firewall"}


def test_identity_file_is_private_and_rejects_loose_permissions(tmp_path):
    identity = enrolled(Server())
    path = tmp_path / "rakis" / "agent.json"
    agent.save_identity(path, identity)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    loaded = agent.load_identity(path)
    assert loaded.token.get_secret_value() == AGENT_TOKEN
    assert agent.public_key(loaded.key()) == agent.public_key(identity.key())
    assert AGENT_TOKEN not in repr(loaded) and loaded.private_key.get_secret_value() not in repr(
        loaded
    )
    os.chmod(path, 0o644)
    with pytest.raises(ValueError):
        agent.load_identity(path)
    os.chmod(path, 0o600)
    link = tmp_path / "rakis" / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        agent.load_identity(link)


def test_cli_enroll_attest_and_host_checks(tmp_path, monkeypatch, capsys):
    server = Server()
    transport = httpx.MockTransport(server)
    real_http = agent._http
    monkeypatch.setattr(agent, "_http", lambda url, bearer, _t: real_http(url, bearer, transport))
    monkeypatch.setattr(
        collector, "_default_runner", lambda argv: pytest.fail("use the patched collect")
    )
    monkeypatch.setattr(
        main.collector, "collect", lambda: COLLECT(fake_runner([]), os_release(tmp_path))
    )
    prompts = []
    monkeypatch.setattr(
        main.getpass, "getpass", lambda prompt: prompts.append(prompt) or ENROLL_TOKEN
    )
    config = tmp_path / "rakis" / "config.json"
    args = ["--config", str(config)]
    assert (
        main.main(
            [*args, "enroll", "--api-url", API, "--org-id", str(ORG), "--asset-id", str(ASSET)]
        )
        == 0
    )
    assert prompts == ["Agent enrollment token: "]
    assert main.main([*args, "attest"]) == 0
    assert main.main([*args, "host-checks"]) == 0
    out = capsys.readouterr().out
    assert AGENT_TOKEN not in out and ENROLL_TOKEN not in out
    lines = [json.loads(line) for line in out.splitlines()]
    assert lines[0] == {"enrolled": True, "asset_id": str(ASSET)}
    assert lines[1]["attested"] is True
    assert lines[2]["job_id"] == JOB
    assert stat.S_IMODE((config.parent / "agent.json").stat().st_mode) == 0o600


def test_cli_dry_run_sends_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(agent, "_http", lambda *a: pytest.fail("dry run must not send"))
    monkeypatch.setattr(
        main.collector, "collect", lambda: COLLECT(fake_runner([]), os_release(tmp_path))
    )
    assert main.main(["--config", str(tmp_path / "c.json"), "host-checks", "--dry-run"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "rakis.host_checks.v0"


def test_agent_tick_runs_periodically_and_survives_errors(monkeypatch, capsys):
    identity = enrolled(Server())
    calls = []

    def attest(_identity):
        calls.append("attest")
        raise ClientError(4, "Dashboard unavailable or invalid response")

    def publish(_identity, report):
        calls.append("checks")
        return {"job_id": JOB}

    monkeypatch.setattr(main.agent, "attest", attest)
    monkeypatch.setattr(main.agent, "publish_host_checks", publish)
    monkeypatch.setattr(main.collector, "collect", lambda: {})
    clock = [1000.0]
    monkeypatch.setattr(main.time, "monotonic", lambda: clock[0])
    checks, attested = main._agent_tick(identity, float("-inf"), float("-inf"))
    assert calls == ["attest", "checks"]
    checks, attested = main._agent_tick(identity, checks, attested)
    assert calls == ["attest", "checks"]
    clock[0] += main.HOST_CHECK_EVERY_S
    main._agent_tick(identity, checks, attested)
    assert calls == ["attest", "checks", "checks"]
    assert "unavailable" in capsys.readouterr().err


LOCAL_IMPORT = "from acsc_cli.hostcheck import"
SERVER_IMPORT = "from acsc_hostcheck import"
PIN = Path(__file__).resolve().parent / "fixtures" / "hostcheck_upstream.json"


def server_form(name: str) -> bytes:
    """The vendored file as it reads in the server repository."""
    text = (Path(agent.__file__).parent / "hostcheck" / name).read_text()
    return text.replace(LOCAL_IMPORT, SERVER_IMPORT).encode()


def test_vendored_collector_matches_pinned_server_hashes():
    """Runs in every connector CI job: any local edit to the vendored collector
    fails unless the server copy changes too and this pin is updated with it.
    The server repository pins the same hashes (backend/common/acsc_hostcheck)."""
    import hashlib

    pin = json.loads(PIN.read_text())
    assert set(pin["sha256"]) == {"collector.py", "parsers.py"}
    for name, digest in pin["sha256"].items():
        assert hashlib.sha256(server_form(name)).hexdigest() == digest, (
            f"acsc_cli/hostcheck/{name} drifted from {pin['repository']}@{pin['commit'][:7]}; "
            "change both copies together and update both pins"
        )
    # Only the import path may differ from the server copy.
    for name in ("collector.py", "parsers.py"):
        local = (Path(agent.__file__).parent / "hostcheck" / name).read_text()
        assert SERVER_IMPORT not in local


def test_vendored_collector_matches_server_copy():
    # Next to the server checkout (acsc-AI/.dependencies/connector) or explicit.
    candidates = [
        os.environ.get("RAKIS_SERVER_SOURCE", ""),
        str(Path(__file__).resolve().parents[3]),
    ]
    roots = [
        Path(c) for c in candidates if c and (Path(c) / "backend/common/acsc_hostcheck").is_dir()
    ]
    if not roots:
        pytest.skip("server source not available; the pinned hash test still runs")
    server = roots[0] / "backend/common/acsc_hostcheck"
    for name in ("collector.py", "parsers.py"):
        assert server_form(name) == (server / name).read_bytes()
