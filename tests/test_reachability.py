"""Inbound reachability client. Loopback only; the dashboard API is mocked."""

import base64
import json
import socket
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from acsc_cli import agent, main
from acsc_cli.client import ClientError
from tests.test_host_checks import AGENT_TOKEN, ASSET, ENROLLMENT, ORG, Server, enrolled

NONCE = "r" * 43
ADDRESS = "203.0.113.7"


class Verifier:
    """Plays the dashboard API and the worker's inbound connection on loopback."""

    def __init__(self, identity, *, port=47850, sign=agent.REACHABILITY_KIND, connect=True):
        self.identity, self.port, self.sign, self.connect = identity, port, sign, connect
        self.check = str(uuid.uuid4())
        self.status = "pending"
        self.paths = []
        self.read = b""

    def __call__(self, request):
        self.paths.append((request.method, request.url.path))
        assert request.headers["Authorization"] == "Bearer " + AGENT_TOKEN
        if request.url.path == "/agent/v1/reachability/challenge":
            return httpx.Response(
                200,
                json={
                    "reachability_id": self.check,
                    "status": "pending",
                    "port": self.port,
                    "nonce": NONCE,
                    "observed_ip": ADDRESS,
                    "enrollment_id": ENROLLMENT,
                    "sign": self.sign,
                    "expires_at": "2026-10-19T10:02:00+00:00",
                },
            )
        if request.url.path == "/agent/v1/reachability/ready":
            assert json.loads(request.content) == {"reachability_id": self.check}
            self.status = "ready"
            if self.connect:
                with socket.create_connection(("127.0.0.1", self.port), timeout=2) as conn:
                    self.read = conn.recv(200)
                self.status = "succeeded" if self.verified() else "failed"
            return httpx.Response(202, json={"status": self.status})
        if request.url.path == f"/agent/v1/reachability/{self.check}":
            assert request.method == "GET"
            return httpx.Response(
                200,
                json={
                    "reachability_id": self.check,
                    "status": self.status,
                    "port": self.port,
                    "valid_until": "2026-10-26T10:00:00+00:00"
                    if self.status == "succeeded"
                    else None,
                    "failure_reason": None,
                },
            )
        return httpx.Response(404)

    def verified(self):
        kind, signature = self.read.decode().rstrip("\n").split(" ")
        message = agent.signed_document(
            agent.REACHABILITY_KIND,
            org_id=str(ORG),
            asset_id=str(ASSET),
            enrollment_id=ENROLLMENT,
            observed_ip=ADDRESS,
            challenge=NONCE,
            public_key=agent.public_key(self.identity.key()),
        )
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(agent.public_key(self.identity.key()))
        )
        key.verify(base64.b64decode(signature), message)
        return kind == agent.REACHABILITY_KIND and self.read.endswith(b"\n")


def run(identity, verifier, **kw):
    return agent.reachability(
        identity,
        transport=httpx.MockTransport(verifier),
        host="127.0.0.1",
        wait_s=kw.pop("wait_s", 2),
        poll_s=0.01,
        **kw,
    )


def test_serves_signed_line_on_server_chosen_port_and_closes():
    identity = enrolled(Server())
    verifier = Verifier(identity)
    result = run(identity, verifier)
    assert result["status"] == "succeeded" and result["port"] == 47850
    assert verifier.read.startswith(b"rakis-agent-reachability-v1 ")
    assert [p for _, p in verifier.paths][:2] == [
        "/agent/v1/reachability/challenge",
        "/agent/v1/reachability/ready",
    ]
    # The listener is closed afterwards.
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", 47850), timeout=0.5).close()


@pytest.mark.parametrize(
    "change",
    [{"port": 22}, {"port": 48000}, {"sign": "rakis-agent-attestation-v1"}],
)
def test_bad_challenge_is_refused_before_listening(change):
    identity = enrolled(Server())
    verifier = Verifier(identity, connect=False, **change)
    with pytest.raises(ClientError):
        run(identity, verifier)
    assert [p for _, p in verifier.paths] == ["/agent/v1/reachability/challenge"]


def test_timeout_reports_ready_without_success():
    identity = enrolled(Server())
    verifier = Verifier(identity, port=47851, connect=False)
    result = run(identity, verifier, wait_s=0.05)
    assert result["status"] == "ready"


def test_port_in_use_is_reported(monkeypatch):
    identity = enrolled(Server())
    blocker = socket.create_server(("127.0.0.1", 47852))
    try:
        with pytest.raises(ClientError) as caught:
            run(identity, Verifier(identity, port=47852, connect=False))
        assert "47852" in str(caught.value)
    finally:
        blocker.close()


def test_cli_remembers_only_after_success(tmp_path, monkeypatch, capsys):
    identity = enrolled(Server())
    config = tmp_path / "rakis" / "config.json"
    path = agent.default_path(config)
    agent.save_identity(path, identity)
    results = iter([{"status": "failed"}, {"status": "succeeded"}])
    monkeypatch.setattr(main.agent, "reachability", lambda _identity: next(results))
    args = ["--config", str(config), "reachability", "--remember"]
    assert main.main(args) == 4
    assert agent.load_identity(path).reachability_checks is False
    assert main.main(args) == 0
    assert agent.load_identity(path).reachability_checks is True
    assert AGENT_TOKEN not in capsys.readouterr().out


def test_background_tick_runs_reachability_only_when_opted_in(monkeypatch):
    identity = enrolled(Server())
    calls = []
    monkeypatch.setattr(main.agent, "attest", lambda i: "2026-11-18T00:00:00+00:00")
    monkeypatch.setattr(main.agent, "publish_host_checks", lambda i, r: {})
    monkeypatch.setattr(main, "_collect", lambda use_sudo: {})
    monkeypatch.setattr(main.agent, "reachability", lambda i: calls.append(i) or {})
    main._agent_tick(identity, float("-inf"), float("-inf"))
    assert calls == []
    opted = identity.model_copy(update={"reachability_checks": True})
    main._agent_tick(opted, float("-inf"), float("-inf"))
    assert calls == [opted]
