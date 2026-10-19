"""Opt-in agent enrollment, attestation and read-only host checks.

Enrollment proves that this server controls its own public address: the
connector generates an Ed25519 key here, the dashboard sees the request come
from the server address, and the connector signs a one-time challenge. The
private key and the released agent token stay in a private file on this server.

The connector only sends. The server never sends commands, and nothing in a
response is executed or used to choose what to collect.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, SecretStr, field_validator, model_validator

from acsc_cli import __version__
from acsc_cli.client import ClientError

AGENT_TOKEN = re.compile(r"^acsc_a_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$")
ENROLLMENT_TOKEN = re.compile(r"^acsc_e_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$")
CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")
ENROLLMENT_KIND = "rakis-agent-enrollment-v1"
ATTESTATION_KIND = "rakis-agent-attestation-v1"
MAX_RESPONSE = 16384


class AgentIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_url: str
    org_id: uuid.UUID
    asset_id: uuid.UUID
    enrollment_id: uuid.UUID
    token: SecretStr
    private_key: SecretStr
    allow_local_http: bool = False
    # Opt in: use the sudoers drop-in for root-only read queries (see README).
    sudo_queries: bool = False

    @field_validator("token")
    @classmethod
    def valid_token(cls, value: SecretStr) -> SecretStr:
        if not AGENT_TOKEN.fullmatch(value.get_secret_value()):
            raise ValueError("invalid agent token")
        return value

    @field_validator("private_key")
    @classmethod
    def valid_key(cls, value: SecretStr) -> SecretStr:
        raw = base64.b64decode(value.get_secret_value(), validate=True)
        if len(raw) != 32:
            raise ValueError("invalid agent key")
        return value

    @model_validator(mode="after")
    def valid_origin(self) -> AgentIdentity:
        self.api_url = check_origin(self.api_url, self.allow_local_http)
        return self

    def key(self) -> Ed25519PrivateKey:
        raw = base64.b64decode(self.private_key.get_secret_value(), validate=True)
        return Ed25519PrivateKey.from_private_bytes(raw)


def check_origin(api_url: str, allow_local_http: bool) -> str:
    p = urlsplit(api_url)
    if (
        not p.hostname
        or p.username
        or p.password
        or p.query
        or p.fragment
        or p.path not in {"", "/"}
        or not (
            p.scheme == "https"
            or (
                allow_local_http
                and p.scheme == "http"
                and p.hostname in {"127.0.0.1", "localhost", "::1"}
            )
        )
    ):
        raise ValueError("HTTPS API origin required")
    _ = p.port
    return api_url.rstrip("/")


def public_key(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def signed_document(
    kind: str,
    *,
    org_id: str,
    asset_id: str,
    enrollment_id: str,
    observed_ip: str,
    challenge: str,
    public_key: str,
) -> bytes:
    """Canonical bytes, identical to the server's acsc_authz.agent_enrollment."""
    document = {
        "kind": kind,
        "org_id": org_id,
        "asset_id": asset_id,
        "enrollment_id": enrollment_id,
        "observed_ip": observed_ip,
        "challenge": challenge,
        "public_key": public_key,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def sign(key: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(key.sign(message)).decode()


def _http(api_url: str, bearer: str, transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(
        base_url=api_url,
        headers={"Authorization": "Bearer " + bearer},
        follow_redirects=False,
        trust_env=False,
        timeout=30,
        transport=transport,
    )


def _post(http: httpx.Client, path: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        with http.stream("POST", path, json=body) as response:
            if response.status_code in {401, 403}:
                raise ClientError(3, "Agent credential rejected or not allowed for this action")
            if response.status_code == 409:
                raise ClientError(4, "Agent proof is not current; re-enroll from the dashboard")
            if response.status_code == 429:
                raise ClientError(4, "Too many requests; try again later")
            if not 200 <= response.status_code < 300:
                raise ClientError(4, f"Request refused (HTTP {response.status_code})")
            raw = bytearray()
            for block in response.iter_bytes():
                raw.extend(block)
                if len(raw) > MAX_RESPONSE:
                    raise ClientError(4, "Response exceeds limit")
            value = json.loads(raw)
    except (httpx.HTTPError, ValueError):
        raise ClientError(4, "Dashboard unavailable or invalid response") from None
    if not isinstance(value, dict):
        raise ClientError(4, "Invalid response")
    return value


def _challenge(value: dict[str, Any], kind: str, enrollment_id: str | None) -> tuple[str, str, str]:
    try:
        challenge = value["challenge"]
        observed = value["observed_ip"]
        enrollment = str(uuid.UUID(value["enrollment_id"]))
        if value.get("sign") != kind or not CHALLENGE.fullmatch(challenge):
            raise ValueError
        if not isinstance(observed, str) or len(observed) > 45:
            raise ValueError
        if enrollment_id is not None and enrollment != enrollment_id:
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ClientError(4, "Invalid challenge response") from None
    return enrollment, challenge, observed


def enroll(
    *,
    api_url: str,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    enrollment_token: SecretStr,
    allow_local_http: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> AgentIdentity:
    """Generate a host key, prove the server address and receive the agent token."""
    api_url = check_origin(api_url, allow_local_http)
    secret = enrollment_token.get_secret_value()
    if not ENROLLMENT_TOKEN.fullmatch(secret):
        raise ClientError(2, "Invalid enrollment token")
    key = Ed25519PrivateKey.generate()
    pub = public_key(key)
    with _http(api_url, secret, transport) as http:
        started = _post(
            http,
            "/agent/v1/enrollment/start",
            {
                "org_id": str(org_id),
                "asset_id": str(asset_id),
                "public_key": pub,
                "agent_version": __version__,
            },
        )
        enrollment, challenge, observed = _challenge(started, ENROLLMENT_KIND, None)
        message = signed_document(
            ENROLLMENT_KIND,
            org_id=str(org_id),
            asset_id=str(asset_id),
            enrollment_id=enrollment,
            observed_ip=observed,
            challenge=challenge,
            public_key=pub,
        )
        done = _post(
            http,
            "/agent/v1/enrollment/complete",
            {
                "org_id": str(org_id),
                "asset_id": str(asset_id),
                "enrollment_id": enrollment,
                "challenge": challenge,
                "signature": sign(key, message),
            },
        )
    token = done.get("agent_token")
    if not isinstance(token, str) or done.get("asset_id") != str(asset_id):
        raise ClientError(4, "Invalid enrollment response")
    raw_key = key.private_bytes_raw()
    return AgentIdentity(
        api_url=api_url,
        org_id=org_id,
        asset_id=asset_id,
        enrollment_id=uuid.UUID(enrollment),
        token=SecretStr(token),
        private_key=SecretStr(base64.b64encode(raw_key).decode()),
        allow_local_http=allow_local_http,
    )


def attest(identity: AgentIdentity, *, transport: httpx.BaseTransport | None = None) -> str:
    """Re-prove the address with the enrolled key. Returns the new due time."""
    key = identity.key()
    with _http(identity.api_url, identity.token.get_secret_value(), transport) as http:
        issued = _post(http, "/agent/v1/attestation/challenge", {})
        enrollment, challenge, observed = _challenge(
            issued, ATTESTATION_KIND, str(identity.enrollment_id)
        )
        message = signed_document(
            ATTESTATION_KIND,
            org_id=str(identity.org_id),
            asset_id=str(identity.asset_id),
            enrollment_id=enrollment,
            observed_ip=observed,
            challenge=challenge,
            public_key=public_key(key),
        )
        done = _post(
            http,
            "/agent/v1/attestation",
            {"challenge": challenge, "signature": sign(key, message)},
        )
    due = done.get("reverify_due_at")
    if not isinstance(due, str) or len(due) > 64:
        raise ClientError(4, "Invalid attestation response")
    return due


def report(collected: dict[str, Any]) -> dict[str, Any]:
    return {"agent_version": __version__, **collected}


def publish_host_checks(
    identity: AgentIdentity,
    collected: dict[str, Any],
    *,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    with _http(identity.api_url, identity.token.get_secret_value(), transport) as http:
        value = _post(http, "/agent/v1/host-checks", report(collected))
    keys = ("job_id", "changed", "findings_count", "advisory_status")
    try:
        uuid.UUID(value["job_id"])
        if type(value.get("changed")) is not bool or type(value.get("findings_count")) is not int:
            raise ValueError
        status = value.get("advisory_status")
        if status is not None and (not isinstance(status, str) or len(status) > 32):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ClientError(4, "Invalid host check response") from None
    return {key: value.get(key) for key in keys}


def default_path(config_path: Path) -> Path:
    return config_path.with_name("agent.json")


def load_identity(path: Path) -> AgentIdentity:
    if os.name == "nt":
        raise ValueError("agent enrollment requires Linux")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > 16384
        ):
            raise ValueError("private agent file required")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(16385)
    finally:
        if fd != -1:
            os.close(fd)
    if len(raw) > 16384:
        raise ValueError("agent file too large")
    return AgentIdentity.model_validate_json(raw)


def save_identity(path: Path, identity: AgentIdentity) -> None:
    if os.name == "nt":
        raise ValueError("agent enrollment requires Linux")
    directory = path.parent
    if directory.is_symlink():
        raise ValueError("agent file parent cannot be a link")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("agent directory must be private (0700)")
    if path.is_symlink():
        raise ValueError("agent file cannot be a link")
    fd, name = tempfile.mkstemp(prefix=".rakis-agent-", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(
                {
                    "api_url": identity.api_url,
                    "org_id": str(identity.org_id),
                    "asset_id": str(identity.asset_id),
                    "enrollment_id": str(identity.enrollment_id),
                    "token": identity.token.get_secret_value(),
                    "private_key": identity.private_key.get_secret_value(),
                    "allow_local_http": identity.allow_local_http,
                    "sudo_queries": identity.sudo_queries,
                },
                stream,
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
