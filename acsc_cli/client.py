from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from typing import Any

import httpx

from acsc_cli import __version__
from acsc_cli.config import Config


class ClientError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _connection(value: Any) -> dict[str, Any]:
    try:
        if not isinstance(value, dict) or value.get("connected") is not True:
            raise ValueError()
        if not isinstance(value.get("asset_id"), str):
            raise ValueError()
        uuid.UUID(value["asset_id"])
        if not isinstance(value.get("name"), str) or len(value["name"]) > 500:
            raise ValueError()
        for key in ("server_time", "last_seen_at"):
            timestamp = value.get(key)
            if key == "last_seen_at" and timestamp is None:
                continue
            if not isinstance(timestamp, str) or len(timestamp) > 64:
                raise ValueError()
            if datetime.fromisoformat(timestamp).tzinfo is None:
                raise ValueError()
    except (ValueError, TypeError):
        raise ClientError(4, "Invalid connection response") from None
    return {key: value.get(key) for key in ("connected", "asset_id", "name", "last_seen_at")}


class Client:
    """Connection and opt-in local observations only. Never polls for commands."""

    def __init__(self, config: Config, *, transport: httpx.BaseTransport | None = None):
        self.http = httpx.Client(
            base_url=config.api_url,
            headers={"Authorization": "Bearer " + config.token.get_secret_value()},
            follow_redirects=False,
            trust_env=False,
            timeout=20,
            transport=transport,
        )

    def close(self) -> None:
        self.http.close()

    def _request(
        self, method: str, path: str, *, observation: bool = False, **kwargs: Any
    ) -> dict[str, Any]:
        try:
            with self.http.stream(method, path, **kwargs) as response:
                if response.status_code in {401, 403}:
                    raise ClientError(3, "Connection token expired, revoked, or rejected")
                if not 200 <= response.status_code < 300:
                    raise ClientError(
                        4, f"Connection request refused (HTTP {response.status_code})"
                    )
                raw = bytearray()
                for block in response.iter_bytes():
                    raw.extend(block)
                    if len(raw) > 16384:
                        raise ClientError(4, "Connection response exceeds limit")
                value = json.loads(raw)
                if observation:
                    return _inspection(value)
                result = _connection(value)
                result["name"] = result["name"].replace(
                    self.http.headers["Authorization"][7:], "[redacted]"
                )
                return result
        except (httpx.HTTPError, ValueError):
            raise ClientError(4, "Dashboard unavailable or invalid response") from None

    def heartbeat(self) -> dict[str, Any]:
        return self._request("POST", "/agent/v1/heartbeat", json={"agent_version": __version__})

    def configuration(
        self, observations: dict[str, Any], *, ai: bool = False, retry_ai: bool = False
    ) -> dict[str, Any]:
        if retry_ai and not ai:
            raise ClientError(2, "Retrying AI review requires explicit AI opt-in")
        return self._request(
            "POST",
            "/agent/v1/configuration",
            observation=True,
            json={
                "agent_version": __version__,
                **observations,
                **({"ai": True} if ai else {}),
                **({"retry_ai": True} if retry_ai else {}),
            },
        )

    def status(self) -> dict[str, Any]:
        return self._request("GET", "/agent/v1/connection")


def _inspection(value: Any) -> dict[str, Any]:
    try:
        if not isinstance(value, dict) or value.get("status") != "succeeded":
            raise ValueError()
        if not isinstance(value.get("job_id"), str):
            raise ValueError()
        uuid.UUID(value["job_id"])
        if type(value.get("changed")) is not bool:
            raise ValueError()
        if type(value.get("complete")) is not bool:
            raise ValueError()
        for key in ("findings_count", "files_inspected", "skipped_files"):
            if type(value.get(key)) is not int or not 0 <= value[key] <= 100000:
                raise ValueError()
    except (ValueError, TypeError):
        raise ClientError(4, "Invalid configuration observation response") from None
    result = {
        key: value[key]
        for key in (
            "job_id",
            "status",
            "changed",
            "complete",
            "findings_count",
            "files_inspected",
            "skipped_files",
        )
    }
    if "ai_triage_status" in value:
        if not isinstance(value["ai_triage_status"], str) or value["ai_triage_status"] not in {
            "not_requested",
            "queued",
            "running",
            "succeeded",
            "incomplete",
        }:
            raise ClientError(4, "Invalid AI configuration review response")
        result["ai_triage_status"] = value["ai_triage_status"]
        error = value.get("ai_triage_error")
        safe_errors = {
            "llm_error",
            "llm_not_configured",
            "llm_invalid_base_url",
            "llm_use_openrouter_provider",
            "llm_invalid_openrouter_url",
            "llm_invalid_openrouter_model",
            "llm_reasoning_openrouter_only",
            "llm_mock_in_production",
            "llm_response_too_large",
            "llm_bad_response",
            "llm_transport_error",
            "llm_input_limit_exceeded",
            "llm_invalid_input",
            "configuration_ai_authority_lost",
            "configuration_ai_input_limit",
            "configuration_ai_no_observations",
            "configuration_ai_budget_exhausted",
            "configuration_ai_invalid_output",
            "configuration_ai_lease_lost",
            "worker_lease_expired",
        }
        result["ai_triage_error"] = (
            None
            if error is None
            else error
            if isinstance(error, str)
            and (error in safe_errors or re.fullmatch(r"llm_http_[1-5]\d{2}", error))
            else "ai_review_unavailable"
        )
    return result
