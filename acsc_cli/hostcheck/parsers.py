"""Parse allowlisted command output into the bounded host check schema."""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Any, Final

MAX_PACKAGES: Final = 20_000
MAX_SOCKETS: Final = 512
# Only these effective sshd settings are reported. Everything else is dropped.
SSHD_KEYS: Final = frozenset(
    {
        "permitrootlogin",
        "passwordauthentication",
        "permitemptypasswords",
        "kbdinteractiveauthentication",
        "challengeresponseauthentication",
        "pubkeyauthentication",
        "x11forwarding",
        "maxauthtries",
        "allowtcpforwarding",
        "allowagentforwarding",
        "permituserenvironment",
        "usepam",
        "ciphers",
        "macs",
        "kexalgorithms",
        "port",
    }
)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}")
_SSHD_VALUE = re.compile(r"[A-Za-z0-9@.,:+_ -]{1,1024}")


def os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines()[:200]:
        key, sep, raw = line.partition("=")
        if not sep or key not in {"ID", "VERSION_ID", "ID_LIKE"}:
            continue
        try:
            parts = shlex.split(raw)
        except ValueError:
            continue
        value = parts[0] if parts else ""
        if re.fullmatch(r"[A-Za-z0-9._ -]{1,64}", value):
            values[key.lower()] = value
    return values


def packages(manager: str, output: str, distro: dict[str, str]) -> dict[str, Any]:
    rows: dict[str, str] = {}
    truncated = False
    for line in output.splitlines():
        fields = line.split("\t")
        if manager == "dpkg":
            # OSV Debian and Ubuntu advisories are keyed by source package.
            if len(fields) != 5 or not fields[2].startswith("ii"):
                continue
            name = fields[3] or fields[0].split(":", 1)[0]
            version = fields[4] or fields[1]
        else:
            if len(fields) != 2:
                continue
            name, version = fields
            if version.startswith("0:"):
                version = version[2:]
        if not _NAME.fullmatch(name) or not re.fullmatch(r"[A-Za-z0-9.+~:^_-]{1,128}", version):
            continue
        if len(rows) >= MAX_PACKAGES:
            truncated = True
            break
        rows[name] = version
    return {
        "collected": True,
        "manager": manager,
        "distro": distro.get("id", ""),
        "distro_version": distro.get("version_id", ""),
        "items": [{"name": n, "version": v} for n, v in sorted(rows.items())],
        "truncated": truncated,
    }


def _endpoint(raw: str) -> tuple[str, int] | None:
    host, sep, port = raw.rpartition(":")
    if not sep or not port.isdigit():
        return None
    host = host.strip("[]").split("%", 1)[0]
    if host == "*":
        host = "0.0.0.0"  # noqa: S104 - parsing ss output, not binding
    try:
        address = str(ipaddress.ip_address(host))
    except ValueError:
        return None
    number = int(port)
    return (address, number) if 0 < number < 65536 else None


def sockets(output: str) -> dict[str, Any]:
    seen: set[tuple[str, str, int]] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in {"tcp", "udp"}:
            continue
        endpoint = _endpoint(fields[4])
        if endpoint is None:
            continue
        seen.add((fields[0], *endpoint))
        if len(seen) >= MAX_SOCKETS:
            break
    return {
        "collected": True,
        "listeners": [{"proto": p, "address": a, "port": n} for p, a, n in sorted(seen)],
    }


def sshd(output: str) -> dict[str, Any]:
    settings: dict[str, str] = {}
    for line in output.splitlines():
        key, _, value = line.strip().partition(" ")
        key = key.lower()
        if key in SSHD_KEYS and _SSHD_VALUE.fullmatch(value.strip()):
            settings[key] = value.strip().lower()
    return {"collected": bool(settings), "settings": settings}


def _nft(text: str) -> dict[str, Any]:
    policy = None
    rules = 0
    chain_is_input = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("chain "):
            chain_is_input = False
        if "hook input" in stripped:
            chain_is_input = True
            match = re.search(r"policy (accept|drop|reject)", stripped)
            if match and policy != "drop":
                policy = match.group(1)
        elif chain_is_input and stripped and not stripped.startswith(("chain ", "}", "type ")):
            rules += 1
    return {
        "backend": "nftables",
        "active": rules > 0 or policy == "drop",
        "input_policy": policy,
        "rule_count": min(rules, 100_000),
    }


def _ufw(text: str) -> dict[str, Any] | None:
    status = re.search(r"^Status:\s*(active|inactive)", text, re.MULTILINE)
    if status is None:
        return None
    default = re.search(r"^Default:\s*(allow|deny|reject) \(incoming\)", text, re.MULTILINE)
    rules = sum(
        1 for line in text.splitlines() if re.search(r"\b(ALLOW|DENY|REJECT|LIMIT)\b", line)
    )
    return {
        "backend": "ufw",
        "active": status.group(1) == "active",
        "input_policy": {"allow": "accept", "deny": "drop", "reject": "reject"}.get(
            default.group(1) if default else "", None
        ),
        "rule_count": min(rules, 100_000),
    }


def _iptables(text: str) -> dict[str, Any]:
    policy = None
    rules = 0
    for line in text.splitlines():
        if line.startswith("-P INPUT "):
            value = line.split()[-1].lower()
            policy = value if value in {"accept", "drop"} else None
        elif line.startswith("-A "):
            rules += 1
    return {
        "backend": "iptables",
        "active": rules > 0 or policy == "drop",
        "input_policy": policy,
        "rule_count": min(rules, 100_000),
    }


def firewall(*, nft: str | None, ufw: str | None, iptables: str | None) -> dict[str, Any]:
    """The strongest active backend wins; no rule text is reported."""
    candidates = []
    if ufw is not None and (parsed := _ufw(ufw)) is not None:
        candidates.append(parsed)
    if nft is not None:
        candidates.append(_nft(nft))
    if iptables is not None:
        candidates.append(_iptables(iptables))
    if not candidates:
        return {"collected": False}
    active = [c for c in candidates if c["active"]]
    chosen = active[0] if active else candidates[0]
    return {"collected": True, **chosen}
