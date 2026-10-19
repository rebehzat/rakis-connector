"""Fixed read-only collection on the enrolled host.

Every command is a constant argv tuple in ``ALLOWLIST``. ``run`` accepts only an
allowlist key, never a command, argument, path or environment value, so a
server response cannot cause any other program to run. No shell is used, the
environment is minimal, output is capped and every call has a deadline.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from acsc_cli.hostcheck import parsers

MAX_OUTPUT: Final = 4 * 1024 * 1024
TIMEOUT_S: Final = 20
SAFE_ENV: Final = MappingProxyType(
    {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
)

# Read-only queries only. None of these change host state.
ALLOWLIST: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "dpkg": (
            "dpkg-query",
            "-W",
            "-f",
            "${Package}\\t${Version}\\t${db:Status-Abbrev}\\t${source:Package}\\t"
            "${source:Version}\\n",
        ),
        "rpm": ("rpm", "-qa", "--qf", "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n"),
        "sockets": ("ss", "-H", "-l", "-n", "-t", "-u"),
        "sshd": ("sshd", "-T"),
        "nft": ("nft", "list", "ruleset"),
        "ufw": ("ufw", "status", "verbose"),
        "iptables": ("iptables", "-S"),
    }
)
OS_RELEASE: Final = Path("/etc/os-release")

Runner = Callable[[tuple[str, ...]], str | None]


class CollectorError(ValueError):
    """A request outside the fixed allowlist."""


def _default_runner(argv: tuple[str, ...]) -> str | None:
    program = shutil.which(argv[0], path=SAFE_ENV["PATH"])
    if program is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed allowlisted argv, no shell
            (program, *argv[1:]),
            capture_output=True,
            timeout=TIMEOUT_S,
            check=False,
            env=dict(SAFE_ENV),
            stdin=subprocess.DEVNULL,
            cwd="/",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or len(completed.stdout) > MAX_OUTPUT:
        return None
    return completed.stdout.decode("utf-8", "replace")


def run(name: str, runner: Runner = _default_runner) -> str | None:
    """Run one allowlisted read-only query by key. Unknown keys are refused."""
    if not isinstance(name, str) or name not in ALLOWLIST:
        raise CollectorError("command_not_allowlisted")
    return runner(ALLOWLIST[name])


def _os_release(path: Path) -> str | None:
    try:
        if path.stat().st_size > 64 * 1024:
            return None
        return path.read_text("utf-8", "replace")
    except OSError:
        return None


def collect(runner: Runner = _default_runner, os_release: Path = OS_RELEASE) -> dict[str, Any]:
    """Build a host check report from the allowlisted queries only."""
    distro = parsers.os_release(_os_release(os_release) or "")
    packages: dict[str, Any] = {"collected": False}
    for manager in ("dpkg", "rpm"):
        output = run(manager, runner)
        if output is not None:
            packages = parsers.packages(manager, output, distro)
            break
    sockets_out = run("sockets", runner)
    sshd_out = run("sshd", runner)
    firewall = parsers.firewall(
        nft=run("nft", runner), ufw=run("ufw", runner), iptables=run("iptables", runner)
    )
    return {
        "schema": "rakis.host_checks.v0",
        "packages": packages,
        "sockets": parsers.sockets(sockets_out)
        if sockets_out is not None
        else {"collected": False},
        "sshd": parsers.sshd(sshd_out) if sshd_out is not None else {"collected": False},
        "firewall": firewall,
    }


def running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0
