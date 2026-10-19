"""Optional least-privilege path for the root-only read queries.

Connector-only (not vendored from the server). The connector runs as a normal
user, so ``sshd -T``, ``nft``, ``ufw`` and ``iptables`` usually report "not
collected". An owner can opt in by installing the sudoers drop-in printed by
``rakis sudoers-file``: it allows this user to run exactly these four argv
lines as root, nothing else. The connector never installs it.

``sudo -n`` never prompts: without the drop-in it fails and the query falls
back to the unprivileged attempt, exactly as before.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from acsc_cli.hostcheck import collector

SUDO: Final = "/usr/bin/sudo"
# Allowlist key -> absolute program path used in the sudoers drop-in.
ROOT_QUERIES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "sshd": "/usr/sbin/sshd",
        "nft": "/usr/sbin/nft",
        "ufw": "/usr/sbin/ufw",
        "iptables": "/usr/sbin/iptables",
    }
)
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
DROP_IN: Final = "/etc/sudoers.d/rakis-hostcheck"


def privileged_argv(name: str) -> tuple[str, ...]:
    """The exact command line granted in the drop-in for one allowlist key."""
    if name not in ROOT_QUERIES:
        raise collector.CollectorError("command_not_allowlisted")
    return (ROOT_QUERIES[name], *collector.ALLOWLIST[name][1:])


def sudoers_text(user: str) -> str:
    """The drop-in for ``user``. Printed for the owner to review and install."""
    if not USER_RE.fullmatch(user or ""):
        raise ValueError("invalid user name")
    commands = ", ".join(" ".join(privileged_argv(name)) for name in ROOT_QUERIES)
    return (
        "# Rakis connector read-only host checks (optional, installed by you).\n"
        f"# Install: sudo visudo -cf FILE && sudo install -m 0440 -o root -g root FILE {DROP_IN}\n"
        f"# Remove:  sudo rm {DROP_IN}\n"
        "# Grants exactly these read-only command lines as root, with no other arguments.\n"
        f"{user} ALL=(root) NOPASSWD: {commands}\n"
    )


def _sudo(argv: tuple[str, ...]) -> str | None:
    if shutil.which(SUDO) != SUDO:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, never prompts
            (SUDO, "-n", "--", *argv),
            capture_output=True,
            timeout=collector.TIMEOUT_S,
            check=False,
            env=dict(collector.SAFE_ENV),
            stdin=subprocess.DEVNULL,
            cwd="/",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or len(completed.stdout) > collector.MAX_OUTPUT:
        return None
    return completed.stdout.decode("utf-8", "replace")


def runner(base: collector.Runner = collector._default_runner) -> collector.Runner:
    """Try the granted root-only queries through ``sudo -n``, else run as before."""
    by_argv = {collector.ALLOWLIST[name]: name for name in ROOT_QUERIES}

    def run(argv: tuple[str, ...]) -> str | None:
        name = by_argv.get(argv)
        if name is not None:
            output = _sudo(privileged_argv(name))
            if output is not None:
                return output
        return base(argv)

    return run
