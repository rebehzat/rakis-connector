"""Manage only the current user's passive connector, never server workloads."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from acsc_cli.config import load

UNIT = "rakis-connector.service"


class BackgroundError(ValueError):
    pass


def _command(name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(name)
    if executable is None:
        raise BackgroundError("Linux systemd and loginctl are required for background operation")
    try:
        return subprocess.run(  # noqa: S603
            [executable, *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackgroundError("The user service manager is unavailable") from exc


def _systemctl(*arguments: str) -> subprocess.CompletedProcess[str]:
    return _command("systemctl", "--user", *arguments)


def _quote(value: str) -> str:
    if any(ord(char) < 32 for char in value):
        raise BackgroundError("Service paths cannot contain control characters")
    return (
        '"'
        + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
        + '"'
    )


def _unit_path() -> Path:
    return (
        Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        / "systemd"
        / "user"
        / UNIT
    )


def _linger() -> bool:
    result = _command("loginctl", "show-user", str(os.getuid()), "--property=Linger", "--value")
    return result.returncode == 0 and result.stdout.strip() == "yes"


def _owned_unit(target: Path) -> None:
    existing = target.lstat()
    if (
        not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != os.getuid()
        or existing.st_nlink != 1
        or existing.st_size > 16384
    ):
        raise BackgroundError("The connector service file must be an owned regular file")
    if not target.read_text().startswith("# Managed by the Rakis passive connector\n"):
        raise BackgroundError("An unrelated connector service file exists; refusing to change it")


def stop_if_installed(config: Path) -> None:
    """Disconnect must not leave a background process holding the saved credential."""
    if sys.platform != "linux":
        return
    target = _unit_path()
    if target.exists() or target.is_symlink():
        _owned_unit(target)
        # A different --config may belong to a separate foreground connection.
        # Stopping our sole user service is safe and avoids leaving any old token alive.
        manage("stop", config, 60)


def manage(action: str, config: Path, interval: int) -> dict[str, object]:
    if sys.platform != "linux" or os.getuid() == 0:
        raise BackgroundError(
            "Run the background connector as your normal Linux user, without sudo"
        )
    if action == "status":
        result = _systemctl("show", UNIT, "--property=ActiveState", "--value")
        return {
            "background": result.stdout.strip() if result.returncode == 0 else "unavailable",
            "survives_logout": _linger(),
        }
    if action == "stop":
        target = _unit_path()
        if not target.exists() and not target.is_symlink():
            return {"background": "stopped", "token_retained": True}
        _owned_unit(target)
        if _systemctl("disable", "--now", UNIT).returncode:
            raise BackgroundError("Could not stop the connector user service")
        return {"background": "stopped", "token_retained": True}
    config = config.absolute()
    executable = str(Path(sys.executable).absolute())
    quoted_config = _quote(str(config))
    quoted_executable = _quote(executable)
    load(config, use_environment=False)
    if not _linger():
        enabled = _command("loginctl", "enable-linger", str(os.getuid()))
        if enabled.returncode or not _linger():
            raise BackgroundError(
                "Logout persistence requires user lingering. This host denied enabling it. "
                "Ask its administrator to enable lingering for your account; then retry. "
                "The connector itself runs without root."
            )
    target = _unit_path()
    directory = target.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = directory.stat()
    if directory.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise BackgroundError(
            "The user service directory must be owned by you and not writable by others"
        )
    if target.exists() or target.is_symlink():
        _owned_unit(target)
    unit = (
        "# Managed by the Rakis passive connector\n[Unit]\nDescription=Rakis server connection\n"
        "[Service]\nType=simple\n"
        f"ExecStart={quoted_executable} -m acsc_cli --config {quoted_config} "
        f"run --interval {interval}\n"
        "Restart=on-failure\nRestartSec=30\nRestartPreventExitStatus=2 3\n"
        "UMask=0077\nNoNewPrivileges=yes\n"
        "UnsetEnvironment=RAKIS_CONNECT_TOKEN RAKIS_API_URL\n"
        "StandardOutput=null\nStandardError=journal\n[Install]\nWantedBy=default.target\n"
    )
    fd, temporary = tempfile.mkstemp(prefix=".rakis-service-", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(unit)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    if _systemctl("daemon-reload").returncode or _systemctl("enable", UNIT).returncode:
        raise BackgroundError(
            "Could not start the connector user service; "
            "check systemctl --user status rakis-connector"
        )
    # Restart also applies a changed configuration/interval to an already running service.
    if _systemctl("restart", UNIT).returncode:
        raise BackgroundError("Could not restart the connector user service")
    service_status = manage("status", config, interval)
    if service_status["background"] != "active":
        raise BackgroundError(
            "The connector did not stay active; check systemctl --user status rakis-connector"
        )
    return {**service_status, "service": UNIT, "runs_as_root": False}
