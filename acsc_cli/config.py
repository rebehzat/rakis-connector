from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StrictBool,
    field_validator,
    model_validator,
)

TOKEN = re.compile(r"^acsc_a_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$")


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_url: str
    token: SecretStr
    allow_local_http: bool = False
    config_roots: list[str] = Field(default_factory=list, max_length=8)
    device_paths: list[str] = Field(default_factory=list, max_length=16)
    ai_configuration: StrictBool = False

    @field_validator("token")
    @classmethod
    def valid_token(cls, value: SecretStr) -> SecretStr:
        if not TOKEN.fullmatch(value.get_secret_value()):
            raise ValueError("invalid connection token")
        return value

    @model_validator(mode="after")
    def valid_origin(self) -> Config:
        if self.ai_configuration and not self.config_roots:
            raise ValueError("AI configuration review requires selected configuration folders")
        p = urlsplit(self.api_url)
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
                    self.allow_local_http
                    and p.scheme == "http"
                    and p.hostname in {"127.0.0.1", "localhost", "::1"}
                )
            )
        ):
            raise ValueError("HTTPS API origin required")
        _ = p.port
        self.api_url = self.api_url.rstrip("/")
        return self


def load(path: Path, *, use_environment: bool = True) -> Config:
    if use_environment and os.environ.get("RAKIS_CONNECT_TOKEN"):
        return Config(
            api_url=os.environ.get("RAKIS_API_URL", ""),
            token=SecretStr(os.environ["RAKIS_CONNECT_TOKEN"]),
        )
    if os.name == "nt":
        raise ValueError("use Windows service environment")
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
            raise ValueError("private config required")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValueError("config too large")
        return Config.model_validate_json(raw)
    finally:
        if fd != -1:
            os.close(fd)


def save(path: Path, config: Config) -> None:
    if os.name == "nt":
        raise ValueError("use --no-store with Windows service environment")
    directory = path.parent
    if directory.is_symlink():
        raise ValueError("config parent cannot be a link")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("config directory must be private (0700)")
    if path.is_symlink():
        raise ValueError("config cannot be a link")
    fd, name = tempfile.mkstemp(prefix=".rakis-", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(
                {
                    "api_url": config.api_url,
                    "token": config.token.get_secret_value(),
                    "allow_local_http": config.allow_local_http,
                    "config_roots": config.config_roots,
                    "device_paths": config.device_paths,
                    "ai_configuration": config.ai_configuration,
                },
                stream,
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def disconnect(path: Path) -> None:
    """Delete only an owned, private regular config; never a link or shared file."""
    if not path.exists() and not path.is_symlink():
        return
    if os.name == "nt":
        raise ValueError("remove Windows service environment credentials")
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        raise ValueError("private config required")
    path.unlink()
