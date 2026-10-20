"""Shared helpers for the connector tests.

The signature database is served as a container in the same shape the public
CDN publishes: a padded header, then a gzip compressed tar of the signature
files.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

HEADER_BYTES = 512
BUILD_TIME = "20 Oct 2026 06-24 +0000"


def build_container(members: dict[str, str], *, digest: str | None = None) -> bytes:
    """Build one signature container: a padded header and a gzip tar."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, content in members.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    payload = gzip.compress(raw.getvalue())
    header = (
        f"ClamAV-VDB:{BUILD_TIME}:1:2:3:{digest or hashlib.md5(payload).hexdigest()}:"
        "VGVzdA==:svc.clamav-publisher:1792477745"
    )
    return header.ljust(HEADER_BYTES).encode("ascii") + payload


def container_handler(
    members: dict[str, str],
    *,
    digest: str | None = None,
    requests: list[str] | None = None,
    status_code: int = 200,
):
    """Serve the same container for every request."""
    body = build_container(members, digest=digest)

    def handler(request: httpx.Request) -> httpx.Response:
        if requests is not None:
            requests.append(request.url.path)
        if status_code != 200:
            return httpx.Response(status_code)
        return httpx.Response(200, content=body, headers={"Content-Length": str(len(body))})

    return handler


def hash_entry(digest: str, size: int, name: str = "Example.Malware.A") -> str:
    return f"{digest}:{size}:{name}\n"


def write_cache(
    directory: Path,
    entries: dict[str, str],
    *,
    version: str = "daily.cvd@2026-10-20",
    updated: str = "2026-10-20T03:12:00+00:00",
) -> Path:
    """Write a cached signature database: the hash files, the index, the metadata."""
    directory.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for name, content in entries.items():
        (directory / name).write_text(content)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, size, name = line.split(":", 2)
            lines.append(f"{digest.lower()}:{size}:{name}")
    lines.sort()
    (directory / "hashes.idx").write_text("".join(f"{line}\n" for line in lines))
    (directory / "database.json").write_text(
        json.dumps(
            {
                "version": version,
                "updated_at": updated,
                "downloaded_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
                "files": len(entries),
            }
        )
    )
    return directory
