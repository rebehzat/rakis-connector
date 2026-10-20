"""Local ClamAV signature matching with the connector's own signature database.

The connector downloads the ClamAV signature containers (``daily.cvd`` and
``main.cvd``) from the public signature CDN and keeps the whole-file hash
databases they carry (``.hdb`` and ``.hsb``). A scanned file is matched by its
MD5, SHA1 and SHA256 digest. The containers are read as they are published:
a fixed header, then a gzip compressed tar of the signature files.

Coverage limitation: this module compares whole-file hashes only. ClamAV's
pattern (``.ndb``), logical (``.ldb``), bytecode and section-hash engines are
not evaluated, and the publisher signature of a container is not checked: the
MD5 that the container header records over its own payload is checked instead.
A file that only matches a pattern or a bytecode signature is not reported
here, so a clean device scan is not proof that the server is free of malware.

Only signature names, relative path labels, file sizes and coverage counters
leave the device: file content, file hashes and the list of scanned files stay
local.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import mmap
import os
import re
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO

import httpx

CONTAINER_URL = "https://database.clamav.net/"
# The signature CDN serves the containers to ClamAV update clients and
# identifies them by the user agent. The connector uses the same convention
# and adds its own version, so the download is not mistaken for a browser.
USER_AGENT = "ClamAV/1.4.3 (rakis-connector)"
CONTAINERS = ("daily.cvd", "main.cvd")
HASH_SUFFIXES = (".hdb", ".hsb")
HEADER_BYTES = 512
MAX_CONTAINER_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
REFRESH_INTERVAL = timedelta(hours=24)
CHUNK_BYTES = 1024 * 1024
DIGEST_HEX = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
HASH_LINE = re.compile(r"^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}):(\d+):(.+)$")
BUILD_TIME = "%d %b %Y %H-%M %z"
METADATA_NAME = "database.json"
INDEX_NAME = "hashes.idx"


class ClamavError(ValueError):
    """The signature database is unavailable or unusable."""


@dataclass(frozen=True)
class Match:
    """One signature match. The signature name is the only detail that leaves."""

    signature: str
    match_type: str


@dataclass(frozen=True)
class HashSignature:
    """A whole-file hash signature."""

    name: str
    size: int


def default_directory() -> Path:
    """The private cache directory that holds the signature database."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "rakis" / "clamav"


def configured_containers() -> tuple[str, ...]:
    """The containers to use. ``RAKIS_CLAMAV_DATABASE=daily`` keeps it small."""
    choice = os.environ.get("RAKIS_CLAMAV_DATABASE", "full").strip().lower()
    if choice == "daily":
        return ("daily.cvd",)
    return CONTAINERS


def parse_hashes(text: str) -> dict[str, list[HashSignature]]:
    """Parse a hash database into signatures keyed by digest.

    Each line is ``<hash>:<size>:<name>``. The hash is an MD5, SHA1 or SHA256
    digest and the size is the size of the known sample. A size of zero
    matches any file size.
    """
    index: dict[str, list[HashSignature]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = HASH_LINE.fullmatch(line)
        if match is None:
            continue
        digest, size, name = match.groups()
        index.setdefault(digest.lower(), []).append(HashSignature(name=name, size=int(size)))
    return index


def _looks_like_hash_database(text: str) -> bool:
    total = valid = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        total += 1
        if HASH_LINE.fullmatch(line):
            valid += 1
    return valid > 0 and valid * 2 >= total


def _looks_like_hash_database_file(path: Path) -> bool:
    """Check the format of a hash database without loading it into memory."""
    with path.open("r", errors="replace") as stream:
        head = []
        for _ in range(200):
            line = stream.readline()
            if not line:
                break
            head.append(line)
    return _looks_like_hash_database("".join(head))


class _HashingReader(io.RawIOBase):
    """Read a stream and hash every byte that passes through it."""

    def __init__(self, stream: BinaryIO, hasher: Any) -> None:
        self._stream = stream
        self._hasher = hasher

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        block = self._stream.read(CHUNK_BYTES if size is None or size < 0 else size)
        if block:
            self._hasher.update(block)
        return block


class SignatureIndex:
    """The hash databases, kept on disk and searched without loading them all.

    The index is a sorted text file. A lookup reads a few pages from the
    memory mapped file, so the connector does not need the whole database in
    memory on a small server.
    """

    def __init__(self, path: Path) -> None:
        self._handle = path.open("rb")
        self._map = mmap.mmap(self._handle.fileno(), 0, access=mmap.ACCESS_READ)

    def close(self) -> None:
        self._map.close()
        self._handle.close()

    def lookup(self, digest: str) -> list[HashSignature]:
        """Every signature recorded for one digest."""
        found: list[HashSignature] = []
        offset = self._first(digest)
        while offset is not None:
            line = self._line(offset)
            key, _, remainder = line.partition(":")
            if key != digest:
                break
            size, _, name = remainder.partition(":")
            try:
                found.append(HashSignature(name=name, size=int(size)))
            except ValueError:
                pass
            offset = self._next(offset)
        return found

    def match(self, stream: BinaryIO, size: int) -> list[Match]:
        """Match one open file against the hash databases."""
        digests: dict[str, str] = {}
        for algorithm in ("md5", "sha1", "sha256"):
            digests[algorithm] = hashlib.new(algorithm)
        while True:
            block = stream.read(CHUNK_BYTES)
            if not block:
                break
            for hasher in digests.values():
                hasher.update(block)
        matches: list[Match] = []
        seen: set[str] = set()
        for algorithm in ("md5", "sha1", "sha256"):
            digest = digests[algorithm].hexdigest()
            for signature in self.lookup(digest):
                if signature.size not in (0, size):
                    continue
                if signature.name in seen:
                    continue
                seen.add(signature.name)
                matches.append(Match(signature=signature.name, match_type="hash"))
        return matches

    def _line(self, offset: int) -> str:
        end = self._map.find(b"\n", offset)
        if end == -1:
            end = len(self._map)
        return self._map[offset:end].decode("utf-8", "replace")

    def _next(self, offset: int) -> int | None:
        end = self._map.find(b"\n", offset)
        if end == -1:
            return None
        start = end + 1
        if start >= len(self._map):
            return None
        return start

    def _first(self, digest: str) -> int | None:
        """The offset of the first line whose digest is not smaller."""
        low = 0
        high = len(self._map)
        while low < high:
            middle = (low + high) // 2
            start = self._line_start(middle)
            end = self._map.find(b"\n", start)
            if end == -1:
                end = len(self._map)
            key = self._map[start:end].decode("utf-8", "replace").partition(":")[0]
            if key < digest:
                low = end + 1
            else:
                high = start
        if low >= len(self._map):
            return None
        start = self._line_start(low)
        end = self._map.find(b"\n", start)
        if end == -1:
            end = len(self._map)
        key = self._map[start:end].decode("utf-8", "replace").partition(":")[0]
        return start if key == digest else None

    def _line_start(self, offset: int) -> int:
        if offset <= 0:
            return 0
        start = self._map.rfind(b"\n", 0, offset)
        return 0 if start == -1 else start + 1


class ClamavDatabase:
    """The signature database the connector downloads and keeps on this server."""

    def __init__(
        self,
        directory: Path | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        url: str = CONTAINER_URL,
        containers: tuple[str, ...] | None = None,
    ) -> None:
        self.directory = Path(directory) if directory is not None else default_directory()
        self.url = url
        self.containers = containers if containers is not None else configured_containers()
        self._transport = transport
        self._http: httpx.Client | None = None
        self._index: SignatureIndex | None = None

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None
        if self._index is not None:
            self._index.close()
            self._index = None

    def refresh(self, *, force: bool = False) -> None:
        """Download the signature containers and keep the hash databases.

        A failed download keeps the cached copy. Only when no usable copy is
        left does the refresh fail.
        """
        self._prepare_directory()
        metadata = self._metadata()
        downloaded = metadata.get("downloaded_at")
        if not force and downloaded and self._is_recent(downloaded):
            return
        total = 0
        builds: dict[str, str] = {}
        for name in self.containers:
            target = self.directory / f"{name}.tmp"
            try:
                self._download(name, target)
                build = self._extract(target, name)
            except (ClamavError, httpx.HTTPError) as exc:
                target.unlink(missing_ok=True)
                if not self._has_hash_files():
                    raise ClamavError(
                        f"the ClamAV signature database could not be downloaded: {exc}"
                    ) from None
                continue
            builds[name] = build
            total += target.stat().st_size
            if total > MAX_TOTAL_BYTES:
                target.unlink(missing_ok=True)
                raise ClamavError("the signature database exceeds the local size limit")
            target.unlink(missing_ok=True)
        if not builds and not self._has_hash_files():
            raise ClamavError("the signature database is not available")
        self._rebuild_index()
        self._write_metadata(builds)

    def index(self) -> SignatureIndex:
        """The hash index, built once per database instance."""
        if self._index is None:
            path = self.directory / INDEX_NAME
            if not path.exists():
                raise ClamavError("the signature database is empty")
            self._index = SignatureIndex(path)
        return self._index

    def status(self) -> dict[str, Any]:
        """Version, timestamp and file count of the cached signature database."""
        metadata = self._metadata()
        version = metadata.get("version")
        updated = metadata.get("updated_at")
        if not version or not updated:
            raise ClamavError("the signature database is not available")
        return {
            "version": version,
            "updated_at": updated,
            "files": int(metadata.get("files", 0)),
        }

    def _prepare_directory(self) -> None:
        directory = self.directory
        if directory.is_symlink():
            raise ClamavError("the signature cache directory cannot be a symlink")
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = directory.lstat()
        except OSError as exc:
            raise ClamavError("the signature cache directory is unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ClamavError("the signature cache directory must be a real directory")
        if info.st_uid != os.getuid():
            raise ClamavError("the signature cache directory must belong to this account")
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.chmod(directory, 0o700, follow_symlinks=False)

    def _client(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(
                follow_redirects=False,
                trust_env=False,
                timeout=120,
                headers={"User-Agent": USER_AGENT},
                transport=self._transport,
            )
        return self._http

    def _download(self, name: str, target: Path) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".clamav-", dir=self.directory)
        os.close(fd)
        path = Path(temporary)
        try:
            with self._client().stream("GET", self.url + name) as response:
                if response.status_code != 200:
                    raise ClamavError(f"the signature download for {name} was refused")
                expected = response.headers.get("Content-Length")
                written = 0
                with path.open("wb") as stream:
                    for block in response.iter_bytes(65536):
                        written += len(block)
                        if written > MAX_CONTAINER_BYTES:
                            raise ClamavError(
                                f"the signature container {name} exceeds the size limit"
                            )
                        stream.write(block)
                    stream.flush()
                    os.fsync(stream.fileno())
            if expected is not None and written != int(expected):
                raise ClamavError(f"the signature download for {name} was incomplete")
            os.chmod(path, 0o600)
            target.unlink(missing_ok=True)
            os.replace(path, target)
        except httpx.HTTPError as exc:
            path.unlink(missing_ok=True)
            raise ClamavError(f"the signature download for {name} failed") from exc
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def _extract(self, container: Path, container_name: str) -> str:
        """Extract the hash databases from one container. Returns its build time."""
        pending: list[tuple[str, Path]] = []
        try:
            with container.open("rb") as raw:
                header = raw.read(HEADER_BYTES)
                if len(header) < HEADER_BYTES or not header.startswith(b"ClamAV-VDB:"):
                    raise ClamavError("the signature container has no readable header")
                fields = header.decode("ascii", "replace").rstrip().split(":")
                digest = next((field for field in fields if DIGEST_HEX.fullmatch(field)), None)
                if digest is None:
                    raise ClamavError("the signature container has no content digest")
                build = self._build_time(fields)
                raw.seek(HEADER_BYTES)
                hasher = hashlib.md5()
                with gzip.GzipFile(fileobj=_HashingReader(raw, hasher)) as stream:
                    with tarfile.open(fileobj=stream, mode="r|") as archive:
                        for member in archive:
                            if not member.isfile():
                                continue
                            name = Path(member.name).name
                            if not name.endswith(HASH_SUFFIXES):
                                continue
                            if member.size > MAX_MEMBER_BYTES:
                                continue
                            handle = archive.extractfile(member)
                            if handle is None:
                                continue
                            fd, temporary = tempfile.mkstemp(prefix=".member-", dir=self.directory)
                            with os.fdopen(fd, "wb") as out:
                                shutil.copyfileobj(handle, out, CHUNK_BYTES)
                            pending.append((name, Path(temporary)))
                if hasher.hexdigest() != digest:
                    raise ClamavError("the signature container does not match its own digest")
            for name, temporary in pending:
                if not _looks_like_hash_database_file(temporary):
                    raise ClamavError(f"the {name} file is not a hash database")
                suffix = name.rsplit(".", 1)[-1]
                target = self.directory / f"{container_name.rsplit('.', 1)[0]}.{suffix}"
                os.chmod(temporary, 0o600)
                os.replace(temporary, target)
        finally:
            for _name, temporary in pending:
                temporary.unlink(missing_ok=True)
        return build

    def _build_time(self, fields: list[str]) -> str:
        """The build time of the container, as an ISO timestamp."""
        for field in fields[1:3]:
            try:
                moment = datetime.strptime(field.strip(), BUILD_TIME)
            except ValueError:
                continue
            return moment.astimezone(UTC).replace(microsecond=0).isoformat()
        return datetime.now(UTC).replace(microsecond=0).isoformat()

    def _rebuild_index(self) -> None:
        """Write the sorted lookup index from the cached hash databases."""
        lines: list[str] = []
        for path in sorted(self.directory.glob("*.hdb")) + sorted(self.directory.glob("*.hsb")):
            with path.open("r", errors="replace") as stream:
                for line in stream:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if not HASH_LINE.fullmatch(line):
                        continue
                    digest, size, name = line.split(":", 2)
                    lines.append(f"{digest.lower()}:{size}:{name}")
        if not lines:
            raise ClamavError("the signature database is empty")
        lines.sort()
        target = self.directory / INDEX_NAME
        fd, temporary = tempfile.mkstemp(prefix=".index-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.writelines(f"{line}\n" for line in lines)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _write(self, target: Path, content: bytes) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".sig-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _has_hash_files(self) -> bool:
        return any(self.directory.glob("*.hdb")) or any(self.directory.glob("*.hsb"))

    def _metadata(self) -> dict[str, Any]:
        path = self.directory / METADATA_NAME
        try:
            value = json.loads(path.read_text())
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    def _write_metadata(self, builds: dict[str, str]) -> None:
        metadata = self._metadata()
        versions = []
        updated = None
        for name, build in sorted(builds.items()):
            versions.append(f"{name}@{build[:10]}")
            if updated is None or build > updated:
                updated = build
        files = len(list(self.directory.glob("*.hdb"))) + len(list(self.directory.glob("*.hsb")))
        payload = {
            "version": "+".join(versions) or metadata.get("version", ""),
            # The build time of the signatures, not the download time.
            "updated_at": updated or metadata.get("updated_at"),
            # When the database was fetched. The refresh cadence follows it.
            "downloaded_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "files": files,
        }
        target = self.directory / METADATA_NAME
        fd, temporary = tempfile.mkstemp(prefix=".meta-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(payload, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _is_recent(self, updated: str) -> bool:
        try:
            moment = datetime.fromisoformat(updated)
        except ValueError:
            return False
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        age = datetime.now(UTC) - moment.astimezone(UTC)
        return timedelta(0) <= age <= REFRESH_INTERVAL
