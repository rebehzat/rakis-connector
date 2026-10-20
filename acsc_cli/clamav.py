"""Local ClamAV signature matching with the connector's own signature database.

Coverage limitation: this module implements whole-file hash matching (MD5, SHA1
and SHA256 lookups from .hdb files) and nucleic matching (section hashes from
.ndb files read at a recorded byte offset). It does not evaluate ClamAV
bytecode (.cvd and .cld) signatures, does not match .ftm magic files, does not
unpack archives, does not run heuristic or behavioural analysis, and does not
use a clamd daemon. A file that only matches a bytecode, magic or heuristic
signature is not reported here, so a clean device scan is not proof that the
server is free of malware.

The signature database is downloaded from https://database.clamav.net/ and kept
in a private local cache. Only signature names, relative path labels, file
sizes and coverage counters leave the device: file content, file hashes and
the list of scanned files stay local.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO

import httpx

DATABASE_URL = "https://database.clamav.net/"
SIGNATURE_FILES = ("daily.hdb", "daily.ndb", "main.hdb", "main.ndb")
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
REFRESH_INTERVAL = timedelta(hours=24)
MAX_SECTION_OFFSETS = 32
CHUNK_BYTES = 1024 * 1024
VALIDATION_BYTES = 512 * 1024
HASH_ALGORITHMS = {"MD5": "md5", "SHA1": "sha1", "SHA256": "sha256"}
HASH_LINE = re.compile(r"^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}):(\d+):(.+)$")
DIGEST = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$")


class ClamavError(ValueError):
    """The signature database is unavailable or unusable."""


@dataclass(frozen=True)
class Match:
    """One signature match. The signature name is the only detail that leaves."""

    signature: str
    match_type: str


@dataclass(frozen=True)
class HashSignature:
    """A whole-file hash signature from a .hdb file."""

    name: str
    size: int


@dataclass(frozen=True)
class NucleicSignature:
    """A section hash signature from a .ndb file."""

    name: str
    algorithm: str
    offset: int
    digest: str


def default_directory() -> Path:
    """The private cache directory that holds the signature database."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "rakis" / "clamav"


def parse_hdb(text: str) -> dict[str, list[HashSignature]]:
    """Parse .hdb content into whole-file hash signatures keyed by digest.

    Each line is ``<hash>:<size>:<name>``. The hash is an MD5, SHA1 or SHA256
    digest and the size is the file size of the known sample. A size of zero
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


def parse_ndb(text: str) -> list[NucleicSignature]:
    """Parse .ndb content into nucleic section signatures.

    Each line is ``<target>:0:<type>,<offset>,<digest>``. ``MD5``, ``SHA1`` and
    ``SHA256`` describe the file itself and ``Hash:0``, ``Hash:1`` and
    ``Hash:2`` describe a section of it; the section hash is an MD5 digest.
    ``PE`` entries are recognised but not matched.
    """
    signatures: list[NucleicSignature] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parsed = _parse_ndb_line(line)
        if parsed is not None:
            signatures.append(parsed)
    return signatures


def _parse_ndb_line(line: str) -> NucleicSignature | None:
    parts = line.split(":", 2)
    if len(parts) < 3:
        return None
    name, target_type, remainder = parts
    if target_type != "0":
        return None
    tokens = [token for token in re.split(r"[,:]", remainder) if token]
    if not tokens:
        return None
    kind = tokens[0]
    if kind == "Hash":
        if len(tokens) < 2 or tokens[1] not in {"0", "1", "2"}:
            return None
        algorithm = "md5"
        position = 2
    elif kind in HASH_ALGORITHMS:
        algorithm = HASH_ALGORITHMS[kind]
        position = 1
    else:
        # PE sections and unknown types are not implemented.
        return None
    if position < len(tokens) and tokens[position] == "*":
        position += 1
    if position >= len(tokens):
        return None
    if tokens[position].isdigit():
        offset = int(tokens[position])
        digest = tokens[position + 1] if len(tokens) > position + 1 else ""
    else:
        offset = 0
        digest = tokens[position]
    digest = digest.lower()
    if not DIGEST.fullmatch(digest):
        return None
    return NucleicSignature(name=name, algorithm=algorithm, offset=offset, digest=digest)


def _looks_like_hdb(text: str) -> bool:
    total = valid = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        total += 1
        if HASH_LINE.fullmatch(line):
            valid += 1
    return valid > 0 and valid * 2 >= total


def _looks_like_ndb(text: str) -> bool:
    total = valid = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        total += 1
        if _parse_ndb_line(line) is not None:
            valid += 1
    return valid > 0 and valid * 2 >= total


class SignatureIndex:
    """Parsed signatures: whole-file hashes and nucleic section hashes."""

    def __init__(
        self, hashes: dict[str, list[HashSignature]], nucleic: list[NucleicSignature]
    ) -> None:
        self._hashes = hashes
        self._sections: dict[tuple[str, int], dict[str, list[str]]] = {}
        for signature in nucleic:
            key = (signature.algorithm, signature.offset)
            self._sections.setdefault(key, {}).setdefault(signature.digest, []).append(
                signature.name
            )

    def match(self, stream: BinaryIO, size: int) -> list[Match]:
        """Match one open file against the signature index.

        The file is read once. Whole-file digests are compared with the .hdb
        index, and the bytes that start at a recorded offset and continue to the
        end of the file are compared with the .ndb index. An offset of zero
        therefore compares the whole file.
        """
        whole = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
        }
        jobs = self._section_jobs(size)
        sections = {job: hashlib.new(job[0]) for job in jobs if job[1] > 0}
        position = 0
        while True:
            block = stream.read(CHUNK_BYTES)
            if not block:
                break
            end = position + len(block)
            for hasher in whole.values():
                hasher.update(block)
            for job, hasher in sections.items():
                start = max(job[1], position)
                if end > start:
                    hasher.update(block[start - position :])
            position = end
        digests = {algorithm: hasher.hexdigest() for algorithm, hasher in whole.items()}
        matches: list[Match] = []
        seen: set[tuple[str, str]] = set()
        for algorithm, digest in digests.items():
            for signature in self._hashes.get(digest, ()):
                if signature.size not in (0, size):
                    continue
                key = (signature.name, "hash")
                if key not in seen:
                    seen.add(key)
                    matches.append(Match(signature=signature.name, match_type="hash"))
        section_digests: dict[tuple[str, int], str] = {}
        for job, hasher in sections.items():
            section_digests[job] = hasher.hexdigest()
        for algorithm, digest in digests.items():
            if (algorithm, 0) in self._sections:
                section_digests[(algorithm, 0)] = digest
        for job, digest in section_digests.items():
            for name in self._sections.get(job, {}).get(digest, ()):
                key = (name, "nucleic")
                if key not in seen:
                    seen.add(key)
                    matches.append(Match(signature=name, match_type="nucleic"))
        return matches

    def _section_jobs(self, size: int) -> list[tuple[str, int]]:
        """Bounded set of (algorithm, offset) pairs to hash for one file."""
        offsets = sorted({offset for _, offset in self._sections if offset < size})
        jobs: list[tuple[str, int]] = []
        for offset in offsets[:MAX_SECTION_OFFSETS]:
            for algorithm in HASH_ALGORITHMS.values():
                if (algorithm, offset) in self._sections:
                    jobs.append((algorithm, offset))
        return jobs


class ClamavDatabase:
    """The signature database the connector downloads and keeps on this server."""

    def __init__(
        self,
        directory: Path | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        url: str = DATABASE_URL,
    ) -> None:
        self.directory = Path(directory) if directory is not None else default_directory()
        self.url = url
        self._transport = transport
        self._http: httpx.Client | None = None
        self._index: SignatureIndex | None = None

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None

    def refresh(self, *, force: bool = False) -> None:
        """Download missing or stale signature files into the private cache.

        A failed download keeps the cached copy. Only when no usable copy is
        left does the refresh fail.
        """
        self._prepare_directory()
        total = 0
        refreshed = False
        for name in SIGNATURE_FILES:
            target = self.directory / name
            if not force and self._is_current(target):
                total += self._size(target)
                continue
            try:
                self._download(name, target)
                refreshed = True
            except (ClamavError, httpx.HTTPError) as exc:
                if not self._usable(target):
                    raise ClamavError(
                        f"the ClamAV signature database could not be downloaded: {exc}"
                    ) from None
            total += self._size(target)
            if total > MAX_TOTAL_BYTES:
                raise ClamavError("the signature database exceeds the local size limit")
        if refreshed:
            self._index = None

    def index(self) -> SignatureIndex:
        """Parse the cached signature files once per database instance."""
        if self._index is None:
            hashes: dict[str, list[HashSignature]] = {}
            nucleic: list[NucleicSignature] = []
            for name in SIGNATURE_FILES:
                path = self.directory / name
                try:
                    text = path.read_text(errors="replace")
                except OSError as exc:
                    raise ClamavError(f"the signature file {name} is missing") from exc
                if name.endswith(".hdb"):
                    for digest, signatures in parse_hdb(text).items():
                        hashes.setdefault(digest, []).extend(signatures)
                else:
                    nucleic.extend(parse_ndb(text))
            if not hashes and not nucleic:
                raise ClamavError("the signature database is empty")
            self._index = SignatureIndex(hashes, nucleic)
        return self._index

    def status(self) -> dict[str, Any]:
        """Version, timestamp and file count of the cached signature database."""
        freshest: tuple[str, float] | None = None
        count = 0
        for name in SIGNATURE_FILES:
            path = self.directory / name
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
                continue
            count += 1
            if freshest is None or info.st_mtime > freshest[1]:
                freshest = (name, info.st_mtime)
        if freshest is None:
            raise ClamavError("the signature database is not available")
        name, mtime = freshest
        updated = datetime.fromtimestamp(mtime, UTC).replace(microsecond=0)
        return {
            "version": f"{name}@{updated.date().isoformat()}",
            "updated_at": updated.isoformat().replace("+00:00", "Z"),
            "files": count,
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
                timeout=60,
                transport=self._transport,
            )
        return self._http

    def _is_current(self, target: Path) -> bool:
        try:
            info = target.lstat()
        except OSError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
            return False
        age = datetime.now(UTC).timestamp() - info.st_mtime
        return 0 <= age <= REFRESH_INTERVAL.total_seconds()

    def _usable(self, target: Path) -> bool:
        try:
            info = target.lstat()
        except OSError:
            return False
        return stat.S_ISREG(info.st_mode) and info.st_size > 0

    def _size(self, target: Path) -> int:
        try:
            info = target.lstat()
        except OSError:
            return 0
        return info.st_size if stat.S_ISREG(info.st_mode) else 0

    def _download(self, name: str, target: Path) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".clamav-", dir=self.directory)
        try:
            with self._client().stream("GET", self.url + name) as response:
                if response.status_code != 200:
                    raise ClamavError(f"the signature download for {name} was refused")
                expected = response.headers.get("Content-Length")
                written = 0
                with os.fdopen(fd, "wb") as stream:
                    fd = -1
                    for block in response.iter_bytes(65536):
                        written += len(block)
                        if written > MAX_FILE_BYTES:
                            raise ClamavError(f"the signature file {name} exceeds the size limit")
                        stream.write(block)
                    stream.flush()
                    os.fsync(stream.fileno())
            if expected is not None and written != int(expected):
                raise ClamavError(f"the signature download for {name} was incomplete")
            os.chmod(temporary, 0o600)
            self._validate(Path(temporary), name)
            if target.is_symlink():
                target.unlink()
            os.replace(temporary, target)
        except httpx.HTTPError as exc:
            raise ClamavError(f"the signature download for {name} failed") from exc
        finally:
            if fd != -1:
                os.close(fd)
            Path(temporary).unlink(missing_ok=True)

    def _validate(self, path: Path, name: str) -> None:
        with path.open("rb") as stream:
            head = stream.read(VALIDATION_BYTES)
        if not head:
            raise ClamavError(f"the downloaded {name} file is empty")
        text = head.decode("utf-8", errors="replace")
        if name.endswith(".hdb"):
            valid = _looks_like_hdb(text)
        else:
            valid = _looks_like_ndb(text)
        if not valid:
            raise ClamavError(f"the downloaded {name} file is not a signature database")
