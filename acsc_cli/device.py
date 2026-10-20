"""Bounded local malware detection. Only signature names leave the device.

The connector scans the chosen files and folders with a ClamAV signature
database it maintains itself and reports the detections to the platform. The
upload carries the signature name, a relative path label, the file size, the
match type and the coverage counters. File content, file hashes and the list
of scanned files stay on the server.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from acsc_cli.clamav import ClamavDatabase, Match, SignatureIndex

MAX_ROOTS = 16
MAX_DEPTH = 12
MAX_ENTRIES = 20000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_READ_BYTES = 4 * 1024 * 1024 * 1024
MAX_DETECTIONS = 500
SYSTEM_ROOTS = (Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"))
# The platform accepts a bounded signature name and no other detail.
SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:+-]{0,127}$")


def scan(paths: list[str], database: ClamavDatabase | None = None) -> dict[str, Any]:
    """Scan the chosen files and folders for known malware signatures.

    The report holds the coverage counters, the signature database version and
    the detection list. No file content, no file hash and no scanned file list
    is part of it.
    """
    if os.name == "nt":
        raise ValueError("device scanning currently requires POSIX safe file access")
    if not 1 <= len(paths) <= MAX_ROOTS:
        raise ValueError("choose between one and sixteen device paths")
    database = database if database is not None else ClamavDatabase()
    database.refresh()
    index = database.index()
    files = 0
    directories = 0
    skipped = 0
    read_bytes = 0
    entries = 0
    detections: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for number, raw_path in enumerate(paths, 1):
        root = Path(raw_path).absolute()
        try:
            info = root.lstat()
        except OSError as exc:
            raise ValueError(f"device path cannot be read: {exc.strerror}") from None
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("device paths cannot be symlinks")
        if root == Path("/") or any(
            root == system or system in root.parents for system in SYSTEM_ROOTS
        ):
            raise ValueError("the filesystem root and system runtime roots cannot be scanned")
        if any(parent.is_symlink() for parent in root.parents):
            raise ValueError("device paths cannot contain symlink parents")

        if stat.S_ISDIR(info.st_mode):

            def walk_error(error: OSError) -> None:
                nonlocal skipped
                skipped += 1

            for directory, dirs, names, directory_fd in os.fwalk(
                root, follow_symlinks=False, onerror=walk_error
            ):
                if directory_fd is None:
                    raise ValueError("device scanning requires safe directory access")
                relative = Path(directory).relative_to(root)
                excluded: set[str] = set()
                for name in dirs:
                    try:
                        child = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError:
                        skipped += 1
                        excluded.add(name)
                        continue
                    if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
                        # A link can point outside the chosen path and is never followed.
                        excluded.add(name)
                        skipped += 1
                dirs[:] = sorted(name for name in dirs if name not in excluded)
                if len(relative.parts) >= MAX_DEPTH:
                    skipped += len(dirs)
                    dirs[:] = []
                entries += len(dirs) + len(names)
                if entries > MAX_ENTRIES:
                    skipped += 1
                    break
                directories += 1
                for name in sorted(names):
                    try:
                        child = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError:
                        skipped += 1
                        continue
                    if not stat.S_ISREG(child.st_mode) or child.st_nlink != 1:
                        # Special files and hard links are not read.
                        skipped += 1
                        continue
                    if (
                        child.st_size > MAX_FILE_BYTES
                        or read_bytes + child.st_size > MAX_READ_BYTES
                    ):
                        skipped += 1
                        continue
                    label = _label(number, (relative / name).as_posix())
                    if label is None:
                        skipped += 1
                        continue
                    fd = None
                    try:
                        fd = os.open(
                            name,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=directory_fd,
                        )
                        matches = _match(fd, child, index)
                    except OSError:
                        matches = None
                    finally:
                        if fd is not None:
                            os.close(fd)
                    if matches is None:
                        skipped += 1
                        continue
                    files += 1
                    read_bytes += child.st_size
                    detections, skipped = _record(
                        detections, seen, skipped, label, child.st_size, matches
                    )
        elif stat.S_ISREG(info.st_mode):
            label = _label(number, root.name)
            if label is None:
                skipped += 1
                continue
            fd = None
            try:
                fd = os.open(root, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                matches = _match(fd, info, index)
            except OSError:
                matches = None
            finally:
                if fd is not None:
                    os.close(fd)
            if matches is None:
                skipped += 1
                continue
            files += 1
            read_bytes += info.st_size
            detections, skipped = _record(detections, seen, skipped, label, info.st_size, matches)
        else:
            raise ValueError("device paths must be files or folders")

    return {
        "engine": "clamav",
        "signature_db": database.status(),
        "files_scanned": files,
        "directories_scanned": directories,
        "skipped_files": min(skipped, 1000000),
        "complete": skipped == 0,
        "detections": detections,
    }


def _label(number: int, relative: str) -> str | None:
    """Build a relative path label the platform accepts."""
    if not relative or len(relative) > 480:
        return None
    if any(ord(char) < 32 or char == "\\" for char in relative):
        return None
    if any(part in {"", ".", ".."} for part in relative.split("/")):
        return None
    label = f"root-{number}/{relative}"
    return label if len(label) <= 512 else None


def _match(fd: int, info: os.stat_result, index: SignatureIndex) -> list[Match] | None:
    """Match one open file, refusing a file that changed while it was read."""
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
        ):
            return None
        with os.fdopen(fd, "rb", closefd=False) as stream:
            matches = index.match(stream, opened.st_size)
            final = os.fstat(stream.fileno())
        if (final.st_size, final.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            return None
        return matches
    except OSError:
        return None


def _record(
    detections: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    skipped: int,
    label: str,
    size: int,
    matches: list[Match],
) -> tuple[list[dict[str, Any]], int]:
    """Add the detections of one file, keeping the report within its limits."""
    for match in matches:
        key = (label, match.signature)
        if key in seen:
            continue
        seen.add(key)
        if not SIGNATURE_PATTERN.fullmatch(match.signature):
            # A name the platform cannot store is a gap in the coverage.
            skipped += 1
            continue
        if len(detections) >= MAX_DETECTIONS:
            # The platform accepts a bounded detection list. A dropped
            # detection is a gap in the coverage and is reported as skipped.
            skipped += 1
            continue
        detections.append(
            {
                "path": label,
                "signature": match.signature,
                "match_type": match.match_type,
                "size_bytes": size,
            }
        )
    return detections, skipped
