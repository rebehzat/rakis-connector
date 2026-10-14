"""Bounded read-only configuration checks. Never retain or upload file content."""

from __future__ import annotations

import json
import os
import re
import stat
from itertools import chain
from pathlib import Path
from typing import Any

MAX_FILES = 250
MAX_FILE_BYTES = 256 * 1024
MAX_READ_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 10000
SKIP_DIRS = {".git", "node_modules", "vendor", ".cache", "proc", "sys", "dev", ".ssh"}
SKIP_FILES = {"passwd", "shadow", "gshadow", "authorized_keys", "known_hosts"}
SKIP_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".db", ".sqlite"}
FORMATS = {
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".ini": "ini",
    ".conf": "config",
    ".config": "config",
    ".cfg": "config",
    ".properties": "config",
    ".service": "systemd",
    ".socket": "systemd",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".hcl": "terraform",
    ".xml": "xml",
    ".cnf": "config",
    ".env": "dotenv",
}
# Only rule IDs leave the process. No matched text, key names, values, or hashes.
PATTERNS = {
    "tls_disabled": re.compile(
        r"(?:\b(?:ssl_verify|verify_ssl|tls_verify|ssl|ssl_engine)\b"
        r"[\s\"']*[:= ]+[\s\"']*(?:false|off|0)\b|"
        r"\b(?:insecure|insecure_skip_verify|insecureSkipVerify)\b[\s\"']*[:=]+[\s\"']*true\b|"
        r"\bssl_protocols\s+[^;\n]*(?:SSLv[23]|TLSv1(?:\.0|\.1)?(?![.0-9])\b))",
        re.I,
    ),
    "debug_enabled": re.compile(
        r"\b(?:debug|debug_mode|app_debug)\b[\s\"']*[:=]+[\s\"']*(?:true|on|1)\b", re.I
    ),
    "wildcard_cors": re.compile(
        r"\b(?:access-control-allow-origin|allow_origins|allowed_origins|cors_allowed_origins)\b[^\n]{0,80}[\"']?\*[\"']?",
        re.I,
    ),
    "privileged_container": re.compile(r"\bprivileged\b[\s\"']*[:=]+[\s\"']*true\b", re.I),
    "public_listener": re.compile(
        r"(?:\b0\.0\.0\.0\b|\[::\]|\bhostNetwork\b[\s\"']*:\s*true\b)", re.I
    ),
}
SECRET = re.compile(
    r"(?:^|[\s\"'])(?:[a-z0-9_]*(?:password|passwd|secret|token|api_key|private_key|credential)[a-z0-9_]*)"
    r"[\s\"']*[:=]\s*([^\n]+)",
    re.I,
)


def _excluded_file(path: Path) -> bool:
    return path.name.lower() in SKIP_FILES or path.suffix.lower() in SKIP_SUFFIXES


def _format(path: Path) -> str | None:
    name = path.name.lower()
    if _excluded_file(path):
        return None
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return "dotenv"
    if name in {"dockerfile", "containerfile"} or name.startswith("dockerfile."):
        return "docker"
    if "nginx" in name:
        return "nginx"
    if name in {"httpd.conf", "apache2.conf", ".htaccess"}:
        return "apache"
    return FORMATS.get(path.suffix.lower())


XML_SECRET = re.compile(
    r"<(?:[a-z0-9_.-]+:)?[a-z0-9_.-]*(?:password|passwd|secret|token|api_key|credential)"
    r"[a-z0-9_.-]*\b[^>]*>\s*([^<]+)</",
    re.I,
)


def checks(text: str, mode: int) -> list[str]:
    """Heuristic warnings, not an application parser or proof of exploitability."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith(("#", ";", "//"))
    )
    result = [code for code, pattern in PATTERNS.items() if pattern.search(text)]
    if mode & stat.S_IWOTH:
        result.append("world_writable")
    for match in chain(SECRET.finditer(text), XML_SECRET.finditer(text)):
        value = match.group(1).strip().strip("\"' ,;")
        if (
            value
            and not value.startswith(("$", "{{", "<", "#"))
            and value.lower() not in {"null", "none", "false", "true", "redacted"}
        ):
            result.append("embedded_credentials")
            break
    return sorted(result)


def inspect(roots: list[str]) -> dict[str, Any]:
    if os.name == "nt":
        raise ValueError("configuration inspection currently requires POSIX safe file access")
    if not 1 <= len(roots) <= 8:
        raise ValueError("choose between one and eight configuration roots")
    files: list[dict[str, Any]] = []
    skipped = entries = read_bytes = 0
    complete = True
    for number, raw_root in enumerate(roots, 1):
        root = Path(raw_root).absolute()
        if root == Path("/") or root.is_symlink() or not root.is_dir():
            raise ValueError("choose a real configuration directory")
        if any(parent.is_symlink() for parent in root.parents):
            raise ValueError("configuration root cannot contain symlink parents")
        if root in {Path("/proc"), Path("/sys"), Path("/dev"), Path("/run")}:
            raise ValueError("virtual/system runtime roots cannot be inspected")

        def walk_error(error: OSError) -> None:
            nonlocal skipped, complete
            skipped += 1
            complete = False

        for directory, dirs, names, directory_fd in os.fwalk(
            root, follow_symlinks=False, onerror=walk_error
        ):
            relative = Path(directory).relative_to(root)
            excluded = {d for d in dirs if d in SKIP_DIRS or (Path(directory) / d).is_symlink()}
            if excluded:
                # An omitted directory can contain supported configuration.
                # Report that gap without opening it or counting its contents.
                skipped += len(excluded)
                complete = False
            dirs[:] = sorted(d for d in dirs if d not in excluded)
            if len(relative.parts) >= 12:
                if dirs:
                    complete = False
                    skipped += len(dirs)
                dirs[:] = []
            entries += len(dirs) + len(names)
            if entries > MAX_ENTRIES:
                complete = False
                skipped += 1
                break
            for name in sorted(names):
                format_name = _format(Path(name))
                if format_name is None:
                    if _excluded_file(Path(name)):
                        skipped += 1
                        complete = False
                    continue
                path = f"root-{number}/" + (relative / name).as_posix()
                if len(path) > 512 or len(files) >= MAX_FILES or read_bytes >= MAX_READ_BYTES:
                    skipped += 1
                    complete = False
                    continue
                fd = None
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_size > MAX_FILE_BYTES
                        or read_bytes + info.st_size > MAX_READ_BYTES
                    ):
                        raise ValueError("not a bounded regular file")
                    fd = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
                    )
                    opened = os.fstat(fd)
                    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                        info.st_dev,
                        info.st_ino,
                        info.st_size,
                        info.st_mtime_ns,
                    ):
                        raise ValueError("file changed during inspection")
                    with os.fdopen(fd, "rb") as stream:
                        fd = None
                        raw = stream.read(MAX_FILE_BYTES + 1)
                        final = os.fstat(stream.fileno())
                    if (
                        len(raw) > MAX_FILE_BYTES
                        or b"\x00" in raw
                        or (final.st_size, final.st_mtime_ns)
                        != (opened.st_size, opened.st_mtime_ns)
                    ):
                        raise ValueError("unreadable configuration")
                    text = raw.decode("utf-8")
                    read_bytes += len(raw)
                    files.append(
                        {
                            "path": path,
                            "format": format_name,
                            "size_bytes": len(raw),
                            "checks": checks(text, opened.st_mode),
                        }
                    )
                except (OSError, ValueError, UnicodeError):
                    skipped += 1
                    complete = False
                finally:
                    if fd is not None:
                        os.close(fd)
    result = {"files": files, "complete": complete, "skipped_files": min(skipped, 100000)}
    if len(json.dumps(result).encode()) > 400 * 1024:
        raise ValueError("configuration observations exceed upload limit")
    return result
