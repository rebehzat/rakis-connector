"""The local signature database stays private and never trusts a download."""

import hashlib
import os
import re
import stat
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from acsc_cli import clamav
from acsc_cli.clamav import (
    ClamavDatabase,
    ClamavError,
    Match,
    SignatureIndex,
    parse_hdb,
    parse_ndb,
)

SAMPLE = b"synthetic-malware-fixture"


def _hdb(digest: str, size: int, name: str = "Example.Malware.A") -> str:
    return f"{digest}:{size}:{name}\n"


def _ndb(name: str = "Example") -> str:
    return f"{name}:0:MD5,0,{'b' * 32}\n"


def _stream(content: bytes):
    import io

    return io.BytesIO(content)


def _refuse(*args, **kwargs):
    raise AssertionError("the signature database must not reach the network")


def _database(tmp_path, content: dict[str, str], *, stale: bool = False, handler=_refuse):
    directory = tmp_path / "cache"
    directory.mkdir(exist_ok=True)
    for name in clamav.SIGNATURE_FILES:
        default = _ndb() if name.endswith("ndb") else _hdb("a" * 32, 3)
        (directory / name).write_text(content.get(name, default))
    if stale:
        old = datetime.now(UTC) - timedelta(hours=48)
        stamp = old.timestamp()
        for name in clamav.SIGNATURE_FILES:
            os.utime(directory / name, (stamp, stamp))
    return ClamavDatabase(directory, transport=httpx.MockTransport(handler))


def test_hash_lines_are_parsed_by_digest():
    digest = "a" * 32
    index = parse_hdb(f"# a comment\n\n{digest}:12:Example.Malware.A\n")
    assert list(index) == [digest]
    assert index[digest][0].name == "Example.Malware.A"
    assert index[digest][0].size == 12


def test_ndb_lines_are_parsed_into_sections():
    whole = parse_ndb(f"Example:0:MD5,1024,{'b' * 32}\n")
    assert whole[0].algorithm == "md5" and whole[0].offset == 1024
    section = parse_ndb(f"Example:0:Hash:0:*,2048,{'c' * 32}\n")
    assert section[0].algorithm == "md5" and section[0].offset == 2048
    assert parse_ndb(f"Example:0:PE,0,{'d' * 32}\n") == []
    assert parse_ndb(f"Example:1:MD5,0,{'b' * 32}\n") == []


def test_a_whole_file_hash_match_is_reported_as_a_hash(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE)
    digest = hashlib.md5(SAMPLE).hexdigest()
    index = SignatureIndex(parse_hdb(_hdb(digest, len(SAMPLE))), [])
    with sample.open("rb") as stream:
        matches = index.match(stream, len(SAMPLE))
    assert matches == [Match(signature="Example.Malware.A", match_type="hash")]


def test_a_section_hash_match_is_reported_as_a_nucleic_match(tmp_path):
    content = b"prefix" + SAMPLE + b"suffix"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(content)
    offset = len(b"prefix")
    digest = hashlib.md5(content[offset:]).hexdigest()
    index = SignatureIndex({}, parse_ndb(f"Example:0:MD5,{offset},{digest}\n"))
    with sample.open("rb") as stream:
        matches = index.match(stream, len(content))
    assert matches == [Match(signature="Example", match_type="nucleic")]


def test_a_clean_file_has_no_match(tmp_path):
    sample = tmp_path / "clean.bin"
    sample.write_bytes(b"nothing to see here")
    index = SignatureIndex(parse_hdb(_hdb("a" * 32, 4)), [])
    with sample.open("rb") as stream:
        assert index.match(stream, 19) == []


def test_signature_files_are_downloaded_into_a_private_cache(tmp_path):
    requests = []

    def handler(request):
        requests.append(request.url.path)
        name = request.url.path.rsplit("/", 1)[-1]
        body = _hdb(hashlib.md5(name.encode()).hexdigest(), 3) if name.endswith("hdb") else _ndb()
        return httpx.Response(200, content=body, headers={"Content-Length": str(len(body))})

    directory = tmp_path / "cache"
    database = ClamavDatabase(directory, transport=httpx.MockTransport(handler))
    database.refresh()
    assert sorted(requests) == ["/daily.hdb", "/daily.ndb", "/main.hdb", "/main.ndb"]
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for name in clamav.SIGNATURE_FILES:
        assert stat.S_IMODE((directory / name).stat().st_mode) == 0o600
    status = database.status()
    assert status["files"] == 4
    assert re.fullmatch(r"(daily|main)\.(hdb|ndb)@\d{4}-\d{2}-\d{2}", status["version"])
    assert status["updated_at"].endswith("Z")
    database.close()


def test_the_signature_database_is_refreshed_at_most_once_a_day(tmp_path):
    requests = []

    def handler(request):
        requests.append(request.url.path)
        name = request.url.path.rsplit("/", 1)[-1]
        body = _hdb("a" * 32, 3) if name.endswith("hdb") else _ndb()
        return httpx.Response(200, content=body)

    database = ClamavDatabase(tmp_path / "cache", transport=httpx.MockTransport(handler))
    database.refresh()
    database.refresh()
    assert len(requests) == 4
    stamp = (datetime.now(UTC) - timedelta(hours=48)).timestamp()
    for name in clamav.SIGNATURE_FILES:
        os.utime(tmp_path / "cache" / name, (stamp, stamp))
    database.refresh()
    assert len(requests) == 8
    database.close()


def test_a_download_that_is_not_a_signature_file_keeps_the_cached_copy(tmp_path):
    digest = hashlib.md5(SAMPLE).hexdigest()
    database = _database(
        tmp_path,
        {"daily.hdb": _hdb(digest, len(SAMPLE))},
        handler=lambda request: httpx.Response(200, content="not a signature file\n"),
    )
    cached = (tmp_path / "cache" / "daily.hdb").read_text()
    database.refresh(force=True)
    assert (tmp_path / "cache" / "daily.hdb").read_text() == cached
    assert database.index().match(_stream(SAMPLE), len(SAMPLE)) == [
        Match(signature="Example.Malware.A", match_type="hash")
    ]


def test_a_failed_download_without_a_cached_copy_is_refused(tmp_path):
    def handler(request):
        return httpx.Response(503)

    database = ClamavDatabase(tmp_path / "cache", transport=httpx.MockTransport(handler))
    with pytest.raises(ClamavError):
        database.refresh()
    database.close()


def test_an_oversized_signature_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(clamav, "MAX_FILE_BYTES", 64)
    database = ClamavDatabase(
        tmp_path / "cache",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=_hdb("a" * 32, 3) * 10)
        ),
    )
    with pytest.raises(ClamavError):
        database.refresh()
    database.close()


def test_a_symlinked_cache_directory_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    database = ClamavDatabase(link, transport=httpx.MockTransport(_refuse))
    with pytest.raises(ClamavError):
        database.refresh()
    database.close()


def test_a_symlinked_cache_file_is_never_written_through(tmp_path):
    other = tmp_path / "other"
    other.write_text("untouched")
    directory = tmp_path / "cache"
    directory.mkdir()
    link = directory / "daily.hdb"
    link.symlink_to(other)

    def handler(request):
        name = request.url.path.rsplit("/", 1)[-1]
        body = _hdb("a" * 32, 3) if name.endswith("hdb") else _ndb()
        return httpx.Response(200, content=body)

    database = ClamavDatabase(directory, transport=httpx.MockTransport(handler))
    database.refresh(force=True)
    assert other.read_text() == "untouched"
    assert not link.is_symlink()
    database.close()
