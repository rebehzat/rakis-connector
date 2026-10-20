"""The local signature database stays private and never trusts a download."""

import hashlib
import os
import re
import stat
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import build_container, container_handler, hash_entry, write_cache

from acsc_cli import clamav
from acsc_cli.clamav import ClamavDatabase, ClamavError, Match, SignatureIndex

SAMPLE = b"synthetic-malware-fixture"
DIGEST = hashlib.md5(SAMPLE).hexdigest()


def _stream(content: bytes):
    import io

    return io.BytesIO(content)


def _refuse(*args, **kwargs):
    raise AssertionError("the signature database must not reach the network")


def _database(tmp_path, handler=_refuse, **kwargs):
    return ClamavDatabase(tmp_path / "cache", transport=httpx.MockTransport(handler), **kwargs)


def test_hash_lines_are_parsed_by_digest():
    index = clamav.parse_hashes(f"# a comment\n\n{DIGEST}:12:Example.Malware.A\n")
    assert list(index) == [DIGEST]
    assert index[DIGEST][0].name == "Example.Malware.A"
    assert index[DIGEST][0].size == 12


def test_a_whole_file_hash_match_is_reported(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE)
    directory = write_cache(tmp_path / "cache", {"daily.hdb": hash_entry(DIGEST, len(SAMPLE))})
    index = SignatureIndex(directory / "hashes.idx")
    with sample.open("rb") as stream:
        matches = index.match(stream, len(SAMPLE))
    assert matches == [Match(signature="Example.Malware.A", match_type="hash")]
    index.close()


def test_a_signature_of_another_size_does_not_match(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE)
    directory = write_cache(tmp_path / "cache", {"daily.hdb": hash_entry(DIGEST, len(SAMPLE) + 1)})
    index = SignatureIndex(directory / "hashes.idx")
    with sample.open("rb") as stream:
        assert index.match(stream, len(SAMPLE)) == []
    index.close()


def test_a_clean_file_has_no_match(tmp_path):
    sample = tmp_path / "clean.bin"
    sample.write_bytes(b"nothing to see here")
    directory = write_cache(tmp_path / "cache", {"daily.hdb": hash_entry("a" * 32, 4)})
    index = SignatureIndex(directory / "hashes.idx")
    with sample.open("rb") as stream:
        assert index.match(stream, 19) == []
    index.close()


def test_the_container_is_downloaded_into_a_private_cache(tmp_path):
    requests: list[str] = []
    handler = container_handler(
        {"daily.hdb": hash_entry(DIGEST, len(SAMPLE)), "daily.ndb": "not a hash file\n"},
        requests=requests,
    )
    directory = tmp_path / "cache"
    database = _database(tmp_path, handler)
    database.refresh()
    assert requests == ["/daily.cvd", "/main.cvd"]
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert (directory / "daily.hdb").exists()
    assert stat.S_IMODE((directory / "daily.hdb").stat().st_mode) == 0o600
    assert stat.S_IMODE((directory / "hashes.idx").stat().st_mode) == 0o600
    status = database.status()
    assert status["files"] == 2
    assert re.fullmatch(
        r"daily\.cvd@\d{4}-\d{2}-\d{2}\+main\.cvd@\d{4}-\d{2}-\d{2}", status["version"]
    )
    assert status["updated_at"].startswith("2026-10-20T06:24:00")
    database.close()


def test_the_download_identifies_the_connector(tmp_path):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("user-agent", ""))
        return httpx.Response(404)

    database = _database(tmp_path, handler)
    with pytest.raises(ClamavError):
        database.refresh()
    assert seen and all(value.startswith("ClamAV/") for value in seen)
    database.close()


def test_the_signature_database_is_refreshed_at_most_once_a_day(tmp_path):
    requests: list[str] = []
    handler = container_handler({"daily.hdb": hash_entry(DIGEST, len(SAMPLE))}, requests=requests)
    database = _database(tmp_path, handler)
    database.refresh()
    database.refresh()
    assert len(requests) == 2
    metadata = tmp_path / "cache" / "database.json"
    stamp = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
    metadata.write_text(metadata.read_text().replace('"downloaded_at":', '"downloaded_at":'))
    import json

    value = json.loads(metadata.read_text())
    value["downloaded_at"] = stamp
    metadata.write_text(json.dumps(value))
    database.refresh()
    assert len(requests) == 4
    database.close()


def test_a_container_that_does_not_match_its_digest_is_refused(tmp_path):
    digest = hashlib.md5(b"something else").hexdigest()
    handler = container_handler({"daily.hdb": hash_entry(DIGEST, len(SAMPLE))}, digest=digest)
    directory = tmp_path / "cache"
    database = _database(tmp_path, handler)
    with pytest.raises(ClamavError):
        database.refresh()
    assert not (directory / "daily.hdb").exists()
    database.close()


def test_a_failed_download_without_a_cached_copy_is_refused(tmp_path):
    database = _database(tmp_path, lambda request: httpx.Response(503))
    with pytest.raises(ClamavError):
        database.refresh()
    database.close()


def test_a_failed_download_keeps_the_cached_copy(tmp_path):
    directory = write_cache(tmp_path / "cache", {"daily.hdb": hash_entry(DIGEST, len(SAMPLE))})
    cached = (directory / "daily.hdb").read_text()
    database = _database(tmp_path, lambda request: httpx.Response(503))
    database.refresh(force=True)
    assert (directory / "daily.hdb").read_text() == cached
    index = database.index()
    assert index.match(_stream(SAMPLE), len(SAMPLE)) == [
        Match(signature="Example.Malware.A", match_type="hash")
    ]
    index.close()
    database.close()


def test_a_refreshed_database_replaces_the_open_lookup_index(tmp_path):
    directory = write_cache(tmp_path / "cache", {"daily.hdb": hash_entry("a" * 32, 4)})
    database = ClamavDatabase(
        directory,
        containers=("daily.cvd",),
        transport=httpx.MockTransport(
            container_handler({"daily.hdb": hash_entry(DIGEST, len(SAMPLE))})
        ),
    )
    try:
        assert database.index().match(_stream(SAMPLE), len(SAMPLE)) == []
        database.refresh(force=True)
        assert database.index().match(_stream(SAMPLE), len(SAMPLE)) == [
            Match(signature="Example.Malware.A", match_type="hash")
        ]
    finally:
        database.close()


def test_an_oversized_container_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(clamav, "MAX_CONTAINER_BYTES", 64)
    database = _database(
        tmp_path,
        container_handler({"daily.hdb": hash_entry(DIGEST, len(SAMPLE))}),
    )
    with pytest.raises(ClamavError):
        database.refresh()
    database.close()


def test_a_symlinked_cache_directory_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    database = _database(tmp_path, _refuse)
    database.directory = link
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
    handler = container_handler({"daily.hdb": hash_entry(DIGEST, len(SAMPLE))})
    database = _database(tmp_path, handler)
    database.refresh()
    assert other.read_text() == "untouched"
    assert not link.is_symlink()
    database.close()


def test_the_daily_container_can_be_used_alone(tmp_path):
    requests: list[str] = []
    handler = container_handler({"daily.hdb": hash_entry(DIGEST, len(SAMPLE))}, requests=requests)
    database = _database(tmp_path, handler, containers=("daily.cvd",))
    database.refresh()
    assert requests == ["/daily.cvd"]
    database.close()


def test_a_container_without_a_hash_database_is_refused(tmp_path):
    handler = container_handler({"daily.info": "daily.hdb:1:abc\n"})
    database = _database(tmp_path, handler)
    with pytest.raises(ClamavError):
        database.refresh()
    database.close()


def test_the_header_digest_covers_the_whole_payload():
    container = build_container({"daily.hdb": hash_entry(DIGEST, len(SAMPLE))})
    header = container[:512].decode("ascii")
    digest = [field for field in header.split(":") if re.fullmatch(r"[0-9a-f]{32}", field)]
    assert digest == [hashlib.md5(container[512:]).hexdigest()]
    assert os.path.isfile("pyproject.toml")
