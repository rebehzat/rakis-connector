"""Device scans report signature names and counters, never content or hashes."""

import hashlib
import json
import os
import re

import httpx
import pytest

from acsc_cli import clamav, device
from acsc_cli.clamav import ClamavDatabase

SAMPLE = b"synthetic-malware-fixture"
PATH_PATTERN = re.compile(r"^root-[0-9]{1,2}/[^\x00-\x1f\\]+$")
SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:+-]{0,127}$")


def _refuse(*args, **kwargs):
    raise AssertionError("the device scan must not reach the network")


def _database(tmp_path, sample: bytes = SAMPLE) -> ClamavDatabase:
    """A cached signature database that holds one known sample."""
    directory = tmp_path / "cache"
    directory.mkdir(exist_ok=True)
    digest = hashlib.md5(sample).hexdigest()
    (directory / "daily.hdb").write_text(f"{digest}:{len(sample)}:Example.Malware.A\n")
    for name in ("daily.ndb", "main.hdb", "main.ndb"):
        (directory / name).write_text(f"Example:0:MD5,0,{'b' * 32}\n")
    return ClamavDatabase(directory, transport=httpx.MockTransport(_refuse))


def test_multiple_files_and_folders_are_scanned_with_relative_labels(tmp_path):
    first = tmp_path / "first"
    first.mkdir()
    (first / "clean.txt").write_text("nothing to see here")
    (first / "nested").mkdir()
    (first / "nested" / "bad.bin").write_bytes(SAMPLE)
    second = tmp_path / "second.txt"
    second.write_bytes(SAMPLE)
    database = _database(tmp_path)

    report = device.scan([str(first), str(second)], database)

    assert report["engine"] == "clamav"
    assert report["files_scanned"] == 3
    assert report["directories_scanned"] == 2
    assert report["skipped_files"] == 0
    assert report["complete"] is True
    assert sorted(item["path"] for item in report["detections"]) == [
        "root-1/nested/bad.bin",
        "root-2/second.txt",
    ]
    detection = report["detections"][0]
    assert detection["signature"] == "Example.Malware.A"
    assert detection["match_type"] == "hash"
    assert detection["size_bytes"] == len(SAMPLE)
    assert str(tmp_path) not in json.dumps(report)
    assert SAMPLE.decode() not in json.dumps(report)
    assert hashlib.md5(SAMPLE).hexdigest() not in json.dumps(report)


def test_the_report_matches_the_agent_contract(tmp_path):
    root = tmp_path / "chosen"
    root.mkdir()
    (root / "sample.bin").write_bytes(SAMPLE)
    database = _database(tmp_path)

    report = device.scan([str(root)], database)

    assert set(report) == {
        "engine",
        "signature_db",
        "files_scanned",
        "directories_scanned",
        "skipped_files",
        "complete",
        "detections",
    }
    assert set(report["signature_db"]) == {"version", "updated_at", "files"}
    assert 1 <= len(report["signature_db"]["version"]) <= 128
    assert report["signature_db"]["files"] == 4
    assert 0 <= report["files_scanned"] <= 10000000
    assert 0 <= report["directories_scanned"] <= 100000
    assert 0 <= report["skipped_files"] <= 1000000
    assert isinstance(report["complete"], bool)
    assert len(report["detections"]) <= 500
    for detection in report["detections"]:
        assert set(detection) == {"path", "signature", "match_type", "size_bytes"}
        assert PATH_PATTERN.fullmatch(detection["path"])
        assert SIGNATURE_PATTERN.fullmatch(detection["signature"])
        assert detection["match_type"] in {"hash", "nucleic"}
        assert 0 <= detection["size_bytes"] <= 1 << 40
        root_number = int(detection["path"].split("/", 1)[0].removeprefix("root-"))
        assert 1 <= root_number <= 16
        assert all(part not in {"", ".", ".."} for part in detection["path"].split("/"))


def test_links_and_system_roots_are_never_scanned(tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(SAMPLE)
    root = tmp_path / "chosen"
    root.mkdir()
    (root / "link.bin").symlink_to(outside)
    (root / "linked").symlink_to(tmp_path, target_is_directory=True)
    database = _database(tmp_path)

    report = device.scan([str(root)], database)

    assert report["files_scanned"] == 0
    assert report["detections"] == []
    assert report["skipped_files"] == 2
    assert report["complete"] is False


def test_the_filesystem_root_and_runtime_roots_are_refused(tmp_path):
    database = _database(tmp_path)
    for path in ("/", "/proc", "/sys", "/dev", "/run"):
        with pytest.raises(ValueError):
            device.scan([path], database)
    link = tmp_path / "link"
    link.symlink_to(tmp_path)
    with pytest.raises(ValueError):
        device.scan([str(link)], database)


def test_too_many_paths_are_refused(tmp_path):
    database = _database(tmp_path)
    with pytest.raises(ValueError):
        device.scan([str(tmp_path)] * 17, database)
    with pytest.raises(ValueError):
        device.scan([], database)


def test_a_file_that_cannot_be_read_is_skipped_without_content(tmp_path):
    root = tmp_path / "chosen"
    root.mkdir()
    secret = root / "unreadable.bin"
    secret.write_bytes(SAMPLE)
    secret.chmod(0o000)
    database = _database(tmp_path)
    try:
        report = device.scan([str(root)], database)
    finally:
        secret.chmod(0o600)
    assert report["files_scanned"] == 0
    assert report["detections"] == []
    assert report["complete"] is False
    assert secret.read_bytes() == SAMPLE


def test_a_special_file_is_skipped(tmp_path):
    root = tmp_path / "chosen"
    root.mkdir()
    os.mkfifo(root / "pipe")
    database = _database(tmp_path)
    report = device.scan([str(root)], database)
    assert report["files_scanned"] == 0
    assert report["skipped_files"] == 1
    assert report["complete"] is False


def test_the_detection_list_stays_within_its_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(device, "MAX_DETECTIONS", 1)
    root = tmp_path / "chosen"
    root.mkdir()
    (root / "one.bin").write_bytes(SAMPLE)
    (root / "two.bin").write_bytes(SAMPLE)
    database = _database(tmp_path)
    report = device.scan([str(root)], database)
    assert len(report["detections"]) == 1
    assert report["skipped_files"] == 1
    assert report["complete"] is False


def test_a_clean_server_reports_no_detection(tmp_path):
    root = tmp_path / "chosen"
    root.mkdir()
    (root / "readme.txt").write_text("nothing to see here")
    database = _database(tmp_path)
    report = device.scan([str(root)], database)
    assert report["detections"] == []
    assert report["files_scanned"] == 1
    assert report["complete"] is True


def test_the_scan_uses_the_cached_database_without_a_download(tmp_path):
    root = tmp_path / "chosen"
    root.mkdir()
    (root / "sample.bin").write_bytes(SAMPLE)
    database = _database(tmp_path)
    database.refresh()
    assert list((tmp_path / "cache").iterdir())
    assert clamav.SIGNATURE_FILES[0] in [path.name for path in (tmp_path / "cache").iterdir()]
