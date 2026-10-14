"""Passive config inspection never transmits secret values or raw source."""

import json
import os

import pytest

from acsc_cli.configuration import checks, inspect


@pytest.mark.parametrize(
    "filename,content,expected",
    [
        (
            ".env",
            "APP_DEBUG=true\nPASSWORD=private-fixture-password\nNORMAL_ENV=private-normal-value",
            ["debug_enabled", "embedded_credentials"],
        ),
        ("service.yaml", "securityContext:\n  privileged: true\n", ["privileged_container"]),
        ("app.json", '{"debug":true,"allow_origins":["*"]}', ["debug_enabled", "wildcard_cors"]),
        (
            "app.toml",
            'ssl_verify = false\napi_key = "private-fixture-key"',
            ["embedded_credentials", "tls_disabled"],
        ),
        ("app.ini", "listen=0.0.0.0\n", ["public_listener"]),
        ("nginx.conf", "ssl off;\n", ["tls_disabled"]),
        ("docker-compose.yml", "privileged: true\n", ["privileged_container"]),
        ("main.tf", "insecure = true\n", ["tls_disabled"]),
        ("app.service", "Environment=APP_DEBUG=true\n", ["debug_enabled"]),
        ("app.xml", "<password>private-fixture-value</password>", ["embedded_credentials"]),
    ],
)
def test_formats_rules_and_total_value_omission(tmp_path, filename, content, expected):
    root = tmp_path / "config"
    root.mkdir()
    source = root / filename
    source.write_text(content)
    source.chmod(0o600)
    before = source.read_bytes()
    result = inspect([str(root)])
    assert result["complete"] and result["skipped_files"] == 0
    assert result["files"][0]["checks"] == expected
    assert result["files"][0]["path"] == "root-1/" + filename
    payload = json.dumps(result)
    assert "private-fixture" not in payload and "private-normal-value" not in payload
    assert str(root) not in payload
    assert source.read_bytes() == before
    assert set(result["files"][0]) == {"path", "format", "size_bytes", "checks"}


def test_environment_references_are_not_reported_as_embedded_secrets():
    assert checks('PASSWORD="${SECRET_STORE_PASSWORD}"\napi_key = $TOKEN', 0o600) == []
    assert checks("password=''\n", 0o600) == []


def test_links_hardlinks_binary_keys_and_oversized_files_are_not_read(tmp_path):
    root = tmp_path / "config"
    root.mkdir()
    outside = tmp_path / "outside.env"
    outside.write_text("PASSWORD=private-fixture")
    (root / "linked.env").symlink_to(outside)
    os.link(outside, root / "hardlinked.env")
    (root / "binary.conf").write_bytes(b"\x00secret")
    (root / "large.conf").write_bytes(b"x" * (256 * 1024 + 1))
    (root / "private.pem").write_text("private-fixture")
    (root / "linked-dir").symlink_to(tmp_path / "other")
    result = inspect([str(root)])
    assert not result["complete"]
    assert result["skipped_files"] >= 4 and result["files"] == []
    assert "private-fixture" not in json.dumps(result)


def test_excluded_directories_and_private_files_make_coverage_partial_without_reading(
    tmp_path, monkeypatch
):
    root = tmp_path / "config"
    root.mkdir()
    excluded = root / "vendor"
    excluded.mkdir()
    (excluded / "service.yml").write_text("password: synthetic-excluded-secret\n")
    (root / "private.pem").write_text("synthetic-private-key\n")
    original_open = os.open

    def safe_open(path, flags, *args, **kwargs):
        assert str(path) not in {"service.yml", "private.pem"}, "Excluded content must stay unread"
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", safe_open)
    result = inspect([str(root)])
    assert result == {"files": [], "complete": False, "skipped_files": 2}
    assert "synthetic" not in json.dumps(result)


def test_exclusions_do_not_hide_an_observation_in_an_allowed_folder(tmp_path):
    root = tmp_path / "config"
    root.mkdir()
    (root / ".ssh").mkdir()
    (root / "service.yaml").write_text("debug: true\n")
    result = inspect([str(root)])
    assert result["complete"] is False and result["skipped_files"] == 1
    assert result["files"][0]["checks"] == ["debug_enabled"]


def test_permissions_and_bounded_file_count(tmp_path):
    root = tmp_path / "config"
    root.mkdir()
    for number in range(251):
        source = root / f"file{number:03}.ini"
        source.write_text("debug=false")
        source.chmod(0o666)
    result = inspect([str(root)])
    assert len(result["files"]) == 250
    assert not result["complete"] and result["skipped_files"] == 1
    assert all(file["checks"] == ["world_writable"] for file in result["files"])


def test_root_must_be_explicit_and_real(tmp_path):
    for roots in ([], ["/"], ["/proc"], [str(tmp_path / "missing")], [str(tmp_path)] * 9):
        with pytest.raises(ValueError):
            inspect(roots)
    link = tmp_path / "link"
    link.symlink_to(tmp_path)
    with pytest.raises(ValueError):
        inspect([str(link)])


@pytest.mark.parametrize("protocols", ["TLSv1.2", "TLSv1.3", "TLSv1.2 TLSv1.3"])
def test_modern_tls_protocols_are_not_reported_as_legacy(protocols):
    assert checks(f"ssl_protocols {protocols};", 0o600) == []


@pytest.mark.parametrize("protocols", ["TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2 TLSv1.1", "SSLv3"])
def test_legacy_tls_protocols_are_reported(protocols):
    assert checks(f"ssl_protocols {protocols};", 0o600) == ["tls_disabled"]


def test_comment_only_configuration_is_not_reported():
    text = (
        "# debug=true\n; password=private-fixture\n// privileged: true\n"
        "<!-- <password>private-fixture</password> -->\n"
    )
    assert checks(text, 0o600) == []
