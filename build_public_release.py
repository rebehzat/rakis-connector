"""Build and audit standalone connector artifacts without publishing them."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path


def build() -> Path:
    source = Path(__file__).resolve().parent
    target = source / "dist"
    project = tomllib.loads((source / "pyproject.toml").read_text())["project"]
    with tempfile.TemporaryDirectory(prefix="rakis-public-release-") as directory:
        stage = Path(directory) / "connector"
        stage.mkdir()
        for filename in ("pyproject.toml", "README.md"):
            shutil.copy2(source / filename, stage / filename)
        shutil.copytree(
            source / "acsc_cli",
            stage / "acsc_cli",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        wheels = Path(directory) / "wheels"
        subprocess.run(  # noqa: S603 - fixed build invocation; no user-supplied executable
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--no-cache-dir",
                "--wheel-dir",
                str(wheels),
                str(stage),
            ],
            env={**os.environ, "SOURCE_DATE_EPOCH": "315532800"},
            check=True,
        )
        (wheel,) = wheels.glob("rakis_connector-*.whl")
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if not name.startswith(
                    ("acsc_cli/", f"rakis_connector-{project['version']}.dist-info/")
                ):
                    raise ValueError("Unexpected file in public connector wheel")
                if name.endswith((".env", ".pyc")) or "sarif" in name:
                    raise ValueError("Unexpected private file in public connector wheel")
        target.mkdir(parents=True, exist_ok=True)
        result = target / wheel.name
        shutil.copy2(wheel, result)
    digest = hashlib.sha256(result.read_bytes()).hexdigest()
    result.with_suffix(result.suffix + ".sha256").write_text(f"{digest}  {result.name}\n")
    (target / "connector-release.json").write_text(
        json.dumps(
            {
                "version": project["version"],
                "filename": result.name,
                "sha256": digest,
                "requires_python": project["requires-python"],
                "commands": [
                    "connect",
                    "run",
                    "background",
                    "scan",
                    "device",
                    "status",
                    "disconnect",
                ],
            },
            indent=2,
        )
        + "\n"
    )
    return result


if __name__ == "__main__":
    print(build())
