"""Release archives must match their explicit source and wheel inventories."""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.check_release_inventory import (
    InventoryError,
    check_sdist,
    check_wheel,
    release_artifacts,
)


def _sdist(path: Path, names: tuple[str, ...], body: bytes = b"content") -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name in names:
            member = tarfile.TarInfo(f"opentine-0.3.0/{name}")
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))


def _wheel(path: Path, names: tuple[str, ...], body: bytes = b"content") -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, body)


def test_sdist_inventory_rejects_untracked_local_state(tmp_path: Path):
    path = tmp_path / "opentine-0.3.0.tar.gz"
    expected = {"README.md"}
    _sdist(path, ("README.md", "PKG-INFO"))
    check_sdist(path, expected, "opentine", "0.3.0")

    _sdist(path, ("README.md", "PKG-INFO", ".claude/settings.local.json"))
    with pytest.raises(InventoryError, match=r"unexpected: \.claude/settings\.local\.json"):
        check_sdist(path, expected, "opentine", "0.3.0")


def test_wheel_inventory_is_package_only_and_exact(tmp_path: Path):
    path = tmp_path / "opentine-0.3.0-py3-none-any.whl"
    dist = "opentine-0.3.0.dist-info"
    generated = (
        f"{dist}/METADATA",
        f"{dist}/RECORD",
        f"{dist}/WHEEL",
        f"{dist}/entry_points.txt",
        f"{dist}/licenses/LICENSE",
    )
    _wheel(path, ("opentine/__init__.py", *generated))
    check_wheel(path, {"opentine/__init__.py", "tests/test_hidden.py"}, "opentine", "0.3.0")

    _wheel(path, ("opentine/__init__.py", "tests/test_hidden.py", *generated))
    with pytest.raises(InventoryError, match="unexpected: tests/test_hidden.py"):
        check_wheel(path, {"opentine/__init__.py"}, "opentine", "0.3.0")


def test_release_artifacts_accepts_a_directory_and_requires_the_pair(tmp_path: Path):
    wheel = tmp_path / "opentine-0.3.0-py3-none-any.whl"
    sdist = tmp_path / "opentine-0.3.0.tar.gz"
    wheel.touch()
    sdist.touch()
    assert release_artifacts([tmp_path]) == [sdist, wheel]

    second = tmp_path / "opentine-0.3.0-py3-none-win_amd64.whl"
    second.touch()
    with pytest.raises(InventoryError, match="exactly one wheel and one sdist"):
        release_artifacts([tmp_path])


def test_sdist_content_must_match_reviewed_source(tmp_path: Path):
    path = tmp_path / "opentine-0.3.0.tar.gz"
    expected = {"README.md"}
    reviewed = {"README.md": hashlib.sha256(b"content").digest()}
    _sdist(path, ("README.md", "PKG-INFO"))
    check_sdist(path, expected, "opentine", "0.3.0", source_hashes=reviewed)

    _sdist(path, ("README.md", "PKG-INFO"), b"altered")
    with pytest.raises(InventoryError, match="sdist content differs from source: README.md"):
        check_sdist(path, expected, "opentine", "0.3.0", source_hashes=reviewed)


def test_wheel_package_content_must_match_validated_sdist(tmp_path: Path):
    path = tmp_path / "opentine-0.3.0-py3-none-any.whl"
    dist = "opentine-0.3.0.dist-info"
    names = (
        "opentine/__init__.py",
        f"{dist}/METADATA",
        f"{dist}/RECORD",
        f"{dist}/WHEEL",
        f"{dist}/entry_points.txt",
        f"{dist}/licenses/LICENSE",
    )
    source = {"opentine/__init__.py": hashlib.sha256(b"content").digest()}
    tracked = {"opentine/__init__.py"}
    _wheel(path, names)
    check_wheel(path, tracked, "opentine", "0.3.0", sdist_hashes=source)

    _wheel(path, names, b"altered")
    with pytest.raises(
        InventoryError,
        match=r"wheel content differs from sdist: opentine/__init__\.py",
    ):
        check_wheel(path, tracked, "opentine", "0.3.0", sdist_hashes=source)
