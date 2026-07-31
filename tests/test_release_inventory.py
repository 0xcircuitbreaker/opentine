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


def test_every_tracked_compat_fixture_is_force_included_in_the_sdist():
    """The compat fixtures live under a directory with its own .gitignore, which
    makes hatchling drop them from the sdist unless they are named in the sdist
    ``artifacts`` key — even though git tracks them. That gap would ship a
    release whose backwards-compat gate cannot run. Hold every tracked file
    under tests/fixtures/compat/ to the artifacts globs, so a future
    ``vX_Y_Z/`` fixture set added without the include is caught here rather
    than by a red CI leg."""
    import os
    import shutil
    import subprocess
    import tomllib

    import pathspec

    root = Path(__file__).resolve().parents[1]

    # The shipped suite must be green without git and from an unpacked sdist,
    # which has no .git (or is unpacked inside an unrelated repo, where git would
    # answer about the wrong tree). Enumerating the tracked set is only
    # meaningful from THIS checkout's root, so skip otherwise. CI always runs
    # from a real checkout, where this asserts for real.
    if shutil.which("git") is None:
        pytest.skip("git is required to enumerate tracked compat fixtures")
    top = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True
    )
    try:
        at_root = top.returncode == 0 and os.path.samefile(top.stdout.decode().strip(), root)
    except OSError:
        at_root = False
    if not at_root:
        pytest.skip("not this git checkout's root (unpacked sdist); CI validates from a checkout")

    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "tests/fixtures/compat"],
        capture_output=True,
    ).stdout
    # Only *.tine files are dropped: the repository fixture's non-.tine internals
    # (config.json, objects/*, refs/*) ship via the plain /tests include.
    tracked = [
        name for name in listed.decode("utf-8").split("\0") if name and name.endswith(".tine")
    ]
    assert tracked, "expected committed *.tine compat fixtures under tests/fixtures/compat/"

    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    artifacts = config["tool"]["hatch"]["build"]["targets"]["sdist"].get("artifacts", [])
    spec = pathspec.PathSpec.from_lines("gitwildmatch", artifacts)
    missing = [name for name in tracked if not spec.match_file(name)]
    assert not missing, (
        f"tracked .tine fixtures not force-included in [tool.hatch.build.targets.sdist] "
        f"artifacts, so they will be dropped from the sdist: {missing}"
    )
