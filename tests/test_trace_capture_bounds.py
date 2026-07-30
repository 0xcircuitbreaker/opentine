"""Code-state capture is bounded and honest about uncaptured files."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from opentine.trace import capture

# ``tests`` ships inside the sdist, and _repository() below builds its fixture by
# shelling git with check=True.  Without this guard the three tests here ERROR with
# FileNotFoundError('git') in any build environment that has no git binary (a
# redistributor validating opentine-0.3.0.tar.gz), reporting a missing tool as a
# capture defect.  CI always has git, so the coverage is never lost there --
# tests/test_release_audit_round11_misc.py asserts this mark is inert in a checkout.
pytestmark = pytest.mark.skipif(
    shutil.which("git") is None,
    reason="git is required to build the fixture repository these bounds are measured on",
)


def _repository(path: Path) -> None:
    subprocess.run(["git", "init", "-q", path], check=True)
    (path / "tracked.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", path, "add", "tracked.txt"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            path,
            "-c",
            "user.name=OpenTine Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "base",
        ],
        check=True,
    )


def test_code_manifest_marks_untracked_only_worktree_incomplete(tmp_path: Path):
    _repository(tmp_path)
    (tmp_path / "untracked.txt").write_text("not captured\n", encoding="utf-8")

    manifest = capture.code_manifest(tmp_path)

    assert manifest["dirty"] is True
    assert manifest["capture_complete"] is False
    assert manifest["untracked_files"] == ["untracked.txt"]
    assert "contents are not captured" in manifest["capture_errors"]["untracked"]


def test_code_manifest_refuses_an_oversized_patch(monkeypatch, tmp_path: Path):
    _repository(tmp_path)
    (tmp_path / "tracked.txt").write_text("x" * 1_000, encoding="utf-8")
    monkeypatch.setattr(capture, "MAX_GIT_CAPTURE_BYTES", 64)

    manifest = capture.code_manifest(tmp_path)

    assert manifest["dirty"] is True
    assert manifest["capture_complete"] is False
    assert manifest["patch"] == ""
    assert "output exceeds 64 bytes" in manifest["capture_errors"]["patch"]


def test_code_manifest_never_calls_failed_status_capture_clean(monkeypatch, tmp_path: Path):
    def failed_status(root, *arguments):
        del root
        return ("", "status failed") if arguments[0] == "status" else ("", None)

    monkeypatch.setattr(capture, "_git", failed_status)
    manifest = capture.code_manifest(tmp_path)
    assert manifest["capture_complete"] is False
    assert manifest["dirty"] is True
