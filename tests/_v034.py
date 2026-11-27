"""The 0.34 package tree, for the reader-compat tests that run the 0.34 code itself.

``git archive v0.34.0 opentine`` from this checkout. CI's test job fetches the
tag (the default checkout is shallow and has no tags); elsewhere a checkout
without it skips the test instead of failing it.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def v034(tmp_path: Path) -> Path:
    """Extract opentine at v0.34.0 under *tmp_path* and return the directory holding it."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    try:
        archive = subprocess.run(
            ["git", "-C", str(ROOT), "archive", "v0.34.0", "opentine"],
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("tag v0.34.0 is not available in this checkout")
    dest = tmp_path / "v034"
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")
    return dest
