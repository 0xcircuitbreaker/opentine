"""0.87 review: Python regions that reach across locked code, and non-regular files.

A region that leaves a bracket open or ends on a decorator changes what the
locked lines after it mean without changing their bytes; a FIFO or device under
the globs is never opened.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from opentine._regions import INVALID, compare, layout
from tests.test_087_regions_pin import tree  # noqa: F401 - the shared fixture

TWO = (
    "def check(x):\n"
    "    # EVOLVE-BLOCK-START\n"
    "    y = x\n"
    "    # EVOLVE-BLOCK-END\n"
    "    assert_safe(y)\n"
    "    # EVOLVE-BLOCK-START\n"
    "    z = y\n"
    "    # EVOLVE-BLOCK-END\n"
    "    return z\n"
)


def _codes(after: str, before: str = TWO) -> list[str]:
    pinned = {"a.py": layout("a.py", before.encode("utf-8"))}
    assert pinned["a.py"]["errors"] == []
    return [f["code"] for f in compare(pinned, {"a.py": layout("a.py", after.encode("utf-8"))})]


def test_a_region_that_leaves_a_bracket_open_over_locked_code_is_refused():
    after = TWO.replace("    y = x\n", "    y = x\n    _ = (lambda: (\n")
    after = after.replace("    z = y\n", "    ))\n    z = y\n")
    compile(after, "a.py", "exec")  # valid Python: assert_safe is never called
    assert INVALID in _codes(after)


def test_a_region_that_ends_on_a_decorator_over_locked_code_is_refused():
    before = (
        "# EVOLVE-BLOCK-START\n"
        "def helper():\n"
        "    return 1\n"
        "# EVOLVE-BLOCK-END\n"
        "def guard(x):\n"
        "    return x > 0\n"
    )
    after = before.replace("    return 1\n", "    return 1\n@lambda f: lambda x: True\n")
    compile(after, "a.py", "exec")  # valid Python: guard is replaced
    assert INVALID in _codes(after, before)


def test_a_marker_inside_an_open_bracket_is_never_pinned():
    text = "X = [\n    # EVOLVE-BLOCK-START\n    1,\n    # EVOLVE-BLOCK-END\n]\n"
    assert layout("a.py", text.encode("utf-8"))["errors"]


@pytest.mark.skipif(sys.platform == "win32" or not hasattr(os, "mkfifo"), reason="POSIX FIFO")
def test_a_fifo_under_the_globs_is_never_opened(tree, monkeypatch):  # noqa: F811
    from opentine._regions_pin import check
    from tests.regions_helpers import pin_regions

    pin_regions(tree)
    fifo = tree / "evolve" / "planted.py"
    os.mkfifo(fifo)
    seen: list[str] = []
    real = Path.read_bytes

    def read_bytes(self):
        seen.append(Path(self).name)
        assert Path(self) != fifo, "the FIFO was opened"
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    row = check(tree)
    assert "planted.py" not in seen
    assert [f["code"] for f in row["findings"]] == ["fail:region-file-added"]
