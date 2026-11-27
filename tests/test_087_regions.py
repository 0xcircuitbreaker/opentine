"""0.87: EVOLVE-BLOCK region pins: only marked regions may change.

Hostile edits outside a region, moved, renamed, nested, unbalanced and
look-alike markers, markers inside strings, CRLF and Unicode normalisation,
added and removed files are each reported; an edit inside a region passes.
"""

from __future__ import annotations

import unicodedata

import pytest

from opentine._regions import ADDED, INVALID, OUTSIDE, REMOVED, compare, layout

BASE = (
    "import math\n"
    "\n"
    "# EVOLVE-BLOCK-START\n"
    "def heuristic(x):\n"
    "    return x * 2\n"
    "# EVOLVE-BLOCK-END\n"
    "\n"
    "def score(xs):\n"
    "    return sum(heuristic(x) for x in xs[-3:])\n"
)


def _codes(before: str, after: str, path: str = "algo.py") -> list[str]:
    pinned = {path: layout(path, before.encode("utf-8"))}
    assert pinned[path]["errors"] == []
    current = {path: layout(path, after.encode("utf-8"))}
    return [f["code"] for f in compare(pinned, current)]


def test_an_edit_inside_the_region_passes():
    after = BASE.replace("return x * 2", "return math.sqrt(x) + 1\n    # tuned")
    assert _codes(BASE, after) == []


@pytest.mark.parametrize(
    "edit",
    [
        ("xs[-3:]", "xs"),  # the slice drop outside the region
        ("import math\n", "import math\nimport os\n"),
        ("def score(xs):\n", "def score(xs):  # noqa\n"),
        ("    return sum", "\treturn sum"),
    ],
)
def test_an_edit_outside_the_region_is_refused(edit):
    assert _codes(BASE, BASE.replace(*edit)) == [OUTSIDE]


def test_moving_a_marker_moves_a_locked_line():
    up = BASE.replace("\n# EVOLVE-BLOCK-START\n", "# EVOLVE-BLOCK-START\n\n")
    down = BASE.replace("# EVOLVE-BLOCK-END\n\ndef score", "\n# EVOLVE-BLOCK-END\ndef score")
    swallow = BASE.replace("# EVOLVE-BLOCK-END\n\ndef score(xs):\n",
                           "\ndef score(xs):\n# EVOLVE-BLOCK-END\n")  # fmt: skip
    for after in (up, down, swallow):
        assert OUTSIDE in _codes(BASE, after)


def test_text_carried_across_the_region_is_an_edit():
    after = BASE.replace("import math\n\n", "").replace("def score", "import math\n\ndef score")
    assert set(_codes(BASE, after)) == {OUTSIDE}


@pytest.mark.parametrize(
    "after",
    [
        BASE.replace("# EVOLVE-BLOCK-END\n", ""),  # unbalanced: never closed
        BASE.replace("# EVOLVE-BLOCK-START\n", ""),  # an END with no START
        BASE.replace("    return x * 2\n", "# EVOLVE-BLOCK-START\n    return x * 2\n"),
        BASE.replace("EVOLVE-BLOCK-END", "EVOLVE-BLOCK-STOP"),  # renamed
        BASE.replace("EVOLVE-BLOCK-START", "evolve-block-start"),  # case
        BASE.replace("EVOLVE-BLOCK-START", "EVOLVE‐BLOCK‐START"),  # Unicode hyphen
        BASE.replace("EVOLVE-BLOCK-END", "\uff25\uff36\uff2f\uff2c\uff36\uff25-BLOCK-END"),
        BASE.replace("# EVOLVE-BLOCK-START\n", "x = 1  # EVOLVE-BLOCK-START\n"),  # trailing
        BASE.replace("# EVOLVE-BLOCK-START\n", "# EVOLVE-BLOCK-START\r# hidden\n"),  # lone CR
        BASE.replace("# EVOLVE-BLOCK-END\n", 'S = """\n# EVOLVE-BLOCK-END\n"""\n'),  # in a string
    ],
)
def test_marker_tampering_is_refused(after):
    assert INVALID in _codes(BASE, after)


def test_an_extra_region_is_refused():
    after = BASE.replace("def score(xs):\n",
                         "# EVOLVE-BLOCK-START\n# EVOLVE-BLOCK-END\ndef score(xs):\n")  # fmt: skip
    assert _codes(BASE, after) == [INVALID]


def test_a_marker_in_a_python_string_never_counts_at_the_baseline():
    text = 'S = """\n# EVOLVE-BLOCK-START\n"""\n# EVOLVE-BLOCK-START\nx = 1\n# EVOLVE-BLOCK-END\n'
    assert any("inside a string" in e for e in layout("m.py", text.encode())["errors"])
    assert layout("m.txt", text.encode())["errors"]  # line-based: a second START is nested


def test_crlf_and_unicode_normalisation_outside_are_edits():
    assert _codes(BASE, BASE.replace("\n", "\r\n")) == [OUTSIDE, OUTSIDE]
    crlf = BASE.replace("\n", "\r\n")
    assert _codes(crlf, crlf.replace("return x * 2", "return x")) == []
    named = BASE.replace("import math", "café = 1")
    nfd = unicodedata.normalize("NFD", named)
    assert nfd != named and _codes(named, nfd) == [OUTSIDE]


def test_block_comment_markers_and_a_bom_are_markers():
    text = "﻿/* EVOLVE-BLOCK-START */\nint x;\n<!-- EVOLVE-BLOCK-END -->\nint y;\n"
    row = layout("a.c", text.encode("utf-8"))
    assert row["errors"] == [] and row["regions"] == 1
    assert _codes(text, text.replace("int x;", "int z;"), "a.c") == []
    assert _codes(text, text.replace("int y;", "int z;"), "a.c") == [OUTSIDE]


def test_a_binary_file_is_one_locked_segment():
    pinned = {"b.bin": layout("b.bin", b"\xff\xfe# EVOLVE-BLOCK-START\n")}
    assert pinned["b.bin"]["regions"] == 0
    found = compare(pinned, {"b.bin": layout("b.bin", b"\xff\xfd# EVOLVE-BLOCK-START\n")})
    assert [f["code"] for f in found] == [OUTSIDE]


def test_files_added_and_removed():
    pinned = {"a.py": layout("a.py", b"x = 1\n")}
    found = compare(pinned, {"b.py": layout("b.py", b"x = 1\n")})
    assert [(f["code"], f["path"]) for f in found] == [(REMOVED, "a.py"), (ADDED, "b.py")]
