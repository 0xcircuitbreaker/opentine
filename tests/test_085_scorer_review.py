"""0.85 review: isolation escapes and a closure that does not trust the child's report."""

from __future__ import annotations

import sys

import pytest

from opentine._scorer_isolated import LIMITS, ScorerRefused, run_child
from tests.scorer_isolation_helpers import isolated_eval, room, run_json, scorer

pytestmark = pytest.mark.filterwarnings("ignore:.*plaintext-hex private key")
__all__ = ["room"]

FORGE = """import json, os, sys
import helper


def score(output, item):
    frame = sys._getframe(1)
    while frame is not None and "request" not in frame.f_locals:
        frame = frame.f_back
    local = frame.f_locals
    report = {"scores": [1.0] * len(local["request"]["pairs"]), "error": None,
              "breaches": [], "modules": {}, "data": [], "network": "namespace",
              "limits": True}
    local["out"].write(local["request"]["nonce"] + json.dumps(report) + "\\n")
    local["out"].flush()
    os._exit(0)
"""

ESCAPES = {
    "spawn": "import _posixsubprocess, os\n\ndef score(output, item):\n"
    "    r, w = os.pipe()\n    _posixsubprocess.fork_exec([b'/bin/sh', b'-c', b'touch MARK'],"
    " [b'/bin/sh'], True, (), None, None, -1, -1, -1, -1, -1, -1, r, w, False, False, -1,"
    " None, None, None, -1, None, True)\n    return 1\n",
    "sqlite": "import sqlite3\n\ndef score(output, item):\n"
    "    sqlite3.connect(MARK).execute('create table t(x)')\n    return 1\n",
    "symlink": "import os\n\ndef score(output, item):\n    os.symlink(__file__, MARK)\n"
    "    return 1\n",
    "hardlink": "import os\n\ndef score(output, item):\n    os.link(__file__, MARK)\n"
    "    return 1\n",
    "utime": "import os\n\ndef score(output, item):\n    os.utime(__file__, (0, 0))\n"
    "    return 1\n",
    "fifo": "import os\n\ndef score(output, item):\n    os.mkfifo(MARK)\n    return 1\n",
    "interpreters": "def score(output, item):\n    import _interpreters\n    return 1\n",
}


@pytest.mark.parametrize("name", sorted(ESCAPES))
def test_an_unaudited_escape_is_refused_and_leaves_nothing(room, name):
    if sys.platform == "win32" and name in ("spawn", "fifo"):
        pytest.skip("a POSIX-only call")
    mark = (room / "out" / "MARK").as_posix()
    (room / "out").mkdir()
    body = ESCAPES[name].replace("MARK", repr(mark) if name != "spawn" else mark)
    spec = scorer(room, name, f"MARK = {mark!r}\n" + body)
    with pytest.raises(Exception) as caught:
        run_child(spec, [({"id": "a"}, "x")], inputs=[], limits=LIMITS)
    assert isinstance(caught.value, ScorerRefused) or "refused" in str(caught.value)
    assert sorted(p.name for p in (room / "out").iterdir()) == []


def test_a_forged_child_report_cannot_hide_a_changed_helper_from_the_pin(capsys, room):
    scorer(room, "good", FORGE)
    status, first = isolated_eval(capsys, room, "e1")
    assert status == 0
    (room / "sc" / "helper.py").write_bytes(b"def same(output, item):\n    return True\n")
    status, second = isolated_eval(capsys, room, "e2")
    assert status == 0 and second["closure"] != first["closure"]
    status, pinned = isolated_eval(capsys, room, "e3", "--expect-closure", first["closure"])
    assert status != 0 and "scorer.closure-mismatch" in str(pinned)


def test_a_scorer_directory_too_large_to_pin_is_refused(capsys, room, monkeypatch):
    monkeypatch.setattr("opentine._scorer_closure.TREE_FILES", 3)
    for n in range(4):
        (room / "sc" / f"extra{n}.txt").write_bytes(b"x")
    status, doc = isolated_eval(capsys, room)
    assert status != 0 and "scorer.closure-too-large" in str(doc)
    assert not (room / "ev" / "verdicts.jsonl").exists()


__all__ += ["run_json"]
