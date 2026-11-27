"""0.85: isolated scorer runs, closure pins and hostile scorers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from opentine import _scorer_closure as closure
from opentine._eval_run import read_verdicts, verify_eval
from opentine._scorer_isolated import LIMITS, ScorerRefused, run_child
from tests.scorer_isolation_helpers import HELPER, isolated_eval, room, run_json, scorer

pytestmark = pytest.mark.filterwarnings("ignore:.*plaintext-hex private key")
__all__ = ["room"]

HOSTILE = {
    "network": "import socket\n\ndef score(output, item):\n"
    "    socket.create_connection(('127.0.0.1', 9), timeout=1)\n    return 1\n",
    "env": "import os\n\ndef score(output, item):\n    return 1 if os.environ.get('HOME') else 0\n",
    "env-iter": "import os\n\ndef score(output, item):\n    return 1 if dict(os.environ) else 0\n",
    "file-read": "def score(output, item):\n    return 1 if open(SECRET).read() else 0\n",
    "file-write": "def score(output, item):\n    open('x.txt', 'w').write('x')\n    return 1\n",
    "dynamic-import": "import importlib\n\ndef score(output, item):\n"
    "    importlib.import_module('subprocess').run([sys.executable])\n    return 1\n",
    "dunder-import": "def score(output, item):\n"
    "    __import__('os').system('echo hi')\n    return 1\n",
    "ctypes": "def score(output, item):\n    import ctypes\n    ctypes.CDLL(None)\n    return 1\n",
    "listdir": "import os\n\ndef score(output, item):\n    os.listdir('/')\n    return 1\n",
}


def test_an_isolated_scorer_scores_like_the_in_process_one_and_pins_its_closure(
    capsys, room, monkeypatch
):
    status, isolated = isolated_eval(capsys, room)
    assert status == 0 and isolated["advisories"] == []
    assert isolated["scorer_version"].startswith(closure.PREFIX)
    monkeypatch.syspath_prepend(str(room / "sc"))  # in-process, the helper needs the path
    argv = ("eval", "run", "d.jsonl", "--scorer", "python:sc/good.py:score", "--key", "k.key")
    status, plain = run_json(capsys, *argv, "--out", "ep")
    assert status == 0 and [a["code"] for a in plain["advisories"]] == [
        "advisory:scorer.in-process"
    ]
    # The reference scores are unchanged under the new runner.
    left = [(r["item"], r["score"]) for r in read_verdicts(room / "ev")]
    assert left == [(r["item"], r["score"]) for r in read_verdicts(room / "ep")]
    assert (plain["passed"], plain["mean_score"]) == (isolated["passed"], isolated["mean_score"])
    doc = json.loads((room / "ev" / "scorer.json").read_bytes())
    assert closure.check(doc) == [] and doc["target"] == "python:sc/good.py:score"
    assert {m["name"] for m in doc["modules"]} == {"good", "helper"}
    assert closure.pin(doc) == isolated["scorer_version"]
    assert closure.closure_digest(doc) == isolated["closure"]
    assert doc["isolation"]["env"] == "empty"
    assert doc["isolation"]["level"] in ("full", "partial")
    assert verify_eval(room / "ev")["ok"]


@pytest.mark.parametrize("kind", sorted(HOSTILE))
def test_a_hostile_scorer_is_refused_and_nothing_is_signed(capsys, room, kind):
    (room / "secret.txt").write_bytes(b"s3cret\n")
    head = f"import sys\nSECRET = {str(room / 'secret.txt')!r}\n"
    spec = scorer(room, "bad", head + HOSTILE[kind])
    status, out = run_json(capsys, "eval", "run", "d.jsonl", "--scorer", spec, "--isolate",
                           "--key", "k.key", "--out", "bad")  # fmt: skip
    assert status == 1 and [r["code"] for r in out["refusals"]] == ["scorer.isolation-breach"]
    assert not (room / "bad").exists()
    assert not (room / "sc" / "x.txt").exists()


def test_a_helper_changed_after_pinning_is_a_closure_mismatch(capsys, room):
    _status, first = isolated_eval(capsys, room)
    status, again = isolated_eval(capsys, room, "ev2", "--expect-closure", first["closure"])
    assert status == 0 and again["closure"] == first["closure"]
    (room / "sc" / "helper.py").write_bytes(HELPER + b"# edited\n")
    status, out = isolated_eval(capsys, room, "ev3", "--expect-closure", first["closure"])
    assert status == 1 and out["refusals"][0]["code"] == "scorer.closure-mismatch"
    assert not (room / "ev3").exists()


def test_a_data_file_is_in_the_closure_only_when_passed_as_an_input(capsys, room):
    (room / "answers.txt").write_bytes(b"0\n1\n2\n")
    spec = scorer(room, "reads", "def score(output, item):\n"
                  "    return output in open('../answers.txt').read().split()\n")  # fmt: skip
    argv = ("eval", "run", "d.jsonl", "--scorer", spec, "--isolate", "--key", "k.key")
    status, out = run_json(capsys, *argv, "--out", "no")
    assert status == 1 and out["refusals"][0]["code"] == "scorer.isolation-breach"
    # The child runs in an empty directory, so the scorer must name inputs absolutely.
    spec = scorer(room, "reads", "import pathlib\n\ndef score(output, item):\n"
                  f"    text = pathlib.Path({str(room / 'answers.txt')!r}).read_text()\n"
                  "    return output in text.split()\n")  # fmt: skip
    status, out = run_json(capsys, *argv, "--out", "yes", "--scorer-input", "answers.txt")
    assert status == 0, out
    doc = closure.read(room / "yes")
    assert [row["file"] for row in doc["inputs"]] == ["answers.txt"]
    assert doc["data"] == []


def test_an_edited_or_missing_closure_document_fails_eval_verify(capsys, room):
    isolated_eval(capsys, room)
    path = room / "ev" / "scorer.json"
    doc = json.loads(path.read_bytes())
    doc["modules"] = doc["modules"][:1]
    path.write_bytes(json.dumps(doc).encode("utf-8"))
    reasons = {f["reason"] for f in verify_eval(room / "ev")["failures"]}
    assert reasons == {"eval.summary-mismatch"}
    path.unlink()
    assert not verify_eval(room / "ev")["ok"]


def test_limits_stop_a_runaway_scorer(room):
    pairs = [({"id": "a", "expected": "x"}, "x")]
    spin = scorer(room, "spin", "def score(output, item):\n    while True:\n        pass\n")
    tight = {**LIMITS, "cpu_seconds": 1, "timeout_seconds": 30}
    with pytest.raises(ScorerRefused) as info:
        run_child(spin, pairs, inputs=[], limits=tight)
    assert info.value.code == "scorer.isolation-breach"
    flood = scorer(room, "flood", "import os\n\ndef score(output, item):\n"
                   "    os.write(1, b'x' * 300000)\n    return 1\n")  # fmt: skip
    with pytest.raises(ScorerRefused) as info:
        run_child(flood, pairs, inputs=[], limits={**LIMITS, "output_bytes": 4096})
    assert "output-limit" in info.value.detail


def test_the_child_sees_an_empty_environment_and_no_signing_material(room, monkeypatch):
    monkeypatch.setenv("OPENTINE_SECRET_PROBE", "leak")
    spec = scorer(
        room,
        "probe",
        "import sys\n\ndef score(output, item):\n"
        "    return 0 if any('opentine._signing' in m for m in sys.modules) else 1\n",
    )
    report = run_child(spec, [({"id": "a"}, "x")], inputs=[], limits=LIMITS)
    assert report["scores"] == [1.0]
    assert "opentine._signing_keys" not in report["modules"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux network namespaces")
def test_on_linux_the_level_is_recorded_honestly(capsys, room):
    _status, out = isolated_eval(capsys, room)
    doc = closure.read(Path(room) / "ev")
    full = doc["isolation"]["network"] == "namespace" and doc["isolation"]["limits"]
    assert out["isolation"] == ("full" if full else "partial")
