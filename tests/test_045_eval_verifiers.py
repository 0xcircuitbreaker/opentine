"""0.45 acceptance: a 1k-item eval's verdicts verify in Python, the pyz and the TS verifier."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from opentine._eval_run import read_verdicts, run_eval, verify_eval
from opentine._eval_scorers import parse
from opentine._pyz_build import build_bytes
from tests.conformance.keys import KEYS

ROOT = Path(__file__).resolve().parents[1]
TS_CLI = ROOT / "ts" / "verifier" / "dist" / "src" / "cli.js"


@pytest.fixture(scope="module")
def evaluated(tmp_path_factory) -> tuple[Path, Path]:
    room = tmp_path_factory.mktemp("eval1k")
    items = [
        {
            "id": f"q{i:04d}",
            "input": f"{i}",
            "expected": str(i),
            "output": str(i) if i % 4 else "x",
            "run": "run:fixture",
        }
        for i in range(1000)
    ]
    run_eval(items, parse("exact"), KEYS["ed25519_seed"], room / "ev",
             created_at="2026-11-08T00:00:00Z")  # fmt: skip
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    public = Ed25519PrivateKey.from_private_bytes(KEYS["ed25519_seed"]).public_key()
    (room / "k.pub").write_text(public.public_bytes_raw().hex() + "\n", encoding="utf-8")
    (room / "tine-verify.pyz").write_bytes(build_bytes())
    return room, room / "ev"


def test_python_verifies_the_1k_eval(evaluated):
    _, ev = evaluated
    result = verify_eval(ev)
    assert result["ok"] and result["items"] == 1000 and result["passed"] == 750


def test_the_pyz_verifies_the_1k_eval_without_opentine(evaluated):
    room, ev = evaluated
    argv = [sys.executable, "-I", "-S", str(room / "tine-verify.pyz"), ev.as_posix(), "--pubkey",
            (room / "k.pub").as_posix()]  # fmt: skip
    done = subprocess.run(argv, capture_output=True, text=True, timeout=600, cwd=room)
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert report["mode"] == "eval" and report["ok"]
    assert report["checks"][-1]["passed"] == 750
    rows = read_verdicts(ev)
    rows[4]["score"] = "1"
    bad = room / "bad.jsonl"
    bad.write_text("".join(json.dumps(row) + "\n" for row in rows[:5]), encoding="utf-8")
    done = subprocess.run([*argv[:4], bad.as_posix()], capture_output=True, text=True, cwd=room)
    assert done.returncode == 1
    failed = [c for c in json.loads(done.stdout)["checks"] if c["outcome"] == "fail"]
    assert failed[0]["reason"] == "eval-verdict.bad-signature"


@pytest.mark.skipif(
    shutil.which("node") is None or not TS_CLI.is_file(),
    reason="the TS verifier is not built (npm --prefix ts/verifier test)",
)
def test_the_ts_verifier_verifies_the_1k_eval(evaluated):
    room, ev = evaluated
    argv = ["node", TS_CLI.as_posix(), (ev / "verdicts.jsonl").as_posix(), "--pubkey",
            (room / "k.pub").as_posix()]  # fmt: skip
    done = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert report["ok"] and report["verified"] == 1000 and report["passed"] == 750


def test_a_verdict_spliced_in_by_another_key_is_refused_without_a_pubkey(evaluated):
    from opentine import _eval_verdict
    from opentine._pyz import _evalv

    room, ev = evaluated
    rows = read_verdicts(ev)[:3]
    names = ("eval", "dataset", "item_digest", "run", "scorer", "scorer_version", "created_at")
    fields = {name: rows[0][name] for name in names}
    forged = _eval_verdict.make(b"\x07" * 32, **fields, item="q9999", score=1, threshold=1)
    for extra, reason in ((forged, "eval.id-mismatch"), (dict(rows[1]), "eval.duplicate-item")):
        bad = room / f"{reason}.jsonl"
        bad.write_text("".join(json.dumps(r) + "\n" for r in [*rows, extra]), encoding="utf-8")
        result = verify_eval(bad)
        assert not result["ok"] and result["failures"][0]["reason"] == reason
        checks = _evalv.verify_eval(bad, None)
        assert checks[-1]["outcome"] == "fail" and checks[0]["reason"] == reason
        if shutil.which("node") and TS_CLI.is_file():
            argv = ["node", TS_CLI.as_posix(), bad.as_posix()]
            done = subprocess.run(argv, capture_output=True, text=True, timeout=120)
            assert done.returncode != 0
            assert json.loads(done.stdout)["failures"][0]["reason"] == reason
