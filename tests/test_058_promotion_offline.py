"""0.58: promote, revert, promote verifies offline in Python, the pyz and TS.

Promotion emits only existing kinds: the admission VSA (DSSE,
``verification_summary/v1``) answered by each implementation's ``vsa.verify``
op, and attestations (decisions, approvals, comparisons) answered by
``sig.verify`` in the attestation family. The chain is rebuilt
deterministically into ``tests/data/promotion_chain.json``, which
``ts/verifier/test/promotion.test.ts`` reads too.
"""

from __future__ import annotations

import base64
import copy
import importlib
import json
import sys
from pathlib import Path

import pytest

from opentine import _promote
from opentine._promote_checks import load_policy
from opentine._pyz_build import build_bytes
from tests.conformance.adapter import OPS, OpInput
from tests.promote_helpers import (
    APPROVER,
    AT,
    PROMOTER,
    RUN_A,
    RUN_B,
    RUN_C,
    key,
    make_eval,
    policy,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "data" / "promotion_chain.json"
pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _promote_one(base: Path, pol: dict, run: str, out: Path) -> None:
    signed = _promote.approve(key(APPROVER), run, "prod", at=AT)
    (base / f"approve-{run[-1]}.json").write_bytes(json.dumps(signed).encode())
    sides = [make_eval(base / f"{n}-{run[-1]}", r, f, dataset=d) for n, r, f, d in (
        ("base", RUN_A, lambda i: i % 2 == 0, "main"), ("cand", run, lambda i: i % 10 != 0, "main"),
        ("hbase", RUN_A, lambda i: i % 2 == 0, "hold"),
        ("hcand", run, lambda i: i % 10 != 0, "hold"))]  # fmt: skip
    _promote.promote(key(PROMOTER), pol, run, "prod", state=base / "state", out=out,
                     baseline=sides[0], evals=sides[1], holdout=(sides[2], sides[3]),
                     approvals=[base / f"approve-{run[-1]}.json"], at=AT)  # fmt: skip


def build_fixture(base: Path) -> dict:
    pol = load_policy(policy(base))
    _promote_one(base, pol, RUN_B, base / "one")
    _promote.revert(key(PROMOTER), pol, RUN_B, "prod", state=base / "state", out=base / "two",
                    reason="rollback", at=AT)  # fmt: skip
    _promote_one(base, pol, RUN_C, base / "three")
    public = key(PROMOTER).public_key().public_bytes_raw()
    approver = key(APPROVER).public_key().public_bytes_raw().hex()
    cases = []
    for step, run in (("one", RUN_B), ("three", RUN_C)):
        envelope = json.loads((base / step / "vsa.json").read_text("utf-8"))
        cases.append({"id": f"{step}/vsa", "op": "vsa.verify", "args": {}, "expect": "valid",
                      "value": {"envelope": envelope, "key": _b64url(public), "subject": run,
                                "levels": ["OPENTINE_PROMOTED"],
                                "policy": "opentine:trust-policy/promotion",
                                "resource": "tine://promotion/labels/prod"}})  # fmt: skip
        for name in ("decision", "compare", "holdout-compare"):
            cases.append(_sig(f"{step}/{name}", base / step / f"{name}.json", public.hex()))
        cases.append(_sig(f"{step}/approval", base / f"approve-{run[-1]}.json", approver))
    cases.append(_sig("two/decision", base / "two" / "decision.json", public.hex()))
    return {"about": "0.58 promote/revert/promote, only existing kinds; regenerate with "
                     "tests/test_058_promotion_offline.py", "cases": cases}  # fmt: skip


def _sig(ident: str, path: Path, public: str) -> dict:
    return {"id": ident, "op": "sig.verify", "expect": "verified",
            "args": {"family": "attestation", "public_key": public},
            "value": json.loads(path.read_text("utf-8"))}  # fmt: skip


def _cases() -> list[dict]:
    return json.loads(FIXTURE.read_text("utf-8"))["cases"]


def _tampered(case: dict) -> dict:
    value = copy.deepcopy(case["value"])
    if case["op"] == "vsa.verify":
        value["subject"] = RUN_A
    else:
        value["claim"]["label"] = "staging"
    return value


def _outcome(case: dict, verdict: dict) -> str:
    return verdict["class"] if case["op"] == "vsa.verify" else verdict["state"]


def test_fixture_is_current(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    assert json.loads(FIXTURE.read_text("utf-8")) == build_fixture(tmp_path)


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["id"])
def test_reference_verifies_every_promotion_object(case: dict) -> None:
    verdict = OPS[case["op"]](OpInput("value", None, case["value"]), dict(case["args"]))
    assert _outcome(case, verdict) == case["expect"]
    edited = OPS[case["op"]](OpInput("value", None, _tampered(case)), dict(case["args"]))
    assert _outcome(case, edited) != case["expect"]


def test_built_pyz_verifies_every_promotion_object(tmp_path) -> None:
    archive = tmp_path / "tine-verify.pyz"
    archive.write_bytes(build_bytes())
    sys.path.insert(0, str(archive))
    try:
        conform = importlib.import_module("tine_verify._pyz._conform")
        assert Path(conform.__file__).as_posix().startswith(archive.as_posix())
        for case in _cases():
            verdict = conform.answer(case["op"], None, case["value"], case["args"], {})
            assert _outcome(case, verdict) == case["expect"], case["id"]
            edited = conform.answer(case["op"], None, _tampered(case), case["args"], {})
            assert _outcome(case, edited) != case["expect"], case["id"]
    finally:
        sys.path.remove(str(archive))
        for name in [n for n in sys.modules if n.split(".")[0] == "tine_verify"]:
            del sys.modules[name]


if __name__ == "__main__":  # regenerate: python -m tests.test_058_promotion_offline DIR
    out = build_fixture(Path(sys.argv[1]))
    FIXTURE.write_bytes((json.dumps(out, indent=2, sort_keys=True) + "\n").encode())
