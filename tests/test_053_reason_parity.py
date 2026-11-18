"""0.53: every refusal names its pinned reason code, in the pyz and the TS verifier.

``scripts/check_parity.py --reasons`` asks python, the built pyz and the TS
verifier for the reason code of every refusal of a pinned ``reject`` case and
fails on an unnamed refusal or a code outside the pinned one's alias group.
The pyz half runs here offline; the TS half runs when ``ts/verifier`` is built
(CI's ``parity`` job requires it).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_parity.py"


def _module():
    spec = importlib.util.spec_from_file_location("check_parity", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pyz_reasons(module) -> tuple[Counter, list[str]]:
    from tests.conformance.engine import op_input
    from tests.conformance.generate import families

    records, groups, keys = module._records(), module._alias_groups(), module._keys()
    storage = set(module.inventory.STORAGE)
    from parity_reasons import ReasonTally

    tally = ReasonTally()
    with module._built_pyz() as conform:
        for family in families():
            if family.filename.removesuffix(".json") in storage:
                continue
            for case in family.cases:
                record = records[case.id]
                if case.profile == "writer" or record["expect"] != "reject":
                    continue
                if case.op not in conform.OPS and case.op not in conform.KEYED:
                    continue
                payload, _ = op_input(case)
                try:
                    conform.answer(case.op, payload.raw, payload.value, case.args, keys)
                except Exception as exc:  # noqa: BLE001 -- a refusal is the answer
                    tally.see("pyz", record, groups, True, getattr(exc, "code", None))
    return tally.checked + Counter(), tally.problems


def test_every_pyz_refusal_names_its_pinned_reason():
    checked, problems = _pyz_reasons(_module())
    assert problems == []
    assert checked["pyz"] >= 400


def test_the_pyz_classifier_keeps_an_existing_code_and_leaves_unknowns_unnamed():
    from opentine._pyz import _reasons
    from opentine.kernel import KernelError

    coded = ValueError("anything")
    coded.code = "sig.bad"  # type: ignore[attr-defined]
    assert _reasons.reason_of(coded) == "sig.bad"
    assert _reasons.reason_of(KernelError("object id mismatch")) == "envelope.oid-mismatch"
    assert _reasons.reason_of(json.JSONDecodeError("x", "", 0)) == "artifact.malformed-json"
    assert _reasons.reason_of(ValueError("never pinned")) is None
    blake = "run:blake2b:" + "1" * 64
    assert _reasons.reason_of(KernelError(f"invalid typed object id: {blake!r}")) == (
        "oid.hash-unsupported"
    )
    assert _reasons.reason_of(KernelError("invalid typed object id: ''")) == "oid.malformed"


def test_reason_tally_counts_unnamed_and_mismatched_refusals():
    sys.path.insert(0, str(ROOT / "scripts"))
    from parity_reasons import ReasonTally

    groups = [{"a.one", "a.two"}]
    tally = ReasonTally()
    reject = {"id": "x", "expect": "reject", "reason": "a.one"}
    tally.see("ts", reject, groups, True, "a.two")  # alias: agrees
    tally.see("ts", reject, groups, True, None)
    tally.see("pyz", reject, groups, True, "b.other")
    tally.see("pyz", {"id": "y", "expect": "accept"}, groups, True, None)  # not a reject case
    assert tally.checked == Counter({"ts": 2, "pyz": 1})
    assert tally.unnamed["ts"] == 1 and tally.mismatch["pyz"] == 1
    assert tally.problems == ["ts unnamed refusal: x", "pyz reason mismatch: x: b.other != a.one"]


def test_ci_runs_the_reason_parity_check():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
    assert "scripts/check_parity.py --require-ts --reasons" in workflow
