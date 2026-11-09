"""0.48 freeze cutoff: every object kind and wire format has vectors in Python, TS and pyz.

The kinds are enumerated from the tree -- the backticked names of SPEC's object,
signing and verification headings, the published schemas and the vector
families -- and each must sit in ``tests/freeze_inventory.py``. For every entry:
the reference adapter answers each op (Python), ``ts/verifier/src/ops.ts`` has a
case for each reader/verifier op (TS), and the pyz answers the family either
through the *built* archive's ``_pyz/_conform`` (run here, case by case,
against the pinned vectors) or through a named test that runs it. Anything not
yet covered is listed, with a reason, and the lists may only shrink.
"""

from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path

import pytest

from opentine._pyz_build import build_bytes
from tests import freeze_inventory as inv
from tests.conformance.adapter import OPS as PYTHON_OPS
from tests.conformance.engine import op_input
from tests.conformance.generate import families

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "docs" / "conformance" / "vectors"
SPEC = (ROOT / "docs" / "SPEC.md").read_text("utf-8")
TS_OPS = set(re.findall(r'case "([^"]+)"', (ROOT / "ts/verifier/src/ops.ts").read_text("utf-8")))
FAMILIES = {family.filename.removesuffix(".json"): family for family in families()}
ENTRY_FAMILIES = {name for entry in inv.KINDS.values() for name in entry[3]}


def _spec_names() -> set[str]:
    heading = re.compile(r"^#{2,3} (?:1\.5|4|8|9)\.[0-9.]+ (.*)$", re.MULTILINE)
    return {name for line in heading.findall(SPEC) for name in re.findall(r"`([^`]+)`", line)}


def test_every_family_on_disk_is_inventoried_once():
    on_disk = {path.stem for path in VECTORS.glob("*.json")}
    listed = [*[n for e in inv.KINDS.values() for n in e[3]], *inv.STORAGE, *inv.WRITER]
    assert sorted(listed) == sorted(set(listed)), "a family is listed twice"
    assert on_disk == set(listed)
    assert on_disk == set(FAMILIES)


def test_every_spec_kind_is_inventoried():
    covered = {name for entry in inv.KINDS.values() for name in entry[1]}
    unknown = _spec_names() - covered - set(inv.DEFERRED) - set(inv.NOT_KIND_NAMES)
    assert not unknown, f"SPEC names a kind the freeze inventory does not: {sorted(unknown)}"


def test_every_published_schema_is_a_kind_or_says_why_not():
    stems = {p.name.removesuffix(".schema.json") for p in (ROOT / "docs/schemas").glob("*.json")}
    stems = {s for s in stems if not s.startswith("tine-cli-")}
    covered = {stem for entry in inv.KINDS.values() for stem in entry[2]}
    assert set(inv.DEFERRED_SCHEMAS.values()) <= set(inv.DEFERRED)
    assert stems == covered | set(inv.NOT_KINDS) | set(inv.DEFERRED_SCHEMAS)


def _ops(names) -> set[tuple[str, str]]:
    return {(case.op, case.profile) for n in names for case in FAMILIES[n].cases}


def test_python_answers_every_op():
    missing = {op for op, _ in _ops(set(FAMILIES))} - set(PYTHON_OPS)
    assert not missing


def test_the_ts_verifier_answers_every_reader_and_verifier_op():
    missing = {op for op, profile in _ops(set(FAMILIES)) if profile != "writer"} - TS_OPS
    assert not missing, f"no TS case for {sorted(missing)}"


@pytest.fixture(scope="module")
def pyz_conform(tmp_path_factory):
    """``tine_verify._pyz._conform`` imported from the built archive, not the tree."""
    archive = tmp_path_factory.mktemp("pyz") / "tine-verify.pyz"
    archive.write_bytes(build_bytes())
    sys.path.insert(0, str(archive))
    try:
        module = importlib.import_module("tine_verify._pyz._conform")
        assert Path(module.__file__).as_posix().startswith(archive.as_posix())
        yield module
    finally:
        sys.path.remove(str(archive))
        for name in [n for n in sys.modules if n == "tine_verify" or n.startswith("tine_verify.")]:
            del sys.modules[name]


KEYS = {
    name: bytes.fromhex(text)
    for name, text in json.loads((ROOT / "docs/conformance/keys.json").read_text("utf-8")).items()
}


def _answer(conform, case):
    payload, _ = op_input(case)
    try:
        return "accept", conform.answer(case.op, payload.raw, payload.value, case.args, KEYS)
    except Exception as exc:  # noqa: BLE001 -- a refusal is the answer
        return "reject", exc


CONFORM_FAMILIES = sorted(n for e in inv.KINDS.values() if e[4] == inv.CONFORM for n in e[3])


@pytest.mark.parametrize("name", CONFORM_FAMILIES)
def test_the_built_pyz_answers_the_family(pyz_conform, name):
    records = {
        r["id"]: r for r in json.loads((VECTORS / f"{name}.json").read_text("utf-8"))["cases"]
    }
    answered = 0
    for case in FAMILIES[name].cases:
        if case.op not in pyz_conform.OPS and case.op not in pyz_conform.KEYED:
            continue
        answered += 1
        record = records[case.id]
        got, out = _answer(pyz_conform, case)
        assert got == ("accept" if case.expect == "verdict" else case.expect), (case.id, out)
        if got == "accept" and "output" in record:
            assert out == record["output"], case.id
        if got == "reject" and hasattr(out, "code"):
            assert out.code in set(record.get("reason_any") or [record["reason"]]), case.id
    if name in inv.PYZ_FILE_LEVEL:
        assert not answered, f"{name} is answered now: remove it from PYZ_FILE_LEVEL"
    else:
        assert answered, f"the pyz answers no case of {name}"


def test_pyz_op_gaps_are_exactly_the_pinned_ones():
    conform = importlib.import_module("opentine._pyz._conform")
    gaps = {
        op
        for op, profile in _ops(CONFORM_FAMILIES)
        if profile != "writer" and op not in conform.OPS and op not in conform.KEYED
    }
    assert gaps == set(inv.PYZ_OP_GAPS), "a gap was closed (shrink the list) or opened"


def test_every_family_is_answered_case_by_case_and_no_gap_is_left():
    """0.50 (criterion 2): no whole-file-only family, no op gap, no family pinned by a test."""
    assert all(entry[4] == inv.CONFORM for entry in inv.KINDS.values())
    assert inv.PYZ_FILE_LEVEL == {} and inv.PYZ_OP_GAPS == {}


def test_the_deferred_list_is_empty():
    """0.50 added families 79-84 for the six kinds 0.48 deferred; none may come back."""
    assert inv.DEFERRED == {} and inv.DEFERRED_SCHEMAS == {}


def test_the_cutoff_is_documented():
    assert '<a id="s-5.5"></a>' in SPEC and "## 5.5 The 0.48 freeze cutoff" in SPEC
    roadmap = (ROOT / "docs" / "ROADMAP.md").read_text("utf-8")
    assert "tests/test_048_freeze_cutoff.py" in roadmap
