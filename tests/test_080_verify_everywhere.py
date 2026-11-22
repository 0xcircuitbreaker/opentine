"""0.80 ``scripts/verify_everywhere.py``: every object checked by python, pyz and TS."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from tests.verify_everywhere_fixture import KINDS, build

ROOT = Path(__file__).resolve().parents[1]
TS_BUILT = (ROOT / "ts" / "verifier" / "dist" / "src" / "parity.js").is_file()


def _load():
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("verify_everywhere", ROOT / "scripts" /
                                                  "verify_everywhere.py")  # fmt: skip
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool():
    return _load()


@pytest.fixture
def room(tmp_path):
    return build(tmp_path)


def _report(tool, capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = tool.main([*argv, "--json", *(["--require-ts"] if TS_BUILT else [])])
    return code, json.loads(capsys.readouterr().out)


def test_the_fixture_holds_every_record_kind_the_loop_writes(room, tool):
    files = {p.relative_to(room["records"]).parts[0] for p in room["records"].rglob("*.json")}
    names = set(room["oids"]) | files | {"promote", "revert"}
    assert set(KINDS) <= names | {"lineage", "holdout"}
    cases = tool.repo_cases(room["repo"].path) + tool.file_cases(room["records"])
    sig_ids = {c.id for c in cases if c.op == "sig.verify"}
    assert {f"{oid}#sig" for oid in room["oids"].values()} <= sig_ids
    assert sum(1 for i in sig_ids if i.startswith("file:")) == 6
    assert {"envelope.decode", "links.extract", "sig.verify"} == {c.op for c in cases}


def test_every_object_and_record_verifies_the_same_everywhere(room, tool, capsys):
    code, report = _report(tool, capsys, str(room["repo"].path), str(room["records"]))
    assert code == 0, report["problems"]
    assert report["ok"] and report["problems"] == []
    assert report["verifiers"][:2] == ["python", "pyz"]
    assert ("ts" in report["verifiers"]) is TS_BUILT
    objects = len(room["repo"].iter_oids())
    assert report["cases"] == 2 * objects + len(room["oids"]) + 6


def test_a_bundle_is_checked_whole_and_object_by_object(room, tool, capsys, tmp_path):
    from opentine import _bundle

    path = tmp_path / "loop.bundle"
    path.write_bytes(_bundle.create(room["repo"]))
    code, report = _report(tool, capsys, str(path))
    assert code == 0, report["problems"]
    assert report["cases"] >= 2 * len(room["runs"])


def test_a_tampered_record_is_refused_by_all_and_reported(room, tool, capsys):
    path = room["records"] / "promote" / "promote.json"
    data = json.loads(path.read_bytes())
    data["claim"]["action"] = "revert"
    path.write_bytes(json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))
    code, report = _report(tool, capsys, str(room["records"]))
    assert code == 1
    assert report["problems"] == ["does not verify: file:promote/promote.json#sig (signature)"]
    capsys.readouterr()
    loose = tool.main([str(room["records"]), "--json", "--allow-invalid"])
    assert loose == 0 and json.loads(capsys.readouterr().out)["problems"] == []


class _Liar:
    """A pyz stand-in that accepts every case with an empty answer."""

    OPS = {"envelope.decode": None, "links.extract": None}
    KEYED = {"sig.verify": None}

    @staticmethod
    def answer(op, raw, value, args, keys):
        return {}


class _Silent(_Liar):
    OPS: dict = {}
    KEYED: dict = {}


@pytest.mark.parametrize(("pyz", "prefix"), [(_Liar, "pyz disagrees"), (_Silent, "pyz gap")])
def test_a_verifier_that_answers_differently_fails_the_check(room, tool, pyz, prefix, tmp_path):
    cases = tool.file_cases(room["records"])
    report = tool.compare(cases, pyz=pyz, scratch=tmp_path)
    assert not report["ok"]
    assert len(report["problems"]) == len(cases)
    assert all(p.startswith(prefix) for p in report["problems"])


def test_a_missing_target_is_a_usage_error(tool, tmp_path):
    with pytest.raises(SystemExit) as raised:
        tool.main([str(tmp_path / "nowhere")])
    assert raised.value.code == 2
