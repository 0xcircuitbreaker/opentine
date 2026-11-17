"""0.53: every refusal of the Python reference names its pinned reason code.

Across the whole pinned conformance set, a ``reject`` case the reference refuses
must carry ``exc.code``, and that code must be the pinned ``reason`` (or one of
``reason_any``), widened only by the published alias groups.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine._refusal_codes import name_refusal, reason_for
from tests.conformance.engine import observe
from tests.conformance.generate import families

SUITE = Path(__file__).resolve().parents[1] / "docs" / "conformance"


def _pinned() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted((SUITE / "vectors").glob("*.json")):
        for record in json.loads(path.read_text("utf-8"))["cases"]:
            out[record["id"]] = record
    return out


def _groups() -> list[set[str]]:
    manifest = json.loads((SUITE / "MANIFEST.json").read_text("utf-8"))
    return [set(group) for group in manifest.get("alias_groups", [])]


def test_every_pinned_refusal_is_named_with_its_pinned_code() -> None:
    records, groups = _pinned(), _groups()
    unnamed: list[str] = []
    mismatched: list[str] = []
    rejects = 0
    for family in families():
        for case in family.cases:
            record = records[case.id]
            if record["expect"] != "reject":
                continue
            rejects += 1
            assert record.get("reason") or record.get("reason_any"), f"{case.id} pins no reason"
            seen = observe(case)
            code = getattr(seen.exception, "code", None)
            if code is None:
                unnamed.append(case.id)
                continue
            allowed = set(record.get("reason_any") or [record["reason"]])
            for group in groups:
                if group & allowed:
                    allowed |= group
            if code not in allowed:
                mismatched.append(f"{case.id}: {code} not in {sorted(allowed)}")
    assert rejects > 400
    assert unnamed == []
    assert mismatched == []


def test_an_existing_code_is_never_replaced() -> None:
    exc = ValueError("invalid typed object id: 'x'")
    exc.code = "path.invalid-oid"  # type: ignore[attr-defined]
    assert name_refusal("oid.parse", exc).code == "path.invalid-oid"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("op", "message", "code"),
    [
        ("fleet.verify", "fleet_id must be 1..128 of [A-Za-z0-9_.-]", "fleet.malformed"),
        ("shape.scan", "JSON body is not UTF-8 text", "shape.not-utf8"),
        ("oid.parse", "invalid typed object id: 'blob:sha256:' + 'ab' * 32", "oid.malformed"),
    ],
)
def test_a_refusal_is_named_by_operation_and_message(op: str, message: str, code: str) -> None:
    assert reason_for(op, ValueError(message)) == code


def test_an_unknown_refusal_stays_unnamed_rather_than_guessed() -> None:
    assert reason_for("envelope.decode", ValueError("something new")) is None


@pytest.mark.parametrize("exc", [TypeError("x"), KeyError("fleet_id"), AttributeError("y")])
def test_a_programming_error_is_never_named_as_a_refusal(exc: BaseException) -> None:
    assert reason_for("fleet.verify", exc) is None
    assert getattr(name_refusal("fleet.verify", exc), "code", None) is None
