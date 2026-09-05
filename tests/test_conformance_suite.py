"""The self-gate: the reference implementation must pass every vector it shipped.

Each core-tier case is one pytest id, so a failure names
``sig.attest.hazard.nonbmp-1e20`` rather than "case 317". A **reject** vector
asserts both halves of the rule: that the implementation refuses, and that it
refuses for the reason ``docs/conformance/REASON_CODES.md`` records -- not by
accident, and not with a message from some unrelated check.

Stress cases are collected here too and skipped unless
``OPENTINE_CONFORMANCE_STRESS`` is set, because three of them assemble hundreds
of megabytes.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from tests.conformance.engine import canonical_output, observe
from tests.conformance.generate import SUITE, all_cases
from tests.conformance.reasons import ALIAS_GROUPS, REASONS

CASES = all_cases()
STRESS_ENABLED = bool(os.environ.get("OPENTINE_CONFORMANCE_STRESS"))
VECTORS = {
    record["id"]: record
    for path in sorted((SUITE / "vectors").glob("*.json"))
    for record in json.loads(path.read_text("utf-8"))["cases"]
}


def _group_for(code: str) -> set[str]:
    allowed = {code}
    for group in ALIAS_GROUPS:
        if allowed & set(group):
            allowed |= set(group)
    return allowed


@pytest.mark.parametrize("case", CASES, ids=[case.id for case in CASES])
def test_the_reference_implementation_answers_every_vector(case) -> None:
    if case.tier == "stress" and not STRESS_ENABLED:
        pytest.skip("set OPENTINE_CONFORMANCE_STRESS=1 to run the stress tier")
    record = VECTORS[case.id]
    observation = observe(case)

    if case.expect == "reject":
        assert observation.disposition == "reject", (
            f"{case.id}: the format requires this input be refused, and it was accepted "
            f"with {observation.output!r}"
        )
        # A negative vector must refuse for the documented reason. The reference has
        # no reason vocabulary of its own, so the pin is its exact message, recorded
        # in x_reference at generation time; drift in either direction fails here.
        assert record["x_reference"]["message"] == str(observation.exception)[:400], case.id
        assert record["x_reference"]["exception"] == type(observation.exception).__name__
        codes = set(record.get("reason_any") or [record["reason"]])
        assert codes <= set(REASONS), case.id
        return

    assert observation.disposition == "accept", (
        f"{case.id}: refused a valid input -- {observation.exception!r}"
    )
    if "output_sha256" in record:
        import hashlib

        digest = hashlib.sha256(canonical_output(observation.output)).hexdigest()
        assert digest == record["output_sha256"], case.id
    else:
        assert observation.output == record["output"], case.id


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.forbidden],
    ids=[case.id for case in CASES if case.forbidden],
)
def test_no_forbidden_answer_is_ever_the_right_one(case) -> None:
    """``forbidden`` is the repaired answer; the reference must never produce it."""
    if case.tier == "stress" and not STRESS_ENABLED:
        pytest.skip("set OPENTINE_CONFORMANCE_STRESS=1 to run the stress tier")
    observation = observe(case)
    if observation.output is None:
        return
    overlap = {
        key: value
        for key, value in case.forbidden.items()
        if key in observation.output and observation.output[key] == value
    }
    assert not overlap, f"{case.id}: produced the forbidden answer {overlap}"


def test_every_side_file_is_referenced_and_hashes_to_its_own_name() -> None:
    referenced = {
        record["input"]["blob"] for record in VECTORS.values() if "blob" in record["input"]
    }
    on_disk = {
        path.relative_to(SUITE).as_posix()
        for directory in ("blobs", "frames")
        for path in (SUITE / directory).glob("*")
        if path.is_file()
    }
    assert referenced == on_disk
    for name in sorted(on_disk):
        import hashlib

        raw = (SUITE / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == Path(name).stem, name


def test_every_inline_input_decodes_to_the_bytes_its_digest_names() -> None:
    for record in VECTORS.values():
        spec = record["input"]
        if "bytes_b64" not in spec:
            continue
        import hashlib

        raw = base64.b64decode(spec["bytes_b64"], validate=True)
        assert hashlib.sha256(raw).hexdigest() == spec["sha256"], record["id"]


def test_a_reject_vector_names_a_code_whose_alias_group_is_registered() -> None:
    for record in VECTORS.values():
        if record["expect"] != "reject":
            continue
        for code in record.get("reason_any") or [record["reason"]]:
            assert _group_for(code) <= set(REASONS), record["id"]
