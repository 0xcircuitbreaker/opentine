"""0.73 review: holes an optimizer-holding loop could use against tine uplift."""

from __future__ import annotations

import json

import pytest

from opentine import _uplift, _uplift_export, _uplift_report
from opentine.repository._holds import edit_holds, holds_path
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_073_uplift_cli import room  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

ODD = ["1e400", "1E-400", "0.0000000000000000001", "1e9999999", " 5", "5 ", "+5", "0x10",
       "1_0", "-0", "0", "inf", "NaN"]  # fmt: skip


@pytest.mark.parametrize("minutes", ODD)
def test_minutes_out_of_range_or_odd_forms_are_refused(minutes: str) -> None:
    assert not _uplift.minutes_ok(minutes)
    suite = {"name": "s", "version": "1", "scoring": "binary",
             "tasks": [{"id": "t", "minutes": minutes}]}  # fmt: skip
    assert _uplift.check_suite(suite)


def test_plain_minutes_still_count() -> None:
    for minutes in ("1", "0.5", "960", "12.25", "525600"):
        assert _uplift.minutes_ok(minutes), minutes


@pytest.mark.parametrize("value", [1, 0, 1.0])
def test_success_must_be_a_real_boolean(value) -> None:
    claim = {"convention": _uplift.RECORD, "record": "run", "suite": "sha256:" + "0" * 64,
             "task": "t", "subject": "s", "condition": "ai", "success": value, "minutes": None,
             "perceived_minutes": None, "generation": None, "at": "x"}  # fmt: skip
    assert _uplift.check_claim(claim)


def test_a_duplicated_hold_row_does_not_count_a_record_twice(room) -> None:  # noqa: F811
    repo = room["repo"]
    before = _uplift_export.build(repo, room["suite"])["records"]
    target = _uplift.hold_target(room["suite"])
    favourable = next(r["oid"] for r in before if r["success"])
    extra = {"oid": favourable, "target": target + "x"}  # a second row naming the same suite
    edit_holds(holds_path(repo), lambda rows: [*rows, extra])
    path = holds_path(repo)
    doc = json.loads(path.read_bytes())
    doc["holds"] += [{"oid": favourable, "target": target}] * 3
    path.write_bytes(json.dumps(doc).encode("utf-8"))
    after = _uplift_export.build(repo, room["suite"])["records"]
    assert after == before


@pytest.mark.parametrize("resamples", [1, 5, 99, 100001])
def test_a_degenerate_resample_count_is_refused(room, resamples) -> None:  # noqa: F811
    export = _uplift_export.build(room["repo"], room["suite"])
    with pytest.raises(ValueError):
        _uplift_report.report_horizon(export, resamples=resamples)


@pytest.mark.parametrize("alpha", ["0.9", "0.51", "1e-30"])
def test_an_alpha_that_shrinks_the_interval_is_refused(room, alpha) -> None:  # noqa: F811
    export = _uplift_export.build(room["repo"], room["suite"])
    with pytest.raises(ValueError):
        _uplift_report.report_horizon(export, resamples=100, alpha=alpha)


def _export_file(room, doc) -> str:  # noqa: F811
    path = room["base"] / "x.json"
    path.write_bytes(doc if isinstance(doc, bytes) else json.dumps(doc).encode("utf-8"))
    return path.as_posix()


def test_a_doctored_export_is_refused_not_crashed(room) -> None:  # noqa: F811
    good = _uplift_export.build(room["repo"], room["suite"])
    dup_row = {**good, "records": [good["records"][0], *good["records"]]}
    unsorted = {**good, "records": list(reversed(good["records"]))}
    not_list = {**good, "records": {"a": 1}}
    bad_finding = {**good, "findings": [{"level": "x"}]}
    text = json.dumps(good)
    dup_key = (text[:-1] + ', "suite": "' + good["suite"] + '"}').encode("utf-8")
    nan = text.replace('"generation": 0', '"generation": NaN', 1).encode("utf-8")
    for doc in (dup_row, unsorted, not_list, bad_finding, dup_key, nan):
        with pytest.raises(ValueError):
            _uplift_export.load(_export_file(room, doc))
    assert _uplift_export.load(_export_file(room, _uplift_export.dump(good))) == good
