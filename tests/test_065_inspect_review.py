"""Red-team holes in Inspect interop (0.64 review): each was reachable by a hostile log."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from opentine import _eval_run
from opentine._inspect_export import collect, to_eval_bytes
from opentine._inspect_import import import_log
from opentine._inspect_log import InspectLogError, parse_log
from opentine._inspect_verdicts import write_verdicts
from opentine.repository import Repo

KEY = bytes(range(32))
WHEN = "2026-11-01T12:00:00Z"
HEAD = {"version": 2, "status": "success", "eval": {"task": "t", "eval_id": "e1"}}


def _doc(samples):
    return json.dumps({**HEAD, "samples": samples}).encode()


def _zip(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members:
            archive.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), data)
    return buffer.getvalue()


def test_a_zip_with_a_duplicated_member_name_is_refused():
    one = json.dumps({"id": 1, "scores": {"m": {"value": "C"}}}).encode()
    two = json.dumps({"id": 1, "scores": {"m": {"value": "I"}}}).encode()
    header = json.dumps(HEAD).encode()
    with pytest.warns(UserWarning):
        data = _zip(
            [
                ("header.json", header),
                ("samples/1_epoch_1.json", one),
                ("samples/1_epoch_1.json", two),
            ]
        )
    with pytest.raises(InspectLogError):
        parse_log(data)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"id": 1' + b"9" * 5000 + b"}",
        b'{"id": 1, "x": NaN}',
        b'{"id": 1, "x": 1e999}',
        b'{"id": 1, "x": -Infinity}',
    ],
)
def test_huge_or_non_finite_numbers_are_refused_as_log_errors(raw):
    doc = b'{"version": 2, "eval": {"task": "t"}, "samples": [' + raw + b"]}"
    with pytest.raises(InspectLogError):
        parse_log(doc)


def _export(tmp_path, samples):
    repo = Repo.init(tmp_path / "r")
    import_log(repo, parse_log(_doc(samples)))
    data = to_eval_bytes(collect(repo))
    return data, zipfile.ZipFile(io.BytesIO(data)).namelist()


def test_an_exported_eval_zip_never_has_a_traversal_member_name(tmp_path):
    _data, names = _export(tmp_path, [{"id": "../../evil"}, {"id": "a/b\\c"}, {"id": "ok"}])
    for name in names:
        assert ".." not in name and "\\" not in name and name.count("/") <= 1
    assert "samples/ok_epoch_1.json" in names


def test_colliding_sample_ids_survive_an_eval_round_trip(tmp_path):
    data, names = _export(tmp_path, [{"id": 1}, {"id": "1"}])
    assert len(set(names)) == len(names)
    assert sorted(repr(s["id"]) for s in parse_log(data)["samples"]) == ["'1'", "1"]


def _verdicts(tmp_path, samples):
    log = parse_log(_doc(samples))
    body = import_log(Repo.init(tmp_path / "r"), log)
    rows = [{"run": r["run"], "sample": s} for r, s in zip(body["samples"], log["samples"])]
    return write_verdicts(rows, KEY, tmp_path / "evals", created_at=WHEN)


def test_colliding_sample_ids_get_distinct_verdict_items(tmp_path):
    out = _verdicts(
        tmp_path,
        [
            {"id": 1, "scores": {"m": {"value": "C"}}},
            {"id": "1", "scores": {"m": {"value": "I"}}},
            {"id": "a@2", "scores": {"m": {"value": "C"}}},
            {"id": "a", "epoch": 2, "scores": {"m": {"value": "I"}}},
        ],
    )
    folder = Path(out["scorers"]["m"]["folder"])
    lines = (folder / "verdicts.jsonl").read_bytes().splitlines()
    items = [json.loads(line)["item"] for line in lines]
    assert len(items) == 4 and len(set(items)) == 4
    assert _eval_run.verify_eval(folder)["ok"]


def test_scorers_whose_folder_names_collide_are_refused_not_overwritten(tmp_path):
    scores = {"Match": {"value": "C"}, "match": {"value": "I"}}
    with pytest.raises(ValueError, match="collide"):
        _verdicts(tmp_path, [{"id": 1, "scores": scores}])
