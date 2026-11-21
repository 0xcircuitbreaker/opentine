"""OT-6: a deeply nested JSON line is refused as malformed, never a RecursionError."""

from __future__ import annotations

import json

import pytest

import opentine.cli as cli
from opentine import _eval_verdict, _lineage
from opentine._query_rows import verdict_lines
from opentine._transcript_corpus import from_files
from opentine.repository._holds import HoldError, read_holds

DEEP = b"[" * 200_000
GOOD = json.dumps({"scheme": _eval_verdict.SCHEME, "eval": "e", "score": 1}).encode()


def test_a_deep_verdict_line_is_skipped_and_good_lines_still_index():
    rows = verdict_lines("ev/verdicts.jsonl", DEEP + b"\n" + GOOD + b"\n")
    assert [r["line"] for r in rows] == [2]


def test_query_index_survives_a_deep_verdict_line(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ev").mkdir()
    (tmp_path / "ev" / "verdicts.jsonl").write_bytes(DEEP + b"\n" + GOOD + b"\n")
    assert cli.main(["init", "."]) in (0, None)
    assert cli.main(["query", "index", "--evals", "ev"]) in (0, None)
    assert cli.main(["query", "--json", "SELECT count(*) AS n FROM evals"]) in (0, None)
    assert '"n": 1' in capsys.readouterr().out


@pytest.mark.parametrize("call", [
    lambda p: _lineage.loads(DEEP),
    lambda p: from_files([str(p)]),
])  # fmt: skip
def test_sibling_readers_refuse_deep_json_with_value_error(tmp_path, call):
    path = tmp_path / "c.jsonl"
    path.write_bytes(DEEP + b"\n")
    with pytest.raises(ValueError):
        call(path)


def test_a_deep_holds_file_is_refused_as_malformed(tmp_path):
    path = tmp_path / "holds.json"
    path.write_bytes(b'{"format": ' + DEEP + b"\n")
    with pytest.raises(HoldError):
        read_holds(path)
