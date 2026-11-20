"""Red-team review of the transcript index (0.74, release 0.73.0).

A loop that can write ``.tine/transcripts/index.sqlite`` must not be able to
run code through it, hide its runs, plant vectors or shrink the caps; a run
must not escape similarity through lookalike characters, base64, padding or a
huge blob. Every check is by content and counts.
"""

from __future__ import annotations

import base64
import json
import math
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from opentine import _transcript_ann as ann
from opentine import _transcript_embed as te
from opentine import _transcript_index as ti
from opentine import _transcript_text as tt
from tests.query_helpers import tine
from tests.test_073_transcripts import HACK, _run, make_room

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture
def room(tmp_path, monkeypatch):
    return make_room(tmp_path, monkeypatch)


def _index(capsys) -> Path:
    code, body = tine(capsys, "transcripts", "index", "--rebuild", "--repo", "r")
    assert code == 0, body
    return Path(body["index"])


def _sql(path: Path, *statements: tuple) -> None:
    with closing(sqlite3.connect(path)) as db:
        for statement in statements:
            db.execute(*statement)
        db.commit()


def test_an_adapter_named_in_the_index_is_never_imported(capsys, room, tmp_path, monkeypatch):
    marker = tmp_path / "imported"
    (tmp_path / "planted_adapter_mod.py").write_bytes(
        f"open({marker.as_posix()!r}, 'wb').close()\nX = None\n".encode()
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    path = _index(capsys)
    planted = json.dumps({"adapter": "planted_adapter_mod:X", "name": "x", "dim": 4})
    _sql(path, ("UPDATE meta SET value = ? WHERE key = 'backend'", (planted,)))
    tine(capsys, "transcripts", "search", "tests", "--repo", "r")
    assert not marker.exists()


def test_caps_written_into_the_index_are_not_trusted(capsys, room):
    path = _index(capsys)
    small = json.dumps({"max_bytes": 1, "step_bytes": 1}, sort_keys=True)
    _sql(path, ("UPDATE meta SET value = ? WHERE key = 'caps'", (small,)))
    code, body = tine(capsys, "transcripts", "search", "tests", "--repo", "r")
    assert code == 0 and "the size caps differ" in body["stale_reasons"]


def test_a_deleted_row_is_stale_even_when_the_runs_digest_is_kept(capsys, room):
    path = _index(capsys)
    _sql(path, ("DELETE FROM transcripts WHERE run = ?", (room["runs"]["hack1"],)))
    code, body = tine(capsys, "transcripts", "similar", "heads/hack2", "--repo", "r")
    assert code == 0 and body["stale"] is True
    assert "the indexed runs differ from the repository's runs" in body["stale_reasons"]


def test_a_planted_row_for_a_run_not_in_the_repository_is_never_a_hit(capsys, room):
    path = _index(capsys)
    with closing(sqlite3.connect(path)) as db:
        row = db.execute("SELECT * FROM transcripts WHERE run = ?", (room["runs"]["hack1"],))
        row = list(row.fetchone())
    row[0] = "run:" + "f" * 64
    _sql(path, ("INSERT INTO transcripts VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(row)))
    code, body = tine(capsys, "transcripts", "similar", "heads/hack2", "--repo", "r")
    assert code == 0 and body["stale"] is True
    assert row[0] not in [h["run"] for h in body["hits"]]


@pytest.mark.parametrize("value", [math.nan, math.inf, 60000.0])
def test_a_non_unit_or_non_finite_vector_is_refused(capsys, room, value):
    path = _index(capsys)
    bad = ann.pack([value] + [0.0] * (te.DIM - 1))
    _sql(path, ("UPDATE transcripts SET vector = ? WHERE run = ?", (bad, room["runs"]["plain1"])))
    code, body = tine(capsys, "transcripts", "similar", "heads/hack2", "--repo", "r")
    assert code == 0 and body["stale"] is True
    assert room["runs"]["plain1"] not in [h["run"] for h in body["hits"]]


def test_a_forged_vector_is_replaced_by_rebuild_and_not_used_as_the_query(capsys, room):
    path = _index(capsys)
    with closing(sqlite3.connect(path)) as db:
        (benign,) = db.execute(
            "SELECT vector FROM transcripts WHERE run = ?", (room["runs"]["plain1"],)
        ).fetchone()
    _sql(path, ("UPDATE transcripts SET vector = ? WHERE run IN (?, ?)",
                (benign, room["runs"]["hack1"], room["runs"]["hack2"])))  # fmt: skip
    code, body = tine(capsys, "transcripts", "similar", "heads/hack2", "-k", "1", "--repo", "r")
    assert code == 0 and body["hits"][0]["run"] != room["runs"]["plain1"]
    code, body = tine(capsys, "transcripts", "index", "--rebuild", "--repo", "r")
    assert body["counts"]["embedded"] == 4 and body["counts"]["reused"] == 0
    code, body = tine(capsys, "transcripts", "similar", "heads/hack2", "-k", "1", "--repo", "r")
    assert [h["run"] for h in body["hits"]] == [room["runs"]["hack1"]]


def _cos(a: str, b: str) -> float:
    backend = te.HashBackend()
    return ann.dot(backend.one(a), backend.one(b))


def test_lookalikes_zero_width_and_base64_do_not_break_similarity():
    text = "sed -i 's/assert result/assert True/' tests/test_core.py and the tests now pass"
    lookalike = text.replace("a", "а").replace("e", "е").replace("o", "о")
    zero_width = "​".join(text)
    wide = text.replace("s", "ｓ")
    encoded = "echo " + base64.b64encode(text.encode()).decode() + " | base64 -d | sh"
    for variant in (lookalike, zero_width, wide, encoded):
        assert _cos(text, variant) >= 0.6, variant[:40]


def test_padding_before_the_behaviour_does_not_push_it_past_the_cap(room):
    words = "thinking about the overall structure of the codebase " * 30
    same = [("model", None, words)] * 40
    doc = tt.transcript(room["repo"], _run(room["repo"], "same", [*same, *HACK]))
    assert not doc.truncated and doc.steps == 3 and "assert True" in doc.text
    distinct = [("model", None, f"{words} {i}") for i in range(40)]
    doc = tt.transcript(room["repo"], _run(room["repo"], "distinct", [*distinct, *HACK]))
    assert doc.truncated and "assert True" in doc.text


def test_a_huge_blob_is_not_read_into_memory(room, monkeypatch):
    run = _run(room["repo"], "huge", [("model", None, "x" * 50_000), *HACK])
    monkeypatch.setattr(tt, "OBJECT_LIMIT", 10_000)
    doc = tt.transcript(room["repo"], run)
    assert doc.truncated and "assert True" in doc.text and "xxxx" not in doc.text


class _NanModel:
    name, dim = "nan-test/1", 2
    weights_path = Path(__file__)

    def embed(self, texts):
        return [[math.nan, 1.0] for _ in texts]


def test_a_model_returning_non_finite_values_is_refused():
    with pytest.raises(ValueError, match="finite"):
        te.load(f"{__name__}:_NanModel").embed(["x"])


def test_rows_that_disagree_with_the_objects_are_found(capsys, room):
    path = _index(capsys)
    _sql(path, ("UPDATE transcripts SET text_sha256 = ? WHERE run = ?",
                ("0" * 64, room["runs"]["hack1"])))  # fmt: skip
    assert ti.verify_rows(room["repo"], path) == [room["runs"]["hack1"]]
    code, body = tine(capsys, "transcripts", "index", "--verify", "--repo", "r")
    assert code == 0 and body["disagreeing"] == [room["runs"]["hack1"]] and body["stale"]
    code, body = tine(capsys, "transcripts", "index", "--rebuild", "--verify", "--repo", "r")
    assert code == 0 and body["disagreeing"] == [] and body["stale"] is False
