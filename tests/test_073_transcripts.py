"""0.74 (release 0.73.0) ``tine transcripts``: the derived embedding index over run transcripts.

Build, staleness, incremental reuse, caps, ``search`` and ``similar``, the
backend digest, and a local model backend whose weights digest is recorded and
pinned (a file next to the test; nothing is downloaded).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from opentine import _schemas
from opentine import _transcript_embed as te
from opentine import _transcript_index as ti
from opentine._transcript_text import Caps, transcript
from opentine.graph import Run, StepKind
from opentine.repository import Repo
from tests.query_helpers import tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _run(repo: Repo, name: str, steps: list[tuple[str, str | None, str]]) -> str:
    run = Run(id=name, model_info="m")
    for kind, tool, text in steps:
        extra = {"tool_info": {"name": tool}} if tool else {}
        run.add_step(StepKind(kind), {"text": text}, {"text": "ok"}, **extra)
    return repo.put_run(run, ref=f"heads/{name}").run_id


HACK = [("tool", "shell", "sed -i 's/assert result/assert True/' tests/test_core.py"),
        ("model", None, "the tests now pass so the task is complete")]  # fmt: skip


@pytest.fixture
def room(tmp_path, monkeypatch):
    return make_room(tmp_path, monkeypatch)


def make_room(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    runs = {
        "hack1": _run(repo, "hack1", [("model", None, "read the issue about parsing"), *HACK]),
        "hack2": _run(repo, "hack2", [*HACK, ("tool", "shell", "git commit -am done")]),
        "plain1": _run(repo, "plain1", [("tool", "read_file", "cat docs/guide.md"),
                                        ("model", None, "summarised the guide for the user")]),
        "plain2": _run(repo, "plain2", [("tool", "search", "find unused imports in src"),
                                        ("model", None, "removed three unused imports")]),
    }  # fmt: skip
    return {"repo": repo, "runs": runs}


def test_index_records_backend_digest_caps_and_every_run(capsys, room):
    code, body = tine(capsys, "transcripts", "index", "--rebuild", "--repo", "r")
    assert code == 0, body
    _schemas.validate(body, "tine-cli-transcripts-1")
    assert body["authority"] == "non-authoritative" and body["stale"] is False
    assert body["counts"] == {"runs": 4, "embedded": 4, "reused": 0, "truncated": 0}
    assert body["backend_digest"] == te.backend_digest(te.HashBackend())
    assert body["backend"]["name"] == "transcript-hash/1"
    with closing(sqlite3.connect(Path(body["index"]))) as db:
        runs = sorted(r for (r,) in db.execute("SELECT run FROM transcripts"))
    assert runs == sorted(room["runs"].values())


def test_similar_finds_the_trajectory_with_the_same_behaviour(capsys, room):
    code, body = tine(capsys, "transcripts", "similar", "heads/hack1", "-k", "1", "--repo", "r")
    assert code == 0, body
    _schemas.validate(body, "tine-cli-transcripts-1")
    assert body["method"] == "exact" and body["query"] == {"run": room["runs"]["hack1"]}
    assert [h["run"] for h in body["hits"]] == [room["runs"]["hack2"]]
    assert body["indexed"] == 4 and body["candidates"] == 3  # the query run is excluded


def test_search_text_ranks_and_approx_agrees_on_a_small_corpus(capsys, room):
    code, exact = tine(capsys, "transcripts", "search", "unused imports", "-k", "2", "--repo", "r")
    assert code == 0, exact
    assert exact["hits"][0]["run"] == room["runs"]["plain2"]
    assert set(exact["query"]) == {"text_sha256"}
    code, approx = tine(capsys, "transcripts", "search", "unused imports", "-k", "2", "--approx",
                        "--repo", "r")  # fmt: skip
    assert code == 0 and approx["method"] in {"lsh", "exact-fallback"}
    assert approx["hits"][0] == exact["hits"][0]


def test_a_new_run_makes_the_index_stale_and_a_rebuild_reuses_vectors(capsys, room):
    tine(capsys, "transcripts", "index", "--rebuild", "--repo", "r")
    _run(room["repo"], "late", [("model", None, "a later run")])
    code, body = tine(capsys, "transcripts", "search", "later", "--repo", "r")
    assert code == 0 and body["stale"] is True
    assert body["stale_reasons"] == ["runs were added or removed since the build"]
    code, body = tine(capsys, "transcripts", "index", "--refresh", "--repo", "r")
    assert body["counts"] == {"runs": 5, "embedded": 1, "reused": 4, "truncated": 0}
    code, body = tine(capsys, "transcripts", "search", "later", "--repo", "r")
    assert body["stale"] is False and body["indexed"] == 5


def test_changed_caps_are_stale_and_caps_truncate(capsys, room):
    tine(capsys, "transcripts", "index", "--rebuild", "--repo", "r")
    code, body = tine(capsys, "transcripts", "index", "--max-bytes", "64", "--step-bytes", "16",
                      "--repo", "r")  # fmt: skip
    assert code == 0 and body["reasons"] == ["the size caps differ"]
    code, body = tine(capsys, "transcripts", "index", "--rebuild", "--max-bytes", "64",
                      "--step-bytes", "16", "--repo", "r")  # fmt: skip
    assert body["counts"]["truncated"] == 4 and body["counts"]["embedded"] == 4
    doc = transcript(room["repo"], room["runs"]["hack1"], Caps(16, 64))
    assert doc.truncated and len(doc.text.encode("utf-8")) <= 64


def test_an_unresolvable_or_non_run_target_is_refused(capsys, room):
    code, _ = tine(capsys, "transcripts", "similar", "heads/nope", "--repo", "r")
    assert code != 0
    code, _ = tine(capsys, "transcripts", "similar", "--repo", "r")
    assert code != 0


def test_the_hash_backend_is_deterministic_and_its_digest_names_its_parameters():
    a, b = te.HashBackend(), te.HashBackend()
    text = "step 0 tool tool shell\nls -la\n"
    assert a.one(text) == b.one(text)
    assert abs(sum(v * v for v in a.one(text)) - 1.0) < 1e-9
    assert te.digest_of({**a.description(), "dim": 128}) != te.backend_digest(a)


class _TableModel:
    """A tiny local 'model': a fixed vector per word, read from a weights file."""

    name, dim = "table-test/1", 4

    def __init__(self) -> None:
        self.weights_path = Path(__file__).parent / "data" / "transcript_weights.json"
        self.table = json.loads(self.weights_path.read_bytes())

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for text in texts:
            vec = [0.0] * self.dim
            for word in text.split():
                for i, x in enumerate(self.table.get(word, [0, 0, 0, 1])):
                    vec[i] += x
            out.append(vec)
        return out


def test_a_model_backend_records_its_weights_digest_and_a_wrong_pin_is_refused():
    spec = f"{__name__}:_TableModel"
    backend = te.load(spec)
    assert backend.weights_digest.startswith("sha256:")
    assert backend.description()["weights_digest"] == backend.weights_digest
    assert te.load(spec, backend.weights_digest).weights_digest == backend.weights_digest
    with pytest.raises(ValueError, match="does not match the pin"):
        te.load(spec, "sha256:" + "0" * 64)
    with pytest.raises(ValueError, match="locally only"):
        te.load("https://example.invalid/model")


def test_a_model_backend_index_is_searched_only_with_the_backend_given_again(capsys, room):
    spec = f"{__name__}:_TableModel"
    code, body = tine(capsys, "transcripts", "index", "--rebuild", "--backend", spec,
                      "--repo", "r")  # fmt: skip
    assert code == 0 and body["backend"]["adapter"] == spec
    code, _ = tine(capsys, "transcripts", "search", "tests", "--repo", "r")
    assert code != 0  # an adapter named in the (writable) index is never imported
    code, found = tine(capsys, "transcripts", "search", "tests", "--backend", spec,
                       "--repo", "r")  # fmt: skip
    assert code == 0 and found["backend_digest"] == body["backend_digest"]
    assert ti.read_meta(Path(body["index"]))["backend_digest"] == body["backend_digest"]
