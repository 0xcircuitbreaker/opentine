"""0.60 review: an optimizer with write access tries to dodge canaries and contamination.

Mutated canaries (case, whitespace, zero-width, lookalike letters, JSON
``\\u`` escapes) are still found; a lengths file that scores no counted canary
or a margin that erases the floor is refused; a holdout item chunked across
several corpus items, or written with lookalike letters, is still reported.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _contamination as cont
from opentine._canary import digest
from opentine.repository import Repo
from tests.holdout_helpers import lengths_file
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_061_canary import CANARY, _cli, _register, _scan, root  # noqa: F401
from tests.test_061_contamination import WORDS, _jsonl

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
MUTATIONS = [
    CANARY.upper(),
    CANARY.replace(" ", "   "),
    CANARY.replace("7f3a", "7f​3a"),
    CANARY.replace("a", "а").replace("e", "е"),
    CANARY.replace("tine", "t i n e"),
    json.dumps(CANARY.replace("c", "с"))[1:-1],
]


@pytest.mark.parametrize("index", range(len(MUTATIONS)))
def test_a_mutated_canary_is_still_found(capsys, root: Path, index: int) -> None:  # noqa: F811
    _register(capsys, root, CANARY, 96)
    blob = f"leaked: {MUTATIONS[index]} end".encode()
    assert CANARY.encode() not in blob
    Repo.open(root).put("blob", blob)
    code, row = _scan(capsys, root)
    assert code == 1
    assert [m["canary_sha256"] for m in row["matches"]] == [digest(CANARY)]


def test_scoring_no_counted_canary_is_refused(capsys, root: Path, tmp_path: Path) -> None:  # noqa: F811
    _register(capsys, root, CANARY, 96)
    path = lengths_file(tmp_path / "empty.json", {})
    args = ("dataset", "canary-check", path, "--repo", root.as_posix(), "--json")
    code, row = _cli(capsys, *args)
    assert code == 1
    assert [f["code"] for f in row["findings"]] == [
        "dataset.canary-unscored",
        "dataset.canary-none-scored",
    ]


@pytest.mark.parametrize("margin", ["96", "500", "-1"])
def test_a_margin_that_erases_the_floor_is_an_error(
    capsys,
    root: Path,  # noqa: F811
    tmp_path: Path,
    margin: str,
) -> None:
    _register(capsys, root, CANARY, 96)
    path = lengths_file(tmp_path / "l.json", {digest(CANARY): 1})
    argv = ["dataset", "canary-check", path, f"--margin-bits={margin}"]
    code, row = _cli(capsys, *argv, "--repo", root.as_posix(), "--json")
    assert code != 0 and "error" in row and "margin-bits" in row["error"]["message"]


def test_a_chunked_holdout_item_is_reported_by_coverage(capsys, tmp_path: Path) -> None:
    words = WORDS.split()
    step = len(words) // 3
    thirds = [" ".join(words[i : i + step + 4]) for i in range(0, len(words), step)]
    whole = cont.shingles(WORDS)
    assert all(cont.jaccard(whole, cont.shingles(t)) < 0.8 for t in thirds)
    holdout = _jsonl(tmp_path / "h.jsonl", [("h1", WORDS)])
    corpus = _jsonl(tmp_path / "c.jsonl", [(f"c{i}", t) for i, t in enumerate(thirds)])
    code, row = _cli(capsys, "dataset", "contamination", holdout, "--against", corpus, "--json")
    assert code == 1 and row["near"] == []
    assert [c["id"] for c in row["chunked"]] == ["h1"] and row["chunked"][0]["coverage"] >= 0.8


def test_lookalike_letters_do_not_lower_the_overlap() -> None:
    mutated = WORDS.upper().replace("A", "А").replace("O", "Ο")
    assert cont.jaccard(cont.shingles(WORDS), cont.shingles(mutated)) == 1.0
