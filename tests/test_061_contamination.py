"""0.60: ``tine dataset contamination``: exact oid and MinHash 5-gram near-duplicates.

A planted paraphrase leak (Jaccard >= 0.8 on word 5-grams) is detected with the
threshold recorded; an exact copy is reported by its blob oid, also when it is
stored in the repository; unrelated text is not reported.
"""

from __future__ import annotations

import json
from pathlib import Path

from opentine import _contamination as cont
from opentine import cli
from opentine.repository import Repo

WORDS = ("the committee reviewed every submitted proposal for the regional water project and "
         "found that the northern district had the most urgent need because its reservoir "
         "had fallen below the seasonal minimum for three consecutive years while demand from "
         "new housing grew faster than any forecast had predicted so the board voted to fund "
         "the northern pipeline first and to revisit the southern request next spring")  # fmt: skip
PARAPHRASE = WORDS.replace("next spring", "in the spring").replace("committee", "panel")
OTHER = ("a recipe for bread needs flour water salt and yeast mixed and kneaded until smooth "
         "then left to rise for an hour before baking in a hot oven until golden")  # fmt: skip


def _cli(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _jsonl(path: Path, rows: list[tuple[str, str]]) -> str:
    lines = [json.dumps({"id": i, "input": text}) for i, text in rows]
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    return path.as_posix()


def test_the_planted_paraphrase_is_over_the_threshold_by_construction() -> None:
    score = cont.jaccard(cont.shingles(WORDS), cont.shingles(PARAPHRASE))
    assert 0.8 <= score < 1.0
    assert cont.jaccard(cont.shingles(WORDS), cont.shingles(OTHER)) == 0.0


def test_a_paraphrase_leak_is_detected_and_unrelated_text_is_not(capsys, tmp_path: Path) -> None:
    holdout = _jsonl(tmp_path / "h.jsonl", [("h1", WORDS), ("h2", "a short unique item")])
    corpus = _jsonl(tmp_path / "c.jsonl", [("c1", PARAPHRASE), ("c2", OTHER)])
    code, row = _cli(capsys, "dataset", "contamination", holdout, "--against", corpus,
                     "--repo", tmp_path.as_posix(), "--json")  # fmt: skip
    assert code == 1 and row["ok"] is False and row["exact"] == []
    assert [(n["id"], n["found_in"].rsplit("#", 1)[1]) for n in row["near"]] == [("h1", "c1")]
    assert row["near"][0]["jaccard"] >= 0.8 and row["method"]["threshold"] == 0.8
    assert row["counts"]["candidates"] <= row["counts"]["corpus"]


def test_an_exact_copy_is_found_by_oid_in_a_corpus_and_a_repository(capsys, tmp_path) -> None:
    root = tmp_path / "r"
    repo = Repo.init(root)
    repo.put("blob", b"a short unique item")
    holdout = _jsonl(tmp_path / "h.jsonl", [("h1", WORDS), ("h2", "a short unique item")])
    corpus = _jsonl(tmp_path / "c.jsonl", [("c1", WORDS)])
    code, row = _cli(capsys, "dataset", "contamination", holdout, "--against", corpus,
                     "--repo", root.as_posix(), "--json")  # fmt: skip
    assert code == 1
    found = {e["id"]: e["found_in"] for e in row["exact"]}
    assert found["h2"] == ["repo"] and found["h1"][0].endswith("#c1")
    assert row["exact"][0]["oid"] == cont.oid(WORDS)


def test_a_clean_holdout_is_clean_and_a_higher_threshold_is_recorded(capsys, tmp_path) -> None:
    holdout = _jsonl(tmp_path / "h.jsonl", [("h1", WORDS)])
    corpus = _jsonl(tmp_path / "c.jsonl", [("c1", OTHER), ("c2", PARAPHRASE)])
    code, row = _cli(capsys, "dataset", "contamination", holdout, "--against", corpus,
                     "--threshold", "0.99", "--repo", tmp_path.as_posix(), "--json")  # fmt: skip
    assert code == 0 and row["ok"] and row["method"]["threshold"] == 0.99


def test_lsh_candidates_scale_with_near_matches_not_with_the_corpus() -> None:
    def corpus(n: int) -> list[tuple[str, dict]]:
        text = "filler {} " + OTHER
        rows = [(f"c{i}", {"id": f"c{i}", "input": text.format(i).replace("bread", f"b{i}")})
                for i in range(n)]  # fmt: skip
        return [*rows, ("leak", {"id": "leak", "input": PARAPHRASE})]

    holdout = [{"id": "h1", "input": WORDS}]
    small, large = cont.check(holdout, corpus(20)), cont.check(holdout, corpus(80))
    assert small["counts"]["near"] == large["counts"]["near"] == 1
    assert small["counts"]["candidates"] == large["counts"]["candidates"] == 1
