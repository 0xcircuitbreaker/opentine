"""0.64 acceptance: Inspect log -> tine -> Inspect keeps sample ids and scores exactly.

Five committed fixtures shaped like the logs Inspect writes for five pinned
inspect_evals tasks (tests/fixtures/inspect/MANIFEST.json); two are ``.eval``
zips, three ``.json``. Each is imported (runs, signed eval verdicts, sandbox
evidence), exported as JSON and as ``.eval``, and read back.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _eval_run
from opentine._inspect_export import collect, prefixes, to_eval_bytes, to_json_bytes
from opentine._inspect_import import import_log
from opentine._inspect_log import parse_log, read_log
from opentine._inspect_verdicts import write_verdicts
from opentine.repository import Repo

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "inspect"
MANIFEST = json.loads((FIXTURES / "MANIFEST.json").read_bytes())
FILES = [row["file"] for row in MANIFEST["fixtures"]]
KEY = bytes(range(32))
WHEN = "2026-11-01T12:00:00Z"


def _identity(log):
    return [(type(s["id"]).__name__, s["id"], s["epoch"], s["scores"], s["target"])
            for s in log["samples"]]  # fmt: skip


def test_the_manifest_pins_five_inspect_evals_tasks_and_a_commit():
    assert len(FILES) == 5 and len({row["task"] for row in MANIFEST["fixtures"]}) == 5
    assert all(row["task"].startswith("inspect_evals/") for row in MANIFEST["fixtures"])
    assert len(MANIFEST["inspect_evals_commit"]) == 40
    assert {Path(f).suffix for f in FILES} == {".eval", ".json"}


@pytest.mark.parametrize("name", FILES)
def test_round_trip_keeps_sample_ids_and_scores_exactly(tmp_path, name):
    original = read_log(FIXTURES / name)
    repo = Repo.init(tmp_path / "r")
    body = import_log(repo, original)
    assert [row["sample_id"] for row in body["samples"]] == [s["id"] for s in original["samples"]]
    exported = collect(repo)
    for data in (to_json_bytes(exported), to_eval_bytes(exported)):
        back = parse_log(data)
        assert sorted(_identity(back), key=repr) == sorted(_identity(original), key=repr)
        assert back["eval"]["task"] == original["eval"]["task"]
    back = parse_log(to_json_bytes(exported))
    assert _identity(back) == _identity(original)  # JSON keeps the log's sample order
    assert [s["messages"] for s in back["samples"]] == [s["messages"] for s in original["samples"]]
    assert back["results"] == original["results"]


def test_exports_are_byte_stable(tmp_path):
    repo = Repo.init(tmp_path / "r")
    import_log(repo, read_log(FIXTURES / "humaneval.eval"))
    log = collect(repo)
    assert to_eval_bytes(log) == to_eval_bytes(collect(repo))
    assert to_json_bytes(log) == to_json_bytes(collect(repo))


def test_sandbox_config_is_the_first_step_of_each_run(tmp_path):
    repo = Repo.init(tmp_path / "r")
    body = import_log(repo, read_log(FIXTURES / "humaneval.eval"))
    for row in body["samples"]:
        first = repo.load_run(row["run"]).steps[0]
        assert first.inputs["inspect.sandbox"] == {"type": "docker", "config": None}
    body = import_log(repo, read_log(FIXTURES / "gsm8k.json"))
    assert "inspect.sandbox" not in repo.load_run(body["samples"][0]["run"]).steps[0].inputs


def test_a_second_import_of_the_same_eval_is_refused(tmp_path):
    repo = Repo.init(tmp_path / "r")
    log = read_log(FIXTURES / "gsm8k.json")
    import_log(repo, log)
    with pytest.raises(ValueError, match="already holds"):
        import_log(repo, log)
    assert len(prefixes(repo)) == 1


@pytest.mark.parametrize("name", FILES)
def test_scores_become_signed_eval_verdicts_that_verify(tmp_path, name):
    log = read_log(FIXTURES / name)
    body = import_log(Repo.init(tmp_path / "r"), log)
    rows = [{"run": r["run"], "sample": s} for r, s in zip(body["samples"], log["samples"])]
    out = write_verdicts(rows, KEY, tmp_path / "evals", created_at=WHEN)
    assert out["scorers"]
    for name_, row in out["scorers"].items():
        result = _eval_run.verify_eval(Path(row["folder"]))
        assert result["ok"], (name_, result["failures"])
        letters = [s["scores"][name_]["value"] for s in log["samples"] if name_ in s["scores"]]
        if all(v in ("C", "I") for v in letters):
            assert result["passed"] == letters.count("C")


def test_a_score_with_no_0_to_1_reading_is_skipped_not_guessed(tmp_path):
    log = read_log(FIXTURES / "boolq.json")
    body = import_log(Repo.init(tmp_path / "r"), log)
    rows = [{"run": r["run"], "sample": s} for r, s in zip(body["samples"], log["samples"])]
    out = write_verdicts(rows, KEY, tmp_path / "evals", created_at=WHEN)
    assert "breakdown" not in out["scorers"]
    assert {row["scorer"] for row in out["skipped"]} == {"breakdown"}


def test_an_edited_verdict_fails_verification(tmp_path):
    log = read_log(FIXTURES / "gsm8k.json")
    body = import_log(Repo.init(tmp_path / "r"), log)
    rows = [{"run": r["run"], "sample": s} for r, s in zip(body["samples"], log["samples"])]
    folder = Path(
        write_verdicts(rows, KEY, tmp_path / "e", created_at=WHEN)["scorers"]["match"]["folder"]
    )
    path = folder / "verdicts.jsonl"
    lines = path.read_bytes().decode("utf-8").splitlines()
    row = json.loads(lines[0])
    row["score"] = "0" if row["score"] == "1" else "1"
    row["passed"] = row["score"] == "1"
    lines[0] = json.dumps(row, sort_keys=True)
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    result = _eval_run.verify_eval(folder)
    assert not result["ok"]
    assert result["failures"][0]["reason"] == "eval-verdict.bad-signature"
