"""0.75: eval selection, withdrawals, offline verification and the query tables."""

from __future__ import annotations

import json

import pytest

from opentine import _dataset_claims as dc
from opentine import _dataset_version as dv
from opentine import _eval_verdict
from tests.dataset_contrib_helpers import annotate
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_075_dataset_curate import (  # noqa: F401
    AT,
    STRANGER,
    _cli,
    _curate,
    _pin,
    _run,
    _seed_taints,
    keys_fixture,
    repo_fixture,
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
EVAL = "sha256:" + "a" * 64


def test_failures_of_an_eval_select_only_signed_failing_runs(capsys, repo, keys, tmp_path):
    _pin(repo)
    runs = [_run(repo, i) for i in range(4)]
    folder = tmp_path / "evals"
    folder.mkdir()
    lines = []
    for i, run in enumerate(runs):
        verdict = _eval_verdict.make(
            b"\x0a" * 32, eval=EVAL, dataset="sha256:" + "b" * 64, item=f"q{i}",
            item_digest="sha256:" + "c" * 64, run=run, scorer="exact", scorer_version="1",
            score=i % 2, threshold=1, created_at=AT)  # fmt: skip
        lines.append(json.dumps(verdict, sort_keys=True))
    forged = json.loads(lines[1])
    forged["passed"] = False
    lines.append(json.dumps(forged, sort_keys=True))
    (folder / "verdicts.jsonl").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    code, body = _curate(capsys, repo, keys, "--evals", str(folder),
                         select=f"failures of eval {EVAL}")  # fmt: skip
    assert code == 0, body
    assert sorted(body["members"]) == sorted([runs[0], runs[2]])
    code, body = _curate(capsys, repo, keys, "--evals", str(folder),
                         select=f"eval:{EVAL} and not failures:{EVAL}")  # fmt: skip
    assert sorted(body["members"]) == sorted([runs[1], runs[3]])
    assert body["version"] == 2 and body["previous"]


def test_a_withdrawn_run_leaves_later_versions_with_a_tombstone(capsys, repo, keys):
    _pin(repo)
    runs = [_run(repo, i) for i in range(3)]
    _, first = _curate(capsys, repo, keys)
    assert set(first["members"]) == set(runs)
    annotate(repo, runs[1], STRANGER)  # the contributor's licence annotation on its run
    code, out = _cli(capsys, "dataset", "withdraw", runs[1], "--reason", "other",
                     "--key", str(keys["stranger"]), "--at", AT, "--repo",
                     str(repo.path.parent), "--json")  # fmt: skip
    assert code == 0, out
    _, second = _curate(capsys, repo, keys)
    assert runs[1] not in second["members"] and second["withdrawn"] == [runs[1]]
    (stone,) = second["tombstones"]
    claim = repo.get(stone).payload()["claim"]
    assert claim["version"] == first["record"] and claim["run"] == runs[1]
    assert dc.check_record(claim) == []


def test_unpinned_roles_leave_a_version_unverified(capsys, repo, keys):
    _run(repo, 1)
    code, body = _curate(capsys, repo, keys)
    assert code == 0
    (row,) = dv.versions(repo)
    assert row["verification"].startswith("unverified: ")
    code, check = _cli(capsys, "dataset", "verify-version", body["record"], "--repo",
                       str(repo.path.parent), "--json")  # fmt: skip
    assert code == 0 and check["ok"] and check["signature"] == "verified-tofu"


def test_verify_version_fails_an_edited_payload(capsys, repo, keys, tmp_path):
    _pin(repo)
    runs = [_run(repo, i) for i in range(3)]
    _, body = _curate(capsys, repo, keys)
    payload = repo.get(body["record"]).payload()
    payload["claim"]["members"] = payload["claim"]["members"][:2]
    path = tmp_path / "edited.json"
    path.write_bytes(json.dumps(payload).encode("utf-8"))
    code, check = _cli(capsys, "dataset", "verify-version", "--file", str(path), "--json")
    assert code == 1 and not check["ok"] and len(runs) == 3
    assert "members_digest does not match the members" in check["problems"]


def test_versions_and_members_are_queryable_with_per_row_verify(capsys, repo, keys):
    _pin(repo)
    tainted = [_run(repo, i) for i in range(10)]
    clean = [_run(repo, i) for i in range(10, 13)]
    _seed_taints(repo, tainted)
    _, body = _curate(capsys, repo, keys)
    root = str(repo.path.parent)
    code, out = _cli(capsys, "query", "SELECT oid, name, version, members, excluded, mode FROM"
                     " dataset_versions", "--verify", "--repo", root, "--json")  # fmt: skip
    assert code == 0, out
    assert out["rows"] == [{"oid": body["record"], "name": "train", "version": 1, "members": 3,
                            "excluded": 10, "mode": "default"}]  # fmt: skip
    assert [c["status"] for c in out["verification"]["rows"]] == ["verified"]
    code, out = _cli(capsys, "query", "SELECT run FROM dataset_members ORDER BY run", "--repo",
                     root, "--json")  # fmt: skip
    assert [r["run"] for r in out["rows"]] == sorted(clean)
