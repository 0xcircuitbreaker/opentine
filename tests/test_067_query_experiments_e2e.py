"""0.67 acceptance, end to end: runs, evals, an experiment manifest and a reproduce
report in one repository, read through ``tine query`` and checked with ``--verify``
and ``tine experiment check``. Every assertion counts rows or findings; nothing is
timed.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _eval_verdict, _experiment, _schemas
from opentine._signing_pins import key_fingerprint
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.query_helpers import add_run, tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

AUTHOR = Ed25519PrivateKey.from_private_bytes(b"\x41" * 32)
SCORER = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
LOOP = Ed25519PrivateKey.from_private_bytes(b"\x43" * 32)
AT = "2026-11-20T10:00:00Z"
SCORES = ("1", "0.5", "0", "1", "0.75", "0.25", "1", "0")


def _fp(key: Ed25519PrivateKey) -> str:
    return key_fingerprint(key.public_key().public_bytes_raw())


def _d(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _write(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_experiment.dump(doc))


@pytest.fixture
def lab(tmp_path, monkeypatch):
    from opentine.repository import Repo

    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    runs = [add_run(repo, f"run{i}", cost=0.5 * (i + 1)) for i in range(4)]
    text = "version = 1\n[roles]\n"
    text += f"scorer = {json.dumps([_fp(SCORER), _fp(AUTHOR)])}\n"
    text += f"optimizer = {json.dumps([_fp(LOOP)])}\n"
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    for name, key in (("author", AUTHOR), ("loop", LOOP)):
        (tmp_path / f"{name}.key").write_bytes(key.private_bytes_raw().hex().encode("ascii"))
    exp = tmp_path / "exp"
    rows = []
    for i, score in enumerate(SCORES):
        verdict = _eval_verdict.make(
            SCORER, eval=_d("eval"), dataset=_d("data"), item=f"item{i}",
            item_digest=_d(f"item{i}"), run=runs[i % len(runs)], scorer="exact",
            scorer_version="1", score=score, threshold="0.5", created_at=AT,
        )  # fmt: skip
        _write(exp / f"verdicts/item{i}.json", verdict)
        rows.append({"id": f"item{i}", "verdict": _eval_verdict.digest(verdict),
                     "path": f"verdicts/item{i}.json", "score": verdict["score"],
                     "passed": verdict["passed"]})  # fmt: skip
    _write(exp / "exp.json", {
        "convention": _experiment.CONVENTION, "experiment": "exp-1", "hypothesis": "h",
        "code_digest": _d("code"), "container_digest": None,
        "model": {"id": "example-model", "version": "1"}, "sampling": {"temperature": 0},
        "seeds": [7], "data": [{"name": "dev", "commitment": _d("data")}],
        "compute": {"usd": 2.5, "gpu_hours": None, "tokens": None}, "results": rows,
        "conclusion": "5 of 8 pass", "created_at": AT,
    })  # fmt: skip
    return {"base": tmp_path, "repo": repo, "exp": exp}


def _q(capsys, sql: str, *extra: str) -> tuple[int, dict]:
    code, body = tine(capsys, "query", sql, "--repo", "r", *extra)
    _schemas.validate(body, "tine-cli-query-1")
    return code, body


def _prepare(capsys, lab: dict, report_key: str = "author.key") -> dict:
    exp = lab["exp"]
    code, out = tine(capsys, "experiment", "sign", str(exp / "exp.json"), "--key", "author.key",
                     "--at", AT)  # fmt: skip
    assert code == 0, out
    code, out = tine(capsys, "reproduce", str(exp / "exp.json"), "--sample", "4", "--key",
                     report_key, "--out", str(exp / "report.json"))  # fmt: skip
    assert code == 0, out
    code, body = tine(capsys, "query", "index", "--rebuild", "--experiments", "exp",
                      "--repo", "r")  # fmt: skip
    assert code == 0, body
    return body


def test_acceptance_query_experiments_and_reproductions(lab, capsys):
    body = _prepare(capsys, lab)
    counts = body["counts"]
    assert (counts["runs"], counts["steps"]) == (4, 8)
    assert (counts["experiments"], counts["experiment_results"], counts["reproductions"]) == (
        1, 8, 1)  # fmt: skip
    assert body["experiments"] == [lab["exp"].resolve().as_posix()] and body["stale"] is False

    code, out = _q(capsys, "SELECT COUNT(*) AS n, SUM(passed) AS ok FROM experiment_results")
    assert code == 0 and out["rows"] == [{"n": 8, "ok": 5}]
    code, out = _q(capsys, "SELECT COUNT(*) AS n, SUM(cost) AS usd FROM costs")
    assert out["rows"] == [{"n": 8, "usd": 5.0}]
    code, out = _q(capsys, "SELECT r.sample, r.agreed, r.disagreed, r.verdict FROM "
                   "reproductions r JOIN experiments e ON r.manifest = e.oid")  # fmt: skip
    assert out["rows"] == [{"sample": 4, "agreed": 4, "disagreed": 0, "verdict": "agree"}]

    for table, n in (("experiments", 1), ("experiment_results", 8), ("reproductions", 1)):
        code, out = _q(capsys, f"SELECT * FROM {table}", "--verify", "--strict")
        assert code == 0, out["verification"]
        assert out["verification"]["counts"] == {"verified": n, "unverified": 0, "failed": 0}

    code, out = tine(capsys, "experiment", "check", str(lab["exp"] / "exp.json"), "--repo", "r")
    assert code == 0 and not [f for f in out["findings"] if f["level"] == "fail"]
    code, out = tine(capsys, "experiment", "check", str(lab["exp"] / "report.json"),
                     "--manifest", str(lab["exp"] / "exp.json"), "--repo", "r")  # fmt: skip
    assert code == 0 and not [f for f in out["findings"] if f["level"] == "fail"]


def test_a_changed_manifest_is_stale_and_its_rows_fail_verify(lab, capsys):
    _prepare(capsys, lab)
    path = lab["exp"] / "exp.json"
    doc = json.loads(path.read_bytes())
    doc["results"][2]["passed"] = True  # claim one more pass after signing
    path.write_bytes(_experiment.dump(doc))
    code, out = _q(capsys, "SELECT oid, id, passed FROM experiment_results", "--verify")
    assert out["stale"] is True and "an experiment folder changed" in out["stale_reasons"]
    assert code == 1 and out["verification"]["counts"]["failed"] == 8
    code, out = tine(capsys, "experiment", "check", str(path), "--repo", "r")
    codes = {f["code"] for f in out["findings"]}
    assert (
        code == 1 and {"fail:experiment.bad-signature", "fail:experiment.result-mismatch"} <= codes
    )


def test_an_edited_index_row_fails_and_an_optimizer_report_does_not_verify(lab, capsys):
    _prepare(capsys, lab, report_key="loop.key")
    path = lab["repo"].path / "query" / "index.sqlite"
    with closing(sqlite3.connect(path)) as db:
        db.execute("UPDATE experiment_results SET score = 1 WHERE id = 'item2'")
        db.commit()
    code, out = _q(capsys, "SELECT oid, id, score FROM experiment_results", "--verify")
    assert code == 1 and out["verification"]["counts"] == {
        "verified": 7, "unverified": 0, "failed": 1}  # fmt: skip
    code, out = _q(capsys, "SELECT oid, agreed FROM reproductions", "--verify")
    assert code == 0 and out["verification"]["counts"]["unverified"] == 1
    code, out = _q(capsys, "SELECT oid, agreed FROM reproductions", "--verify", "--strict")
    assert code == 1
