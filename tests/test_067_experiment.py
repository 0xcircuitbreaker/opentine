"""0.67: experiment manifests, ``tine experiment check`` and ``tine reproduce``."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _eval_verdict, _experiment, _reproduce, _schemas, cli
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

AUTHOR = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
SCORER = Ed25519PrivateKey.from_private_bytes(b"\x32" * 32)
AT = "2026-11-20T10:00:00Z"
SCORES = ("1", "0.5", "0", "1", "0.75", "0.25", "1", "0")


def _d(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    try:
        cli.main([*argv, "--json"])
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip() else {})


def _write(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_experiment.dump(doc))


@pytest.fixture
def lab(tmp_path, monkeypatch):
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "author.key").write_bytes(AUTHOR.private_bytes_raw().hex().encode("ascii"))
    rows = []
    for i, score in enumerate(SCORES):
        verdict = _eval_verdict.make(
            SCORER, eval=_d("eval"), dataset=_d("data"), item=f"item{i}",
            item_digest=_d(f"item{i}"), run=f"run{i}", scorer="exact",
            scorer_version="1", score=score, threshold="0.5", created_at=AT,
        )  # fmt: skip
        rel = f"verdicts/item{i}.json"
        _write(tmp_path / rel, verdict)
        rows.append({"id": f"item{i}", "verdict": _eval_verdict.digest(verdict), "path": rel,
                     "score": verdict["score"], "passed": verdict["passed"],
                     "input": {"x": i}})  # fmt: skip
    draft = {
        "convention": _experiment.CONVENTION, "experiment": "exp-1",
        "hypothesis": "the patch raises exact-match accuracy",
        "code_digest": _d("code"), "container_digest": _d("box"),
        "model": {"id": "example-model", "version": "2026-10-01"},
        "sampling": {"temperature": 0, "max_tokens": 256}, "seeds": [7],
        "data": [{"name": "dev", "commitment": _d("data")}],
        "compute": {"usd": 1.25, "gpu_hours": None, "tokens": 12000},
        "results": rows, "conclusion": "accuracy 0.5625 on dev", "created_at": AT,
    }  # fmt: skip
    _write(tmp_path / "exp.json", draft)
    return tmp_path


def _sign(capsys, lab: Path) -> dict:
    code, out = _tine(capsys, "experiment", "sign", str(lab / "exp.json"),
                      "--key", str(lab / "author.key"), "--at", AT)  # fmt: skip
    assert code == 0, out
    return out


def _check(capsys, lab: Path, *extra: str) -> tuple[int, dict]:
    return _tine(capsys, "experiment", "check", str(lab / "exp.json"), *extra)


def _codes(out: dict) -> list[str]:
    return [f["code"] for f in out["findings"]]


def test_signed_manifest_checks_clean_and_validates(capsys, lab):
    out = _sign(capsys, lab)
    assert out["rows"] == len(SCORES) and _schemas.validate_output(out) == []
    doc = _experiment.load(lab / "exp.json")
    assert _schemas.validate(doc, "opentine-experiment-manifest-1")[1] == []
    code, out = _check(capsys, lab)
    assert code == 0 and out["ok"] and _schemas.validate_output(out) == []
    # verdict signer unpinned: advisory only, blocking with --strict (D12)
    assert set(_codes(out)) == {"advisory:experiment.signer-unpinned"}
    assert _check(capsys, lab, "--strict")[0] == 1


def test_pinned_scorer_clears_the_advisory(capsys, lab):
    repo = Repo.init(lab / "r")
    pub = SCORER.public_key().public_bytes_raw().hex()
    (repo.path / "key-roles.toml").write_bytes(f'version = 1\n[roles]\nscorer = ["{pub}"]\n'
                                               .encode("ascii"))  # fmt: skip
    pin_roles(repo.path)
    _sign(capsys, lab)
    code, out = _check(capsys, lab, "--repo", str(lab / "r"), "--strict")
    assert code == 0 and out["findings"] == []


def test_result_row_disagreeing_with_its_verdict_fails(capsys, lab):
    doc = _experiment.load(lab / "exp.json")
    doc["results"][1]["score"] = "0.9"
    _write(lab / "exp.json", doc)
    _sign(capsys, lab)
    code, out = _check(capsys, lab)
    assert code == 1 and "fail:experiment.result-mismatch" in _codes(out)
    assert {f["row"] for f in out["findings"] if f["level"] == "fail"} == {"item1"}


def test_missing_unsigned_and_swapped_references_fail(capsys, lab):
    _sign(capsys, lab)
    (lab / "verdicts" / "item0.json").unlink()
    tampered = json.loads((lab / "verdicts" / "item2.json").read_bytes())
    tampered["score"] = "1"
    _write(lab / "verdicts" / "item2.json", tampered)
    code, out = _check(capsys, lab)
    assert code == 1
    fails = {(f["code"], f["row"]) for f in out["findings"] if f["level"] == "fail"}
    assert fails == {("fail:experiment.reference-missing", "item0"),
                     ("fail:experiment.reference-unsigned", "item2")}  # fmt: skip


def test_unsigned_or_edited_manifest_fails(capsys, lab):
    code, out = _check(capsys, lab)
    assert code == 1 and "fail:experiment.unsigned" in _codes(out)
    _sign(capsys, lab)
    doc = _experiment.load(lab / "exp.json")
    doc["conclusion"] = "accuracy 0.9 on dev"
    _write(lab / "exp.json", doc)
    code, out = _check(capsys, lab)
    assert code == 1 and "fail:experiment.bad-signature" in _codes(out)


def test_reproduce_agrees_on_a_deterministic_fixture(capsys, lab):
    _sign(capsys, lab)
    argv = ("reproduce", str(lab / "exp.json"), "--sample", "3", "--key",
            str(lab / "author.key"), "--at", AT, "--out", str(lab / "rep.json"))  # fmt: skip
    code, out = _tine(capsys, *argv)
    assert code == 0 and _schemas.validate_output(out) == [], out
    report = out["report"]
    assert report["verdict"] == "agree" and report["agreed"] == 3
    assert report["nondeterministic"] == []
    sel = report["selection"]
    assert sel["population"] == len(SCORES) and len(sel["ids"]) == 3
    assert _tine(capsys, *argv)[1]["report"]["selection"] == sel  # seeded, recorded
    assert (lab / "rep.json").read_bytes() == _experiment.dump(report)
    code, out = _tine(capsys, "experiment", "check", str(lab / "rep.json"))
    assert code == 0 and out["kind"] == "reproduce-report" and out["verdict"] == "agree"


RUNNER = """
COUNT = {"n": 0}
def drift(manifest, row):
    COUNT["n"] += 1
    return {"score": "0.1" if COUNT["n"] % 2 else row["score"],
            "observed": {"seed": 99, "model": {"id": "example-model", "version": "x"},
                         "code_digest": manifest["code_digest"]}}
"""


def test_reproduce_reports_disagreement_and_nondeterministic_fields(capsys, lab):
    _sign(capsys, lab)
    (lab / "runner.py").write_bytes(RUNNER.encode("utf-8"))
    code, out = _tine(capsys, "reproduce", str(lab / "exp.json"), "--sample", "2",
                      "--seed", "5", "--tolerance", "0.05", "--runner",
                      f"{(lab / 'runner.py').as_posix()}:drift",
                      "--key", str(lab / "author.key"), "--at", AT)  # fmt: skip
    report = out["report"]
    assert code == 1 and report["verdict"] == "disagree" and report["selection"]["seed"] == 5
    assert report["nondeterministic"] == ["model", "score", "seeds"]


def test_selection_and_declared_fields_are_pure():
    manifest = {"results": [{"id": f"r{i}"} for i in range(50)], "seeds": [],
                "sampling": {"temperature": 0.7}}  # fmt: skip
    one = _reproduce.select(manifest, 5, seed=1)
    assert one == _reproduce.select(manifest, 5, seed=1) and len(one["ids"]) == 5
    assert _reproduce.declared(manifest) == {"seeds", "sampling"}
    with pytest.raises(ValueError):
        _reproduce.select(manifest, 0, seed=1)


def test_reproduce_refuses_an_unsigned_manifest(capsys, lab):
    code, _ = _tine(capsys, "reproduce", str(lab / "exp.json"), "--sample", "1",
                    "--key", str(lab / "author.key"))  # fmt: skip
    assert code != 0


def test_manifest_problems_name_the_field():
    assert _experiment.problems({"convention": "x"}) == [
        "not an opentine.experiment-manifest/1 document"
    ]
    signer = key_fingerprint(AUTHOR.public_key().public_bytes_raw())
    assert signer.startswith("sha256:")
