"""0.47: Reviews, their signed gate decisions and ``caps.reviews`` (SPEC 4.19, 8.19).

The 70-review family agrees in Python and the pyz (the TS verifier runs it in
``ts/verifier``'s conformance test); ``tine review`` writes a chain only a
reviewer can extend and gate decisions only a reviewer can sign; an exported
Review verifies with the built ``tine-verify.pyz`` (which refuses every network
call), every gate decision included; ``tine serve`` stores Reviews as signed
and answers a uniform 404.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _eval_verdict, _review, _schemas, cli
from opentine._cli_errors import VERIFICATION_FAILED
from opentine._pyz import _review as pyz
from opentine._pyz import _reviewfile as pyz_file
from opentine._pyz_build import build_bytes
from opentine.repository import Repo
from opentine.repository import _review_store as store
from tests.conformance import tagged
from tests.test_0461_projects import _remote

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "docs/conformance/vectors/70-review.json").read_text("utf-8"))["cases"]
SEED, STRANGER = "ab" * 32, "cd" * 32
RUN = "run:sha256:" + "1" * 64


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


def _answer(verifier: str, op: str, value: dict):
    if op == "review.verify":
        if verifier == "python":
            return _review.check(value["version"], previous=value["previous"],
                                 reviewer_key=value["reviewer_key"])  # fmt: skip
        return pyz.review_verify(value["version"], value["previous"], value["reviewer_key"])
    if op == "review-gate.verify":
        check = _review.check_gate if verifier == "python" else pyz.gate_verify
        return check(value["decision"], value["version"])
    if verifier == "python":
        return _review.verify_bundle(value["bundle"], reviewer_key=value["reviewer_key"])
    return pyz_file.bundle_verify(value["bundle"], value["reviewer_key"])


@pytest.mark.parametrize("verifier", ["python", "pyz"])
def test_the_68_family_agrees_in_python_and_the_pyz(verifier):
    assert len(CASES) == 40
    for case in CASES:
        value = tagged.decode(case["input"]["value"])
        if case["expect"] == "accept":
            assert _answer(verifier, case["op"], value) == case["output"], case["id"]
        else:
            with pytest.raises(ValueError) as caught:
                _answer(verifier, case["op"], value)
            assert caught.value.code == case["reason"], case["id"]  # type: ignore[attr-defined]


def test_the_record_schemas_hold_the_accepted_vectors():
    seen = set()
    for case in CASES:
        if case["expect"] != "accept":
            continue
        value = tagged.decode(case["input"]["value"])
        for record in (value.get("version"), value.get("decision"), value.get("bundle")):
            if record is not None:
                stem, errors = _schemas.validate(record)
                assert errors == [], (case["id"], errors)
                seen.add(stem)
    assert seen == {"opentine-review-1", "opentine-review-gate-1", "opentine-review-bundle-1"}


# --- tine review, locally ---------------------------------------------------- #


@pytest.fixture
def repo(tmp_path) -> Repo:
    store_ = Repo.init(tmp_path / "r")
    (tmp_path / "alice.key").write_text(SEED, encoding="utf-8")
    (tmp_path / "bob.key").write_text(STRANGER, encoding="utf-8")
    return store_


def _hex(seed: str) -> str:
    return (
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
        .public_key()
        .public_bytes_raw()
        .hex()
    )


def _review_cli(capsys, repo: Repo, *argv: str, key: str | None = "alice") -> tuple[int, dict]:
    extra = (
        ("--ed25519-key-file", (repo.path.parent.parent / f"{key}.key").as_posix()) if key else ()
    )
    code, out = _tine(capsys, "review", *argv, *extra, "--repo", repo.path.parent.as_posix(),
                      "--json")  # fmt: skip
    document = json.loads(out) if out.strip().startswith("{") else {}
    if code == 0:
        assert _schemas.validate_output(document) == [], document
    return code, document


def _built(capsys, repo: Repo) -> None:
    code, _ = _review_cli(capsys, repo, "create", "auth", "--title", "Rework auth",
                          "--code-repo", "app=app", "--code-repo", "infra", "--gate", "ship",
                          "--reviewer", _hex(STRANGER))  # fmt: skip
    assert code == 0
    code, out = _review_cli(capsys, repo, "add", "auth", "--run", RUN, "--commit", "a" * 40,
                            "--at", "infra", "--finding", "high:a token is logged",
                            "--monitor", "coverage", "--score", "0.9",
                            "--threshold", "0.8")  # fmt: skip
    assert code == 0 and out["version"]["seq"] == 1, out
    subjects = [{"repo": "infra", "type": "run", "id": RUN},
                {"repo": "infra", "type": "commit", "id": "a" * 40}]  # fmt: skip
    assert out["version"]["subjects"] == subjects


def test_create_add_gate_show_export_verify(repo, capsys, tmp_path):
    _built(capsys, repo)
    code, out = _review_cli(capsys, repo, "gate", "auth", "ship", "--approve", "--reason", "ok",
                            key="bob")  # fmt: skip
    assert code == 0 and out["gate"]["decision"] == "approve", out
    code, out = _review_cli(capsys, repo, "show", "auth", key=None)
    assert out["result"]["status"] == "approved" and out["result"]["gates"] == {"ship": "approved"}
    bundle = tmp_path / "auth.review.json"
    code, out = _review_cli(capsys, repo, "export", "auth", "-o", bundle.as_posix(), key=None)
    assert code == 0 and json.loads(bundle.read_text("utf-8"))["kind"] == "opentine.review-bundle"
    code, out = _review_cli(capsys, repo, "verify", bundle.as_posix(), "--reviewer-key",
                            _hex(SEED), key=None)  # fmt: skip
    assert code == 0 and out["result"]["state"] == "verified" and out["result"]["decisions"] == 1
    assert repo.fsck().ok


def test_only_reviewers_extend_the_chain_or_decide(repo, capsys, tmp_path):
    _built(capsys, repo)
    (tmp_path / "eve.key").write_text("ef" * 32, encoding="utf-8")
    before = store.load(repo, "auth")
    code, _ = _review_cli(capsys, repo, "add", "auth", "--gate", "deploy", key="eve")
    assert code == VERIFICATION_FAILED and store.load(repo, "auth") == before
    code, _ = _review_cli(capsys, repo, "gate", "auth", "ship", "--approve", key="eve")
    assert code == VERIFICATION_FAILED and store.load(repo, "auth") == before


def test_a_failing_monitor_blocks_an_approval_but_not_a_reject(repo, capsys):
    _built(capsys, repo)
    code, _ = _review_cli(capsys, repo, "add", "auth", "--monitor", "intent-drift",
                          "--score", "0.4", "--threshold", "0.7")  # fmt: skip
    assert code == 0
    code, _ = _review_cli(capsys, repo, "gate", "auth", "ship", "--approve")
    assert code == VERIFICATION_FAILED
    code, out = _review_cli(capsys, repo, "gate", "auth", "ship", "--reject", "--reason", "drift")
    assert code == 0
    code, out = _review_cli(capsys, repo, "show", "auth", key=None)
    assert out["result"]["status"] == "rejected"


def test_a_monitor_takes_its_score_from_a_signed_eval_verdict(repo, capsys, tmp_path):
    _built(capsys, repo)
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
    verdict = _eval_verdict.make(
        signer, eval="sha256:" + "1" * 64, dataset="sha256:" + "2" * 64, item="i1",
        item_digest="sha256:" + "3" * 64, run=RUN, scorer="exact", scorer_version="1",
        score=0.95, threshold=0.9, created_at="2026-11-09T00:00:00Z",
    )  # fmt: skip
    path = tmp_path / "verdict.json"
    path.write_text(json.dumps(verdict), encoding="utf-8")
    code, out = _review_cli(capsys, repo, "add", "auth", "--monitor", "risk", "--verdict",
                            path.as_posix())  # fmt: skip
    assert code == 0, out
    risk = [m for m in out["version"]["monitors"] if m["name"] == "risk"][0]
    assert risk == {"name": "risk", "scorer": "exact", "score": "0.95", "threshold": "0.9",
                    "passed": True, "verdict": _eval_verdict.digest(verdict)}  # fmt: skip


def test_import_adopts_an_extension_and_refuses_a_fork(repo, capsys, tmp_path):
    _built(capsys, repo)
    exported = store.load(repo, "auth")
    other = Repo.init(tmp_path / "other")
    assert store.install(other, {**exported, "versions": exported["versions"][:1]}) == {
        "versions": 1, "decisions": 0}  # fmt: skip
    assert store.install(other, exported)["versions"] == 1
    assert store.load(other, "auth") == exported
    forked = _review.sign(_review.build("auth", previous=exported["versions"][0],
                                        **{k: exported["versions"][0][k] for k in (
                                            "title", "reviewers", "repos", "gates")},
                                        updated_at="2030-01-01T00:00:00Z"),
                          Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED)))  # fmt: skip
    with pytest.raises(ValueError):
        store.install(other, _review.bundle([exported["versions"][0], forked], []))


# --- the built pyz, offline -------------------------------------------------- #


def test_the_built_pyz_verifies_an_exported_review_with_every_gate_decision(repo, capsys, tmp_path):
    _built(capsys, repo)
    assert _review_cli(capsys, repo, "gate", "auth", "ship", "--approve", key="bob")[0] == 0
    bundle = tmp_path / "auth.review.json"
    assert _review_cli(capsys, repo, "export", "auth", "-o", bundle.as_posix(), key=None)[0] == 0
    pyz_path = tmp_path / "tine-verify.pyz"
    pyz_path.write_bytes(build_bytes())

    def run(path: Path) -> tuple[int, dict]:
        argv = [sys.executable, "-I", "-S", pyz_path.as_posix(), path.as_posix()]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=tmp_path)
        return done.returncode, json.loads(done.stdout)

    code, result = run(bundle)
    assert code == 0 and result["mode"] == "review" and result["verdict"] == "pass"
    assert [c["name"] for c in result["checks"]] == ["review", "review-gate"]
    assert result["checks"][0]["status"] == "approved"
    assert result["checks"][1]["signer"] == _hex(STRANGER)
    value = json.loads(bundle.read_text("utf-8"))
    value["decisions"][0]["reason"] = "forged"
    forged = tmp_path / "forged.review.json"
    forged.write_text(json.dumps(value), encoding="utf-8")
    code, result = run(forged)
    assert code == 1 and result["checks"][0]["reason"] == "review-gate.bad-signature"


# --- tine serve: caps.reviews ------------------------------------------------ #


def test_push_to_tine_serve_and_read_back_a_verifiable_bundle(repo, capsys, tmp_path, monkeypatch):
    service, http = _remote(tmp_path, monkeypatch)
    assert service.capabilities()["reviews"]["path"] == "reviews"
    _built(capsys, repo)
    assert _review_cli(capsys, repo, "gate", "auth", "ship", "--approve", key="bob")[0] == 0
    remote = ("--remote", "https://remote", "--tenant", "acme", "--token", "w")
    code, out = _review_cli(capsys, repo, "push", "auth", *remote, key=None)
    assert code == 0 and (out["versions"], out["decisions"]) == (2, 1), out
    code, out = _review_cli(capsys, repo, "push", "auth", *remote, key=None)
    assert code == 0 and (out["versions"], out["decisions"]) == (0, 0)
    read = http("r").get("/v1/tenants/acme/reviews/auth")
    assert read.status_code == 200 and read.json()["bundle"] == store.load(repo, "auth")
    assert _review.verify_bundle(read.json()["bundle"])["status"] == "approved"
    other = http("o").get("/v1/tenants/acme/reviews/auth")
    nowhere = http("o").get("/v1/tenants/nobody/reviews/auth")
    assert (other.status_code, other.content) == (nowhere.status_code, nowhere.content)
    missing = http("r").get("/v1/tenants/acme/reviews/none")
    assert missing.status_code == 404 and missing.json() == {"error": "not found"}
    assert "reviews/auth" not in http("r").get("/v1/tenants/acme/refs").json()["refs"]
    head = read.json()["head"]
    reader = http("r").put("/v1/tenants/acme/reviews/auth", json={"expected_old": head,
                                                                 "version": {}})  # fmt: skip
    assert reader.status_code == 403


def test_a_repeated_decision_is_stored_once_and_the_lock_is_released(repo, capsys):
    _built(capsys, repo)
    assert _review_cli(capsys, repo, "gate", "auth", "ship", "--reject")[0] == 0
    current = store.load(repo, "auth")
    store.decide(repo, current["decisions"][-1])
    assert store.load(repo, "auth") == current
    assert not list(store._path(repo, "auth").parent.glob("*.lock"))


def test_the_remote_store_publishes_a_record_whole_or_not_at_all(tmp_path):
    from opentine.remote import _review_store as remote

    record = {"review_id": "auth", "seq": 0, "x": 1}
    assert remote.append(tmp_path, "acme", record) is True
    assert remote.append(tmp_path, "acme", {**record, "x": 2}) is False
    folder = tmp_path / ".reviews" / "acme" / "auth" / "v"
    assert sorted(p.name for p in folder.iterdir()) == ["00000000.json"]
    assert remote.versions(tmp_path, "acme", "auth") == [record]
