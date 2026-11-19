"""0.67 review: a forged or cherry-picked reproduce report does not pass check."""

# ruff: noqa: F811

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _experiment, _reproduce, _signed_doc
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.test_067_experiment import AT, AUTHOR, _sign, _tine, _write, lab  # noqa: F401

OPTIMIZER = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)


def _report(capsys, lab: Path, *extra: str) -> dict:
    _sign(capsys, lab)
    code, out = _tine(capsys, "reproduce", str(lab / "exp.json"), "--sample", "3",
                      "--key", str(lab / "author.key"), "--at", AT, *extra)  # fmt: skip
    assert code == 0, out
    return out["report"]


def _resign(lab: Path, doc: dict, key=AUTHOR) -> Path:
    from opentine._signing_pins import key_fingerprint

    doc = {k: v for k, v in doc.items() if k != "signature"}
    doc["signer"] = key_fingerprint(key.public_key().public_bytes_raw())
    body = {n: doc[n] for n in _reproduce.FIELDS}
    doc["signature"] = _signed_doc.sign(_reproduce.DOMAIN, body, key,
                                        signer=doc["signer"], signed_at=AT)  # fmt: skip
    _write(lab / "rep.json", doc)
    assert _reproduce.verify_report(doc) is None
    return lab / "rep.json"


def _check(capsys, path: Path, *extra: str) -> tuple[int, list[str]]:
    code, out = _tine(capsys, "experiment", "check", str(path), *extra)
    return code, [f["code"] for f in out["findings"]]


def test_cherry_picked_sample_fails_against_the_manifest(capsys, lab):
    doc = _report(capsys, lab)
    rest = sorted({f"item{i}" for i in range(8)} - set(doc["selection"]["ids"]))[:3]
    scores = {r["id"]: r["score"] for r in _experiment.load(lab / "exp.json")["results"]}
    doc["selection"]["ids"] = rest
    for row, rid in zip(doc["rows"], rest, strict=True):
        row.update(id=rid, expected=scores[rid], observed=[scores[rid]] * 2)
    path = _resign(lab, doc)
    assert _check(capsys, path)[0] == 0  # self-consistent without the manifest
    code, codes = _check(capsys, path, "--manifest", str(lab / "exp.json"))
    assert code == 1 and "fail:experiment.report-mismatch" in codes


def test_report_claiming_agreement_beyond_its_tolerance_fails(capsys, lab):
    doc = _report(capsys, lab)
    row = doc["rows"][0]
    row["observed"] = [row["observed"][0]] * 2
    row["expected"] = "0.123" if row["observed"][0] != "0.123" else "0.5"
    code, codes = _check(capsys, _resign(lab, doc))
    assert code == 1 and "fail:experiment.report-mismatch" in codes


def test_hidden_nondeterministic_score_fails(capsys, lab):
    doc = _report(capsys, lab, "--tolerance", "1")
    row = doc["rows"][0]
    row["observed"] = [row["expected"], "0.99999" if row["expected"] != "0.99999" else "0"]
    row["delta"] = str(max(abs(float(x) - float(row["expected"])) for x in row["observed"]))
    assert doc["nondeterministic"] == []
    code, codes = _check(capsys, _resign(lab, doc))
    assert code == 1 and "fail:experiment.report-mismatch" in codes


def test_reproducer_chosen_seed_tolerance_and_single_repeat_are_advisory(capsys, lab):
    _report(capsys, lab, "--seed", "5", "--tolerance", "0.2", "--repeats", "1",
            "--out", str(lab / "rep.json"))  # fmt: skip
    code, codes = _check(capsys, lab / "rep.json", "--manifest", str(lab / "exp.json"))
    assert code == 0 and set(codes) == {
        "advisory:experiment.seed-override", "advisory:experiment.tolerance-chosen",
        "advisory:experiment.single-repeat"}  # fmt: skip
    code, _ = _check(capsys, lab / "rep.json", "--manifest", str(lab / "exp.json"), "--strict")
    assert code == 1


def test_verdict_runner_refuses_a_tampered_verdict_file(capsys, lab):
    _sign(capsys, lab)
    path = lab / "verdicts" / "item0.json"
    verdict = _experiment.load(path)
    verdict["score"] = "0.5" if verdict["score"] != "0.5" else "1"
    _write(path, verdict)
    code, _ = _tine(capsys, "reproduce", str(lab / "exp.json"), "--sample", "8",
                    "--tolerance", "1", "--key", str(lab / "author.key"), "--at", AT)  # fmt: skip
    assert code != 0


def test_report_signed_by_a_pinned_optimizer_key_fails(capsys, lab):
    repo = Repo.init(lab / "r")
    pub = OPTIMIZER.public_key().public_bytes_raw().hex()
    (repo.path / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\noptimizer = ["{pub}"]\n'.encode("ascii"))  # fmt: skip
    pin_roles(repo.path)
    path = _resign(lab, _report(capsys, lab), OPTIMIZER)
    code, codes = _check(capsys, path, "--repo", str(lab / "r"))
    assert code == 1 and "fail:experiment.key-separation" in codes
