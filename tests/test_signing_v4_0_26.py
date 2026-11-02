"""Format v4 signatures (0.26 phase 3): tine-sig/3, tine-attest/2, offline paths."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine._artifact_io import artifact_signature, read_artifact_json
from opentine._format_v4 import FORMAT_ENV
from opentine._signing_v4 import (
    SCHEME_ATTEST_V2,
    SCHEME_V3,
    check_v4_attestation,
    statement_for,
)
from opentine._verify_dataset import merkle_root
from opentine.attest_signing import sign_attestation, verify_attestation
from opentine.graph import RunStatus
from opentine.signing import SignatureError, sign_artifact

HMAC = b"0123456789abcdef0123456789abcdef"
SEED = bytes(range(32))
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _v4(tmp_path, monkeypatch):
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / "home" / name.lower()))
    monkeypatch.setenv(FORMAT_ENV, "4")


def _run(run_id: str = "signed-v4") -> Run:
    run = Run(id=run_id)
    run.add_step(StepKind.think, {"q": "hi"}, {"a": 1})
    run.add_step(StepKind.done, {"text": "ok"})
    run.add_tag("release")
    run.status = RunStatus.completed
    return run


def _signed(tmp_path: Path, name: str = "run.tine", **kwargs) -> Path:
    kwargs.setdefault("sign_key", HMAC)
    return _run(kwargs.pop("run_id", "signed-v4")).save(tmp_path / name, **kwargs)


def test_hmac_round_trip_and_verdicts(tmp_path: Path) -> None:
    path = _signed(tmp_path, key_id="demo", signer="bot", signed_at="2026-11-01T00:00:00Z")
    block = json.loads(path.read_bytes())["signatures"][0]
    assert block["scheme"] == SCHEME_V3 and block["alg"] == "hmac-sha256"
    good = Run.verify_signature(path, hmac_key=HMAC)
    assert (good.ok, good.state, good.key_id, good.signer) == (True, "verified", "demo", "bot")
    assert Run.verify_signature(path, hmac_key=b"x" * 32).state == "mismatch"
    assert Run.verify_signature(path).state == "no-key"
    assert Run.verify_integrity(path).ok and Run.load(path).id == "signed-v4"


def test_ed25519_round_trip(tmp_path: Path) -> None:
    path = _signed(tmp_path, sign_key=SEED, sign_algorithm="ed25519")
    public = bytes.fromhex(json.loads(path.read_bytes())["signatures"][0]["public_key"])
    assert Run.verify_signature(path, public_key=public).state == "verified"
    assert Run.verify_signature(path, trust_embedded=True).state == "verified-tofu"


def test_unsigned_v4_is_unsigned(tmp_path: Path) -> None:
    path = _run().save(tmp_path / "plain.tine")
    assert Run.verify_signature(path, hmac_key=HMAC).state == "unsigned"


def _edit(path: Path, mutate) -> dict:
    document = json.loads(path.read_bytes())
    mutate(document)
    return document


def _event(document: dict) -> dict:
    return next(e for oid, e in document["objects"].items() if oid.startswith("event:"))


@pytest.mark.parametrize(
    ("mutate", "state"),
    [
        (lambda d: d.__setitem__("root", next(o for o in d["objects"] if o[:4] == "blob")), "mismatch"),  # noqa: E501
        (lambda d: _event(d)["body"].__setitem__("cost", 9), "mismatch"),
        (lambda d: d.__setitem__("annotations", []), "mismatch"),
        (lambda d: d["annotations"][0]["body"]["value"].__setitem__("tags", ["x"]), "mismatch"),
        (lambda d: d["signatures"][0].__setitem__("value", "0" * 64), "mismatch"),
        (lambda d: d["signatures"][0].__setitem__("signer", "mallory"), "mismatch"),
        (lambda d: d["signatures"][0].__setitem__("scheme", "tine-sig/2"), "error"),
    ],
    ids=["root", "envelope", "strip-annotations", "annotation", "value", "header", "scheme"],
)  # fmt: skip
def test_tampering_is_detected(tmp_path: Path, mutate, state: str) -> None:
    document = _edit(_signed(tmp_path, signer="bot"), mutate)
    result = Run.verify_signature(document, hmac_key=HMAC)
    assert not result.ok and result.state == state


def test_old_schemes_still_verify_but_are_not_written(tmp_path: Path) -> None:
    signed = [
        p
        for p in sorted((FIXTURES / "compat").glob("*/artifact_signed.tine"))
        if artifact_signature(read_artifact_json(p)) is not None
    ]
    for path in signed:
        result = Run.verify_signature(path, hmac_key=b"compat-golden-signing-key-000001")
        assert result.ok, (path, result)
    assert signed
    with pytest.raises(SignatureError, match="tine-sig/3"):
        sign_artifact({"metadata": {}}, HMAC)
    payload = {
        "claim": {},
        "evidence_ids": [],
        "signer": "me",
        "target_id": "run:sha256:" + "1" * 64,
    }
    with pytest.raises(SignatureError, match="Ed25519 only"):
        sign_attestation(payload, HMAC)


def test_tine_attest_v2_round_trip() -> None:
    payload = {
        "claim": {"ok": 1},
        "evidence_ids": [],
        "signer": "me",
        "target_id": "run:sha256:" + "1" * 64,
    }  # noqa: E501
    block = sign_attestation(payload, SEED, algorithm="ed25519", key_id="k")
    assert block["scheme"] == SCHEME_ATTEST_V2
    stored = {**payload, "signature": block}
    assert verify_attestation(stored, trust_embedded=True).state == "verified-tofu"
    assert verify_attestation({**stored, "claim": {"ok": 2}}, trust_embedded=True).state == (
        "mismatch"
    )


def test_offline_verify_on_a_signed_v4_file(tmp_path: Path, monkeypatch, capsys) -> None:
    from opentine.cli import main

    path = _signed(tmp_path)
    monkeypatch.setenv("V4_TEST_KEY", HMAC.decode())
    main(["verify", str(path), "--offline", "--json", "--key-env", "V4_TEST_KEY"])
    report = json.loads(capsys.readouterr().out)
    checks = {c["name"]: c for c in report["checks"]}
    assert report["ok"] and checks["signature"]["reason"] == "signature.verified"
    assert checks["digest"]["detail"].startswith("root run:sha256:")


def test_dataset_merkle_over_v4_files(tmp_path: Path, capsys) -> None:
    from opentine.cli import main

    data = tmp_path / "data"
    data.mkdir()
    roots = {}
    for name in ("a", "b", "c"):
        path = _run(f"run-{name}").save(data / f"{name}.tine")
        roots[f"run-{name}"] = json.loads(path.read_bytes())["root"]
    main(["verify", str(data), "--offline", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] and report["count"] == 3
    assert {r["run_id"]: r["digest"] for r in report["runs"]} == roots
    assert report["merkle"]["root"] == merkle_root(sorted(roots.items()))


def test_intoto_statement_for_a_v4_run_carries_tine_attest_v2(tmp_path: Path) -> None:
    path = _run().save(tmp_path / "run.tine")
    root = json.loads(path.read_bytes())["root"]
    statement = statement_for(Run.load(path), root, SEED)
    assert statement["subject"][0]["digest"]["sha256"] == root.split(":")[-1]
    record = statement["predicate"]["attestation"]
    assert record["target_id"] == root and record["signature"]["scheme"] == SCHEME_ATTEST_V2
    assert check_v4_attestation(statement, root) is None
    record["target_id"] = "run:sha256:" + "2" * 64
    assert "does not target" in check_v4_attestation(statement, root)


def test_migrate_says_already_v4(tmp_path: Path, capsys) -> None:
    from opentine.cli import main

    path = _run().save(tmp_path / "run.tine")
    before = path.read_bytes()
    main(["migrate", str(path)])
    assert "already format v4" in capsys.readouterr().out
    assert path.read_bytes() == before
