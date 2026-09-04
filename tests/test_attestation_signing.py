"""Signed v3 attestations (``tine-attest/1``), the 0.9.0 Spec & Trust gap-closer.

Before this, ``repository.ops.attest`` had a ``signature`` slot nothing ever
filled: a v3 attestation was an unauthenticated claim, and ``--signer`` was
documented, verbatim, as a "Self-asserted signer label". Anyone who could write
to a repository could write ``signer: security-team``. These tests pin the four
properties that make the fix worth having.

* **The signature covers everything that gives the attestation meaning.** One
  test per forgeable field — ``claim``, ``target_id``, ``signer``,
  ``evidence_ids`` — plus the signed header. Each is a distinct forgery, so each
  gets its own case: if ``claim`` could be edited while the signature still
  verified, the feature would be worthless.
* **No false verdicts, ever.** ``unsigned`` for no block, ``no-key`` for a key
  this caller does not hold, ``mismatch`` for anything that does not check out.
  Never ``verified``, and never an exception in place of a verdict.
* **Backwards compatibility is sacred.** An attestation written without a key is
  *byte-identical* to what 0.3.0-0.8.1 wrote — same payload, same stored bytes,
  same oid — it loads out of a released repository, it ``fsck``s clean, and it
  reports ``unsigned`` rather than ``verified``.
* **The operator surface tells the truth.** ``tine attest``/``tine evaluate``
  take ``tine sign``'s key flags; ``tine repo-verify`` is fail-closed the way
  ``tine verify`` is; the human receipt says ``unsigned`` when it is.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from opentine import cli
from opentine._attest_view import ATTEST_DOMAIN_PREFIX, SCHEME_ATTEST_V1, signed_view
from opentine._signing_view import DOMAIN_PREFIX
from opentine.attest_signing import sign_attestation, verify_attestation
from opentine.kernel import ObjectEnvelope
from opentine.repository import Repo
from opentine.signing import HAS_ED25519, SignatureError, generate_ed25519
from opentine.trace import Recorder, TraceEvent

COMPAT = Path(__file__).parent / "fixtures" / "compat"

KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes, the same shape test_signing uses
OTHER_KEY = b"fedcba9876543210fedcba9876543210"

needs_ed25519 = pytest.mark.skipif(not HAS_ED25519, reason="ed25519 needs the crypto extra")


def _legacy_payload(target_id: str, claim: dict[str, Any], signer: str) -> dict[str, Any]:
    """The attestation payload 0.3.0-0.8.1 wrote, spelled out rather than imported.

    Copied from the pre-0.9.0 ``ops.attest`` body on purpose: importing today's
    writer would make the byte-identity test below tautological.
    """
    return {
        "claim": claim,
        "evidence_ids": [],
        "signature": None,
        "signer": signer,
        "target_id": target_id,
    }


@pytest.fixture
def repo_with_run(tmp_path: Path) -> tuple[Repo, str]:
    repo = Repo.init(tmp_path / "repo")
    recorder = Recorder.start(repo, capture=False)
    recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "hello"}))
    run = recorder.finalize()
    repo.update_ref("heads/main", run, expected_old=repo.read_ref("heads/main"))
    return repo, run


@pytest.fixture
def signed(repo_with_run) -> tuple[Repo, str, str, dict[str, Any]]:
    """A repository holding one HMAC-signed attestation, plus its stored payload."""
    repo, run = repo_with_run
    oid = repo.attest(run, {"kind": "approval"}, signer="security-team", key=KEY, key_id="k1")
    return repo, run, oid, repo.get(oid).payload()


# --- round trip --------------------------------------------------------------


def test_hmac_sign_verify_round_trip_is_verified(signed):
    repo, _, oid, payload = signed
    block = payload["signature"]
    assert block["scheme"] == SCHEME_ATTEST_V1 and block["alg"] == "hmac-sha256"
    assert block["key_id"] == "k1" and block["signer"] == "security-team"

    result = repo.verify_attestation(oid, hmac_key=KEY)
    assert (result.ok, result.state, result.reason) == (True, "verified", "ok")
    assert (result.algorithm, result.key_id, result.signer) == (
        "hmac-sha256",
        "k1",
        "security-team",
    )


@needs_ed25519
def test_ed25519_sign_verify_round_trip_is_verified(repo_with_run):
    repo, run = repo_with_run
    seed, public = generate_ed25519()
    oid = repo.attest(
        run, {"kind": "approval"}, signer="release-eng", key=seed, algorithm="ed25519"
    )
    block = repo.get(oid).payload()["signature"]
    assert block["alg"] == "ed25519" and block["public_key"] == public

    assert repo.verify_attestation(oid, public_key=public).state == "verified"
    # TOFU is a *distinct* state: the embedded key is self-asserted.
    tofu = repo.verify_attestation(oid, trust_embedded=True)
    assert tofu.ok and tofu.state == "verified-tofu"
    assert repo.verify_attestation(oid).state == "no-key"


def test_the_signature_survives_a_reopen_because_it_covers_stored_bytes(signed, tmp_path):
    repo, _, oid, _ = signed
    reopened = Repo.open(repo.path.parent)
    assert reopened.verify_attestation(oid, hmac_key=KEY).state == "verified"


def test_a_claim_holding_a_credential_is_signed_as_stored_not_as_passed(repo_with_run):
    """Repo.put redacts; signing the caller's dict would make every such attestation mismatch."""
    repo, run = repo_with_run
    oid = repo.attest(run, {"api_key": "sk-abcdefghijklmnop"}, signer="op", key=KEY)
    assert repo.get(oid).payload()["claim"] == {"api_key": "[REDACTED]"}
    assert repo.verify_attestation(oid, hmac_key=KEY).state == "verified"


# --- tamper detection, one field at a time -----------------------------------


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("claim", {"kind": "revoked"}),
        ("signer", "attacker"),
        ("evidence_ids", ["attestation:sha256:" + "0" * 64]),
    ],
    ids=["claim", "signer", "evidence_ids"],
)
def test_editing_a_signed_field_reports_mismatch(signed, field, forged):
    _, _, _, payload = signed
    assert verify_attestation({**payload, field: forged}, hmac_key=KEY).state == "mismatch"


def test_editing_the_target_id_reports_mismatch(repo_with_run):
    """The forgery that matters most: moving an approval onto a different run."""
    repo, run = repo_with_run
    recorder = Recorder.start(repo, capture=False)
    recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "other"}))
    other = recorder.finalize()
    oid = repo.attest(run, {"kind": "approval"}, signer="security-team", key=KEY)
    payload = repo.get(oid).payload()
    assert payload["target_id"] == run and other != run

    forged = {**payload, "target_id": other}
    assert verify_attestation(forged, hmac_key=KEY).state == "mismatch"


@pytest.mark.parametrize(
    ("key", "value"),
    [("key_id", "k2"), ("signed_at", "2026-09-04T00:00:00Z"), ("signer", "attacker")],
    ids=["key_id", "signed_at", "block-signer"],
)
def test_editing_the_signed_header_reports_mismatch(signed, key, value):
    _, _, _, payload = signed
    block = {**payload["signature"], key: value}
    assert verify_attestation({**payload, "signature": block}, hmac_key=KEY).state == "mismatch"


def test_dropping_a_header_field_reports_mismatch(signed):
    """An absent key_id is signed *as absent*, so it cannot be removed afterwards."""
    _, _, _, payload = signed
    block = {name: item for name, item in payload["signature"].items() if name != "key_id"}
    assert verify_attestation({**payload, "signature": block}, hmac_key=KEY).state == "mismatch"


def test_swapping_the_scheme_is_an_error_not_a_downgrade(signed):
    _, _, _, payload = signed
    block = {**payload["signature"], "scheme": "tine-sig/2"}
    result = verify_attestation({**payload, "signature": block}, hmac_key=KEY)
    assert (result.ok, result.state, result.reason) == (
        False,
        "error",
        "unsupported signature scheme",
    )


def test_the_two_families_cannot_share_a_signature():
    """Distinct domain prefixes, so no artifact signature can be lifted onto an attestation."""
    assert ATTEST_DOMAIN_PREFIX != DOMAIN_PREFIX
    view = signed_view({"claim": {}, "signer": "op", "signature": {"value": "x"}}, {})
    assert "signature" not in view["body"], "the value being computed cannot be inside the view"
    assert set(view["header"]) == {"alg", "key_id", "scheme", "signed_at", "signer"}


# --- no false verdicts -------------------------------------------------------


def test_an_attestation_written_without_a_key_is_unsigned_never_verified(repo_with_run):
    repo, run = repo_with_run
    oid = repo.attest(run, {"kind": "approval"}, signer="security-team")
    assert repo.get(oid).payload()["signature"] is None
    for keys in ({}, {"hmac_key": KEY}, {"trust_embedded": True}):
        result = repo.verify_attestation(oid, **keys)
        assert (result.ok, result.state) == (False, "unsigned"), keys


def test_the_wrong_key_is_mismatch_and_no_key_at_all_is_no_key(signed):
    repo, _, oid, _ = signed
    assert repo.verify_attestation(oid, hmac_key=OTHER_KEY).state == "mismatch"
    no_key = repo.verify_attestation(oid)
    assert (no_key.ok, no_key.state) == (False, "no-key")
    # The verdict is returned, never raised: a caller must not need a try block.
    assert no_key.reason == "HMAC signature present but no key supplied"


@pytest.mark.parametrize(
    "block",
    [
        "not-an-object",
        {"alg": "hmac-sha256", "scheme": SCHEME_ATTEST_V1},
        {"alg": "hmac-sha256", "scheme": SCHEME_ATTEST_V1, "value": "zz"},
        {"alg": "md5", "scheme": SCHEME_ATTEST_V1, "value": "0" * 64},
        {"alg": "hmac-sha256", "scheme": SCHEME_ATTEST_V1, "value": "0" * 64, "key_id": 7},
    ],
    ids=["not-object", "no-value", "short-value", "bad-alg", "non-string-header"],
)
def test_a_malformed_signature_block_is_an_error_not_a_pass(signed, block):
    _, _, _, payload = signed
    result = verify_attestation({**payload, "signature": block}, hmac_key=KEY)
    assert (result.ok, result.state) == (False, "error"), result


def test_signing_refuses_a_weak_hmac_key_and_a_missing_signer(repo_with_run):
    repo, run = repo_with_run
    with pytest.raises(SignatureError, match="too short"):
        repo.attest(run, {"kind": "approval"}, signer="op", key=b"short")
    with pytest.raises(SignatureError, match="signer"):
        sign_attestation({"claim": {}, "signer": ""}, KEY)


def test_a_prepared_signature_and_a_key_cannot_both_fill_the_slot(repo_with_run):
    repo, run = repo_with_run
    with pytest.raises(ValueError, match="not both"):
        repo.attest(run, {}, signer="op", signature={"alg": "x"}, key=KEY)


# --- backwards compatibility -------------------------------------------------


def test_an_unsigned_attestation_is_byte_identical_to_what_0_8_1_wrote(repo_with_run):
    repo, run = repo_with_run
    claim = {"kind": "approval"}
    oid = repo.attest(run, claim, signer="security-team")

    legacy = ObjectEnvelope.create("attestation", _legacy_payload(run, claim, "security-team"))
    assert oid == legacy.oid, "signing support changed the oid of an unsigned attestation"
    assert repo.raw(oid) == legacy.encode()
    assert b'"signature":null' in repo.raw(oid)


@pytest.mark.parametrize("version", ["v0_3_0", "v0_7_2", "v0_8_0"])
def test_an_existing_repositorys_unsigned_attestation_loads_and_fscks(tmp_path, version):
    """The real compatibility case: an object an older release wrote, read by this one."""
    root = tmp_path / version
    shutil.copytree(COMPAT / version / "repo", root)
    repo = Repo.open(root)
    run = repo.read_ref("heads/main")
    # Written the pre-0.9.0 way — the payload literal, no signing code involved.
    oid = repo.put("attestation", _legacy_payload(run, {"kind": "approval"}, "old-release"))

    assert repo.get(oid).payload()["signer"] == "old-release"
    assert repo.attest(run, {"kind": "approval"}, signer="old-release") == oid
    result = repo.verify_attestation(oid, hmac_key=KEY)
    assert (result.ok, result.state) == (False, "unsigned")
    assert repo.fsck().ok, repo.fsck().errors


def test_a_signed_attestation_also_fscks_clean(signed):
    repo, _, _, _ = signed
    outcome = repo.fsck()
    assert outcome.ok, outcome.errors


# --- the operator surface ----------------------------------------------------


def _run_cli(*args: str) -> None:
    cli.main(list(args))


def _refused(capsys, verb: str, *args: str) -> str:
    with pytest.raises(SystemExit) as exited:
        _run_cli(verb, *args)
    assert exited.value.code == 1
    captured = capsys.readouterr()
    assert captured.out.strip() == "", "a refusal must not print on stdout"
    lines = [line for line in captured.err.splitlines() if line.strip()]
    assert lines and lines[0].startswith(f"tine {verb}: ")
    assert "Traceback" not in captured.err
    return " ".join(lines)


def test_attest_signs_with_key_file_and_repo_verify_confirms_it(repo_with_run, tmp_path, capsys):
    repo, run = repo_with_run
    key_file = tmp_path / "hmac.key"
    key_file.write_text(KEY.decode() + "\n", encoding="utf-8")
    root = str(repo.path.parent)

    _run_cli(
        "attest",
        "heads/main",
        "--repo",
        root,
        "--signer",
        "security-team",
        "--claim",
        '{"kind": "approval"}',
        "--key-file",
        str(key_file),
        "--key-id",
        "k1",
        "--json",
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["signed"] is True
    assert receipt["signature"]["scheme"] == SCHEME_ATTEST_V1
    assert receipt["signature"]["key_id"] == "k1"

    _run_cli("repo-verify", "heads/main", "--repo", root, "--key-file", str(key_file), "--json")
    report = json.loads(capsys.readouterr().out)
    assert (report["command"], report["ok"], report["count"]) == ("repo-verify", True, 1)
    row = report["attestations"][0]
    assert (row["state"], row["signer"], row["key_id"]) == ("verified", "security-team", "k1")
    assert row["attestation_id"] == receipt["attestation_id"]


def test_evaluate_signs_too_and_the_receipt_says_unsigned_when_it_is(repo_with_run, capsys):
    repo, _ = repo_with_run
    root = str(repo.path.parent)
    os.environ["TINE_TEST_ATTEST_KEY"] = KEY.decode()
    try:
        _run_cli(
            "evaluate",
            "heads/main",
            "--repo",
            root,
            "--evaluator",
            "judge",
            "--score",
            "quality=0.9",
            "--key-env",
            "TINE_TEST_ATTEST_KEY",
            "--json",
        )
        assert json.loads(capsys.readouterr().out)["signed"] is True
    finally:
        del os.environ["TINE_TEST_ATTEST_KEY"]

    _run_cli(
        "attest", "heads/main", "--repo", root, "--signer", "op", "--claim", '{"kind": "note"}'
    )
    human = capsys.readouterr().out
    assert "unsigned" in human and "self-asserted" in human
    _run_cli(
        "evaluate", "heads/main", "--repo", root, "--evaluator", "j", "--score", "q=1", "--json"
    )
    assert json.loads(capsys.readouterr().out)["signed"] is False


def test_repo_verify_is_fail_closed_and_a_report_when_unarmed(repo_with_run, tmp_path, capsys):
    repo, run = repo_with_run
    key_file = tmp_path / "hmac.key"
    key_file.write_text(KEY.decode(), encoding="utf-8")
    other = tmp_path / "other.key"
    other.write_text(OTHER_KEY.decode(), encoding="utf-8")
    root = str(repo.path.parent)
    repo.attest(run, {"kind": "approval"}, signer="op")  # unsigned

    # Unarmed: a report, exit 0, and it must not look like a pass.
    _run_cli("repo-verify", "heads/main", "--repo", root)
    assert "unsigned" in capsys.readouterr().out

    with pytest.raises(SystemExit) as exited:
        _run_cli("repo-verify", "heads/main", "--repo", root, "--require-signature")
    assert exited.value.code == 1
    capsys.readouterr()

    repo.attest(run, {"kind": "approval"}, signer="security-team", key=KEY)
    # Still fails: the unsigned one is still there and every row must verify.
    with pytest.raises(SystemExit) as exited:
        _run_cli("repo-verify", "heads/main", "--repo", root, "--key-file", str(key_file))
    assert exited.value.code == 1
    report = capsys.readouterr().out
    assert "verified" in report and "unsigned" in report


def test_repo_verify_with_the_wrong_key_exits_1_and_says_mismatch(repo_with_run, tmp_path, capsys):
    repo, run = repo_with_run
    other = tmp_path / "other.key"
    other.write_text(OTHER_KEY.decode(), encoding="utf-8")
    repo.attest(run, {"kind": "approval"}, signer="security-team", key=KEY)

    with pytest.raises(SystemExit) as exited:
        _run_cli(
            "repo-verify",
            "heads/main",
            "--repo",
            str(repo.path.parent),
            "--key-file",
            str(other),
            "--json",
        )
    assert exited.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False and report["attestations"][0]["state"] == "mismatch"


def test_require_signature_refuses_a_run_with_no_attestation_at_all(repo_with_run, capsys):
    repo, _ = repo_with_run
    with pytest.raises(SystemExit) as exited:
        _run_cli(
            "repo-verify", "heads/main", "--repo", str(repo.path.parent), "--require-signature"
        )
    assert exited.value.code == 1
    assert "no attestation" in capsys.readouterr().out


def test_repo_verify_takes_one_attestation_oid_too(signed, capsys):
    repo, _, oid, _ = signed
    _run_cli("repo-verify", oid, "--repo", str(repo.path.parent), "--json")
    report = json.loads(capsys.readouterr().out)
    assert report["count"] == 1 and report["attestations"][0]["attestation_id"] == oid


def test_the_key_flags_refuse_a_missing_file_and_two_keys_at_once(repo_with_run, capsys):
    repo, _ = repo_with_run
    root = str(repo.path.parent)
    claim = ("--signer", "op", "--claim", "{}")
    message = _refused(
        capsys, "attest", "heads/main", "--repo", root, *claim, "--key-file", "no/such.key"
    )
    assert "cannot read the key" in message

    message = _refused(
        capsys,
        "attest",
        "heads/main",
        "--repo",
        root,
        *claim,
        "--key-env",
        "TINE_TEST_ATTEST_KEY",
        "--key-file",
        "some.key",
    )
    assert "cannot be combined" in message
    message = _refused(
        capsys, "repo-verify", "heads/main", "--repo", root, "--key-env", "X", "--key-file", "y"
    )
    assert "cannot be combined" in message


def test_repo_verify_refuses_a_target_that_is_not_a_run_or_an_attestation(repo_with_run, capsys):
    repo, run = repo_with_run
    event = repo.get(run).payload()["events"][0]
    message = _refused(capsys, "repo-verify", event, "--repo", str(repo.path.parent))
    assert "neither a run nor an attestation" in message
    message = _refused(capsys, "repo-verify", "heads/nope", "--repo", str(repo.path.parent))
    assert "cannot resolve" in message


def test_mcp_attest_stays_unsigned_because_a_model_holds_no_keys():
    """Parity is deliberate here: run content must not be able to sign as an operator."""
    from opentine import mcp_repository

    source = Path(mcp_repository.__file__).read_text(encoding="utf-8")
    assert "key_file" not in source and "key_env" not in source
