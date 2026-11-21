"""0.75 plan item (release 0.74.0): ``tine sign --keyless`` and ``tine keyless verify``.

Offline throughout: a throwaway Fulcio-like CA and a Rekor-like log (real RFC
6962 Merkle tree, inclusion proofs, signed tree heads) behind an
``httpx.MockTransport``. The claims: the bundle is the existing Sigstore bundle
(chain, log entry, inclusion proof, checkpoint); it verifies offline; a keyless
identity is never trusted without an owner-pinned trust-bundle entry naming the
exact issuer and identity; a log time outside the certificate window is a
``caveat:``; tampering with the proof or tree head fails; the OIDC token is
never written anywhere.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import Run, RunStatus, StepKind, _trust_bundle, cli, rekor
from opentine.repository._tlog_note import vkey_for
from tests._keyless_fixtures import GH_ISSUER, REPO, WORKFLOW, WorkflowFulcio
from tests._sigstore_fakes import IDENTITY, ISSUER_URL, FakeLog, fake_jwt, transport

TOKEN = fake_jwt({"iss": GH_ISSUER, "sub": WORKFLOW, "aud": "sigstore"})
MAIL_TOKEN = fake_jwt({"iss": ISSUER_URL, "sub": "u", "email": IDENTITY, "aud": "sigstore"})
OWNER = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
OWNER_NAME = "example.com/trust"
OWNER_VKEY = vkey_for(OWNER_NAME, OWNER.public_key().public_bytes_raw())


def _cli(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


@pytest.fixture
def ws(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "cfg").as_posix())
    for name in ("SIGSTORE_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
                 "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "OPENTINE_TRUST_OWNER",
                 "OPENTINE_TRUST_BUNDLE"):  # fmt: skip
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="keyless_run", model_info="mock-model", user_prompt="hello")
    run.add_step(StepKind.model, {"prompt": "hello"}, outputs={"text": "hi"}, model_info="m")
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    return tmp_path, monkeypatch


def _setup(ws, *, workflow=True, offset=0):
    root, monkeypatch = ws
    log, fulcio = FakeLog(), WorkflowFulcio(workflow=workflow)
    log.time_offset = offset
    (root / "rekor.pub").write_bytes(log.public_pem())
    (root / "fulcio.pem").write_bytes(fulcio.roots_pem())
    monkeypatch.setattr(rekor, "TRANSPORT", transport(log, fulcio))
    monkeypatch.setenv("SIGSTORE_ID_TOKEN", TOKEN if workflow else MAIL_TOKEN)
    return log, fulcio


def _sign(capsys, *extra: str) -> dict:
    capsys.readouterr()
    code = _cli("sign", "run.tine", "--keyless", "--rekor", "https://rekor.test",
                "--fulcio-url", "https://fulcio.test", "--output", "run.sigstore.json",
                "--json", *extra)  # fmt: skip
    out = capsys.readouterr().out
    assert code == 0, out
    return json.loads(out)


def _verify(capsys, bundle="run.sigstore.json", *extra: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = _cli("keyless", "verify", bundle, "--fulcio-root", "fulcio.pem",
                "--rekor-key", "rekor.pub", "--json", *extra)  # fmt: skip
    return code, json.loads(capsys.readouterr().out)


def _pin(root: Path, issuer: str, identity: str, serial: int = 1) -> None:
    payload = {"trust_bundle": 1, "serial": serial,
               "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "trust_policy": {"cert_oidc_issuer": issuer, "cert_identity": identity}}  # fmt: skip
    (root / ".tine").mkdir(exist_ok=True)
    (root / ".tine" / "trust-bundle.note").write_bytes(
        _trust_bundle.sign(payload, OWNER, OWNER_NAME)
    )
    (root / "cfg" / "opentine").mkdir(parents=True, exist_ok=True)
    (root / "cfg" / "opentine" / "trust-owner").write_bytes((OWNER_VKEY + "\n").encode())


def test_the_bundle_carries_chain_entry_proof_and_tree_head_and_no_token(ws, capsys):
    from opentine._schemas import validate_output

    _setup(ws)
    row = _sign(capsys)
    assert validate_output(row) == []
    doc = json.loads((ws[0] / "run.sigstore.json").read_bytes())
    material = doc["verificationMaterial"]
    assert len(material["x509CertificateChain"]["certificates"]) == 2  # leaf + intermediate
    entry = material["tlogEntries"][0]
    assert entry["inclusionProof"]["hashes"] and entry["inclusionProof"]["checkpoint"]["envelope"]
    for path in ws[0].rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes(), path


def test_a_keyless_identity_is_never_trusted_by_default(ws, capsys):
    _setup(ws)
    _sign(capsys)
    code, row = _verify(capsys)
    assert code == 1 and row["code"] == "caveat:keyless-unpinned" and row["trusted"] is False
    assert row["assurance_tier"] == "keyless-workflow"
    ident = row["identity"]
    assert ident["issuer"] == GH_ISSUER and ident["build_signer_uri"] == WORKFLOW
    assert ident["source_repository_uri"] == REPO and ident["runner_environment"] == "github-hosted"


def test_an_owner_pinned_issuer_and_exact_identity_is_trusted(ws, capsys):
    from opentine._schemas import validate_output

    _setup(ws)
    _sign(capsys)
    _pin(ws[0], GH_ISSUER, WORKFLOW)
    code, row = _verify(capsys, "run.sigstore.json", "--run", "run.tine")
    assert validate_output(row) == []
    assert code == 0 and row["code"] == "keyless.trusted" and row["trusted"] is True


@pytest.mark.parametrize(
    "issuer,identity",
    [("https://other.example", WORKFLOW), (GH_ISSUER, WORKFLOW + "x"), (GH_ISSUER, REPO)],
)
def test_a_pin_must_name_both_the_issuer_and_the_exact_identity(ws, capsys, issuer, identity):
    _setup(ws)
    _sign(capsys)
    _pin(ws[0], issuer, identity)
    code, row = _verify(capsys)
    assert code == 1 and row["code"] == "caveat:keyless-unpinned"


def test_a_person_identity_maps_to_its_own_tier(ws, capsys):
    _setup(ws, workflow=False)
    _sign(capsys)
    _pin(ws[0], ISSUER_URL, IDENTITY)
    code, row = _verify(capsys)
    assert code == 0 and row["assurance_tier"] == "keyless-person"


def test_a_log_time_outside_the_certificate_window_is_a_caveat_not_trust(ws, capsys):
    _setup(ws, offset=3600)  # logged an hour after the ten-minute certificate expired
    _sign(capsys)
    _pin(ws[0], GH_ISSUER, WORKFLOW)
    code, row = _verify(capsys)
    assert code == 1 and row["code"] == "caveat:keyless-outside-window"
    assert row["trusted"] is False and row["outcome"] == "caveat"


def _tamper(root: Path, change) -> None:
    path = root / "run.sigstore.json"
    doc = json.loads(path.read_bytes())
    change(doc)
    path.write_bytes((json.dumps(doc) + "\n").encode())


def _flip(b64: str) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode()


@pytest.mark.parametrize("part", ["hashes", "checkpoint", "time"])
def test_a_tampered_proof_or_tree_head_fails(ws, capsys, part):
    _setup(ws)
    _sign(capsys)
    _pin(ws[0], GH_ISSUER, WORKFLOW)

    def change(doc):
        entry = doc["verificationMaterial"]["tlogEntries"][0]
        if part == "hashes":
            entry["inclusionProof"]["hashes"][0] = _flip(entry["inclusionProof"]["hashes"][0])
        elif part == "checkpoint":
            note = entry["inclusionProof"]["checkpoint"]["envelope"]
            entry["inclusionProof"]["checkpoint"]["envelope"] = note.replace("\n", "\n\n", 1)
        else:
            entry["integratedTime"] = str(int(entry["integratedTime"]) - 1)

    _tamper(ws[0], change)
    code, row = _verify(capsys)
    assert code == 1 and row["code"] == "fail:keyless-receipt" and row["trusted"] is False


def test_an_unknown_root_fails_and_a_bundled_root_is_not_trusted(ws, capsys):
    _, fulcio = _setup(ws)
    _sign(capsys)
    other = WorkflowFulcio()
    (ws[0] / "fulcio.pem").write_bytes(other.roots_pem())
    code, row = _verify(capsys)
    assert code == 1 and row["code"] == "fail:keyless-chain"

    def add_root(doc):
        from cryptography.hazmat.primitives import serialization

        der = fulcio.root.public_bytes(serialization.Encoding.DER)
        certs = doc["verificationMaterial"]["x509CertificateChain"]["certificates"]
        certs.append({"rawBytes": base64.b64encode(der).decode()})

    _tamper(ws[0], add_root)
    code, row = _verify(capsys)
    assert code == 1 and row["code"] == "fail:keyless-chain"


def test_the_run_subject_must_match(ws, capsys):
    _setup(ws)
    _sign(capsys)
    _pin(ws[0], GH_ISSUER, WORKFLOW)
    other = Run(id="other", model_info="m", user_prompt="x")
    other.status = RunStatus.completed
    other.save(ws[0] / "other.tine")
    code, row = _verify(capsys, "run.sigstore.json", "--run", "other.tine")
    assert code == 1 and row["code"] == "fail:keyless-subject"


def test_a_pinned_owner_without_its_bundle_fails_closed(ws, capsys):
    _setup(ws)
    _sign(capsys)
    _pin(ws[0], GH_ISSUER, WORKFLOW)
    (ws[0] / ".tine" / "trust-bundle.note").unlink()
    capsys.readouterr()
    code = _cli("keyless", "verify", "run.sigstore.json", "--fulcio-root", "fulcio.pem",
                "--rekor-key", "rekor.pub", "--json")  # fmt: skip
    assert code == 2


def test_tine_verify_reads_the_same_bundle_with_its_existing_checks(ws, capsys):
    _setup(ws)
    _sign(capsys)
    capsys.readouterr()
    code = _cli("verify", "run.tine", "--attestation", "run.sigstore.json", "--json",
                "--rekor-key", "rekor.pub", "--fulcio-root", "fulcio.pem",
                "--cert-identity", WORKFLOW, "--cert-oidc-issuer", GH_ISSUER)  # fmt: skip
    out = json.loads(capsys.readouterr().out)
    assert code == 0, out
    assert out["ok"] is True and out["signature"]["status"] == "verified-keyless"
    assert out["signature"]["keyid"] == WORKFLOW and out["receipt"]["status"] == "verified"


def test_mode_flags_are_refused_where_they_do_nothing(ws, capsys):
    _setup(ws)
    assert _cli("sign", "run.tine", "--keyless", "--key-file", "k") == 2
    assert _cli("sign", "run.tine", "--rekor", "https://rekor.test", "--key-env", "K") == 2
    monkeypatch = ws[1]
    monkeypatch.delenv("SIGSTORE_ID_TOKEN")
    assert _cli("sign", "run.tine", "--keyless", "--output", "x.json") == 1
    assert not (ws[0] / "x.json").exists()
