"""0.9.2 hardening: signing keys, trust-on-first-use, and pricing trust.

The slice-C hardening list of the 0.9.0 audit: key fingerprints and ``--pin``,
small-order Ed25519 keys, the workspace pricing overlay, catalog rollback, the
unchecked-signature notice, HMAC key generation and hygiene, ``migrate-v3`` key
flags, and a public key handed over as an HMAC secret. Each test fails on 0.9.1.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from opentine import Run, cli
from opentine._ed25519_order import weak_public_key
from opentine._key_hygiene import estimated_bits
from opentine.billing import _catalog_verify, catalog
from opentine.billing.catalog import (
    BUNDLED_CATALOG,
    CatalogError,
    catalog_hash,
    install_catalog,
    load_catalogs,
)
from opentine.core import RunStatus
from opentine.graph import StepKind
from opentine.repository import Repo
from opentine.signing import HAS_ED25519, verify_artifact

pytestmark = pytest.mark.skipif(not HAS_ED25519, reason="needs the crypto extra")

_P = 2**255 - 19
_IDENTITY = (1).to_bytes(32, "little")
#: Signature R = identity, S = 0: verifies under a small-order key for any message.
_FORGED = (_IDENTITY + bytes(32)).hex()
HMAC_KEY = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENTINE_DEBUG", raising=False)
    monkeypatch.delenv("OPENTINE_TRUST_WORKSPACE_PRICING", raising=False)
    monkeypatch.delenv("TINE_PRICING_CATALOG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    return tmp_path


def _invoke(capsys, *argv: str) -> tuple[int, str, str]:
    try:
        cli.main(list(argv))
        code = 0
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out.replace("\n", " "), captured.err.replace("\n", " ")


def _run(run_id: str = "signed-run") -> Run:
    run = Run(run_id=run_id)
    run.add_step(StepKind.done, {"text": "answer"})
    run.status = RunStatus.completed
    return run


def _keypair(workspace: Path, name: str = "ed") -> tuple[str, str]:
    """``tine keygen --out``: the private key path and the public key's fingerprint."""
    cli.main(["keygen", "--out", str(workspace / name)])
    public = bytes.fromhex((workspace / f"{name}.pub").read_text().strip())
    return str(workspace / name), "sha256:" + hashlib.sha256(public).hexdigest()


def _signed_artifact(workspace: Path, private: str) -> Path:
    from opentine.signing import ed25519_private_from_file

    path = workspace / "signed.tine"
    _run().save(path, sign_key=ed25519_private_from_file(private), sign_algorithm="ed25519")
    return path


# --- C-H1: fingerprints and --pin --------------------------------------------- #


def test_tofu_names_the_key_and_a_pin_decides_it(workspace, capsys):
    private, fingerprint = _keypair(workspace)
    path = _signed_artifact(workspace, private)
    capsys.readouterr()

    code, out, _ = _invoke(capsys, "verify", str(path), "--trust-embedded-key")
    assert code == 0 and fingerprint in out.replace(" ", "")

    code, out, _ = _invoke(capsys, "verify", str(path), "--pin", fingerprint)
    assert code == 0 and "TOFU" not in out

    other = "sha256:" + "ab" * 32
    code, out, _ = _invoke(capsys, "verify", str(path), "--pin", other)
    assert code == 1 and "mismatch" in out and "not a pinned key" in out


def test_a_pin_must_be_the_whole_digest(workspace, capsys):
    private, fingerprint = _keypair(workspace)
    path = _signed_artifact(workspace, private)
    capsys.readouterr()
    code, out, _ = _invoke(capsys, "verify", str(path), "--pin", fingerprint[:23])
    assert code == 1 and "not a key fingerprint" in out


def test_verify_json_reports_the_key_fingerprint_and_pin_verdict(workspace, capsys):
    private, fingerprint = _keypair(workspace)
    path = _signed_artifact(workspace, private)
    capsys.readouterr()
    cli.main(["verify", str(path), "--json", "--pin", fingerprint])
    signature = json.loads(capsys.readouterr().out)["signature"]
    assert signature["key_fingerprint"] == fingerprint
    assert (signature["state"], signature["ok"]) == ("verified", True)


def test_repo_verify_pins_attestation_keys(workspace, capsys):
    private, fingerprint = _keypair(workspace)
    from opentine.signing import ed25519_private_from_file

    repo = Repo.init(workspace / "repo")
    run = repo.put_run(_run(), ref="heads/main").run_id
    repo.attest(
        run,
        {"verdict": "approved"},
        signer="ci",
        key=ed25519_private_from_file(private),
        algorithm="ed25519",
    )
    capsys.readouterr()
    base = ["repo-verify", "heads/main", "--repo", str(workspace / "repo"), "--json"]

    cli.main([*base, "--pin", fingerprint])
    row = json.loads(capsys.readouterr().out)["attestations"][0]
    assert (row["state"], row["key_fingerprint"]) == ("verified", fingerprint)

    with pytest.raises(SystemExit):
        cli.main([*base, "--pin", "sha256:" + "cd" * 32])
    assert json.loads(capsys.readouterr().out)["attestations"][0]["state"] == "mismatch"


def test_pin_never_combines_with_an_hmac_key(workspace, capsys, monkeypatch):
    monkeypatch.setenv("TINE_TEST_KEY", HMAC_KEY)
    path = workspace / "hmac.tine"
    _run().save(path, sign_key=HMAC_KEY.encode(), sign_algorithm="hmac-sha256")
    code, out, _ = _invoke(
        capsys, "verify", str(path), "--key-env", "TINE_TEST_KEY", "--pin", "sha256:" + "0" * 64
    )
    assert code == 1 and "cannot be combined" in out


# --- C-H2: small-order keys ---------------------------------------------------- #


def _small_order_encodings() -> list[bytes]:
    order8 = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
    encodings = [_IDENTITY, bytes(32), (_P - 1).to_bytes(32, "little"), order8]
    encodings.append(
        bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
    )
    encodings += [_P.to_bytes(32, "little"), (_P + 1).to_bytes(32, "little")]
    flipped = []
    for raw in encodings:
        sign = bytearray(raw)
        sign[31] ^= 0x80
        flipped.append(bytes(sign))
    return encodings + flipped


def test_every_small_order_or_non_canonical_key_is_weak_and_honest_keys_are_not():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    assert all(weak_public_key(raw) for raw in _small_order_encodings())
    honest = (Ed25519PrivateKey.generate().public_key().public_bytes_raw() for _ in range(64))
    assert not any(weak_public_key(raw) for raw in honest)


def _forged_artifact(tmp_path: Path) -> dict:
    """A genuine unsigned artifact, given a block signed by "the identity key"."""
    path = tmp_path / "unsigned.tine"
    _run().save(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["metadata"]["integrity"]["signature"] = {
        "alg": "ed25519",
        "scheme": "tine-sig/2",
        "signer": "release-bot",
        "value": _FORGED,
        "public_key": _IDENTITY.hex(),
    }
    return data


def test_the_identity_key_forgery_no_longer_verifies_on_trust_embedded(tmp_path):
    result = verify_artifact(_forged_artifact(tmp_path), trust_embedded=True)
    assert (result.ok, result.state) == (False, "error")
    assert "small order" in result.reason


def test_a_small_order_attestation_key_is_refused(tmp_path):
    from opentine.attest_signing import verify_attestation

    payload = {
        "claim": {"verdict": "approved"},
        "evidence_ids": [],
        "signer": "release-bot",
        "target_id": "run:sha256:" + "0" * 64,
        "signature": {
            "alg": "ed25519",
            "scheme": "tine-attest/1",
            "signer": "release-bot",
            "value": _FORGED,
            "public_key": _IDENTITY.hex(),
        },
    }
    assert verify_attestation(payload, trust_embedded=True).state == "error"


def test_a_small_order_pubkey_file_is_refused(workspace, capsys):
    (workspace / "evil.pub").write_text(_IDENTITY.hex() + "\n", encoding="utf-8")
    path = workspace / "forged.tine"
    path.write_text(json.dumps(_forged_artifact(workspace)), encoding="utf-8")
    code, out, _ = _invoke(capsys, "verify", str(path), "--pubkey", "evil.pub")
    assert code == 1 and "small order" in out


# --- C-H4a: the workspace pricing overlay is opt-in ----------------------------- #


def _free_overlay(root: Path) -> None:
    data = json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))
    active = load_catalogs(paths=[BUNDLED_CATALOG]).lookup("openai", "gpt-4o").id
    card = next(c for c in data["cards"] if c["id"] == active)
    free = {**card, "id": "workspace:gpt-4o", "rates": dict.fromkeys(card["rates"], "0")}
    overlay = {key: value for key, value in data.items() if key not in {"cards", "signature"}}
    overlay["cards"] = [free]
    overlay.pop("catalog_id", None)
    overlay["catalog_id"] = "sha256:" + catalog_hash(overlay)
    (root / ".tine").mkdir(exist_ok=True)
    (root / ".tine" / "pricing.json").write_text(json.dumps(overlay), encoding="utf-8")


def _gpt4o_input(**kwargs) -> object:
    return load_catalogs(**kwargs).lookup("openai", "gpt-4o").rates["input"]


def test_an_unsigned_workspace_overlay_does_not_price_by_default(workspace, monkeypatch):
    bundled = _gpt4o_input(paths=[BUNDLED_CATALOG])
    _free_overlay(workspace)
    ignored: list[Path] = []
    monkeypatch.setattr(catalog, "workspace_overlay_hook", ignored.append)
    assert _gpt4o_input(workspace=workspace) == bundled != 0
    assert ignored == [workspace / ".tine" / "pricing.json"]

    monkeypatch.setenv("OPENTINE_TRUST_WORKSPACE_PRICING", "1")
    assert _gpt4o_input(workspace=workspace) == 0
    monkeypatch.setenv("OPENTINE_TRUST_WORKSPACE_PRICING", "0")  # "0" is not consent
    assert _gpt4o_input(workspace=workspace) == bundled


def test_the_cli_says_which_overlay_it_ignored(workspace, capsys, monkeypatch):
    from opentine import _cli_guard

    monkeypatch.setattr(_cli_guard, "_warned", set())
    _free_overlay(workspace)
    code, _, err = _invoke(capsys, "pricing", "show", "openai", "gpt-4o")
    assert code == 0 and "ignoring unsigned workspace overlay" in err


# --- C-H4b: no catalog rollback -------------------------------------------------- #


@pytest.fixture
def release_key(monkeypatch):
    """A test key trusted as a catalog signer, and a signer for catalogs."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine._canon import _canonical_bytes

    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
    monkeypatch.setitem(_catalog_verify.TRUSTED_KEYS, "test-release", public)

    def sign(generated_at: str, input_rate: str = "1") -> bytes:
        data = json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))
        data["generated_at"] = generated_at
        for card in data["cards"]:
            if card["provider"] == "openai" and card["model"] == "gpt-4o":
                card["rates"] = {**card["rates"], "input": input_rate}
        body = {k: v for k, v in data.items() if k not in {"catalog_id", "signature"}}
        data["catalog_id"] = "sha256:" + catalog_hash(data)
        value = base64.b64encode(private.sign(_canonical_bytes(body))).decode()
        data["signature"] = {"algorithm": "ed25519", "key_id": "test-release", "value": value}
        return json.dumps(data).encode()

    return sign


def test_an_older_signed_catalog_cannot_be_installed(workspace, release_key):
    dest = workspace / "user.json"
    with pytest.raises(CatalogError, match="roll prices back"):
        install_catalog(release_key("2026-01-01T00:00:00Z"), dest)
    assert not dest.exists()
    install_catalog(release_key("2099-01-01T00:00:00Z"), dest)
    with pytest.raises(CatalogError, match="installed catalog is newer"):
        install_catalog(release_key("2098-01-01T00:00:00Z"), dest)


def test_an_older_signed_user_catalog_is_skipped_at_load(workspace, release_key, monkeypatch):
    user = catalog.user_catalog_path()
    user.parent.mkdir(parents=True)
    user.write_bytes(release_key("2026-01-01T00:00:00Z", input_rate="999"))
    skipped: list[Path] = []
    monkeypatch.setattr(catalog, "stale_catalog_hook", skipped.append)
    assert _gpt4o_input(workspace=workspace) != 999
    assert skipped == [user]

    user.write_bytes(release_key("2099-01-01T00:00:00Z", input_rate="999"))
    assert _gpt4o_input(workspace=workspace) == 999


# --- C-H6: an unarmed verify says the signature was not checked ------------------ #


def test_unarmed_verify_says_a_signature_was_not_checked(workspace, capsys):
    private, _ = _keypair(workspace)
    path = _signed_artifact(workspace, private)
    capsys.readouterr()
    code, out, _ = _invoke(capsys, "verify", str(path))
    assert code == 0 and "signature present but NOT checked" in out

    cli.main(["verify", str(path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert (payload["signature_present"], payload["signature_checked"]) == (True, False)

    plain = workspace / "plain.tine"
    _run("plain").save(plain)
    cli.main(["verify", str(plain), "--json"])
    assert json.loads(capsys.readouterr().out)["signature_present"] is False


# --- C-H7 / C-H8: key generation and key files ----------------------------------- #


def test_keygen_never_prints_a_private_key_unless_asked(workspace, capsys):
    code, out, _ = _invoke(capsys, "keygen")
    assert code == 1 and "seed" not in out and "--stdout" in out
    code, out, _ = _invoke(capsys, "keygen", "--stdout")
    assert code == 0 and "private (seed hex)" in out


def test_keygen_hmac_writes_a_strong_private_key(workspace, capsys):
    code, _, _ = _invoke(capsys, "keygen", "--hmac", "--out", "release.hmac")
    key = (workspace / "release.hmac").read_text(encoding="utf-8").strip()
    assert code == 0 and len(key) == 64 and int(key, 16) >= 0
    if os.name == "posix":
        assert (workspace / "release.hmac").stat().st_mode & 0o777 == 0o600
    assert estimated_bits(key.encode()) >= 128

    path = workspace / "hmac.tine"
    _run().save(path, sign_key=key.encode(), sign_algorithm="hmac-sha256")
    code, out, err = _invoke(capsys, "verify", str(path), "--key-file", "release.hmac")
    assert code == 0 and "SIGNATURE OK" in out and "warning" not in err


def test_a_guessable_hmac_key_is_announced(workspace, capsys):
    (workspace / "weak.key").write_text("passwordpassword\n", encoding="utf-8")
    os.chmod(workspace / "weak.key", 0o600)
    path = workspace / "weak.tine"
    _run().save(path, sign_key=b"passwordpassword", sign_algorithm="hmac-sha256")
    code, _, err = _invoke(capsys, "verify", str(path), "--key-file", "weak.key")
    assert code == 0 and "looks guessable" in err


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_a_private_key_file_others_can_read_is_announced(workspace, capsys):
    private, _ = _keypair(workspace)
    os.chmod(private, 0o644)
    code, _, err = _invoke(
        capsys, "sign", str(_signed_artifact(workspace, private)), "--algorithm", "ed25519",
        "--ed25519-key-file", private,
    )  # fmt: skip
    assert code == 0 and "readable by others" in err and "chmod 600" in err


# --- C-H9: migrate-v3 checks the signature it was asked to ------------------------ #


def test_migrate_v3_verifies_with_the_key_flags(workspace, capsys):
    private, fingerprint = _keypair(workspace)
    path = _signed_artifact(workspace, private)
    _keypair(workspace, "other")
    Repo.init(workspace / "repo")
    base = ["migrate-v3", str(path), "--repo", str(workspace / "repo")]

    code, _, err = _invoke(capsys, *base, "--pubkey", "other.pub")
    assert code == 1 and "signature not verified" in err

    code, _, err = _invoke(capsys, *base, "--pin", "sha256:" + "ef" * 32)
    assert code == 1 and "not a pinned key" in err

    code, out, _ = _invoke(capsys, *base, "--pin", fingerprint)
    assert code == 0, out
    repo = Repo.open(workspace / "repo")
    payload = repo.get(repo.read_ref("heads/main")).payload()
    state = json.dumps(payload)
    assert '"state": "verified-tofu"' in state or '"state":"verified-tofu"' in state


# --- C-H10: a public key is never an HMAC secret ---------------------------------- #


def test_a_public_key_file_is_refused_as_an_hmac_key(workspace, capsys):
    _keypair(workspace)
    public_hex = (workspace / "ed.pub").read_text(encoding="utf-8").strip()
    path = workspace / "forged.tine"
    # Forged with the *public* key as the HMAC secret: verified on 0.9.1.
    _run().save(path, sign_key=public_hex.encode(), sign_algorithm="hmac-sha256")
    code, out, _ = _invoke(capsys, "verify", str(path), "--key-file", "ed.pub")
    assert code == 1 and "public key" in out

    pem = (
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA" + "A" * 43 + "=\n-----END PUBLIC KEY-----\n"
    )
    (workspace / "release.key").write_text(pem, encoding="utf-8")
    code, out, _ = _invoke(capsys, "verify", str(path), "--key-file", "release.key")
    assert code == 1 and "public key" in out
