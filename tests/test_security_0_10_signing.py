"""0.10 round-3 audit: pricing trust, signature re-spellings, keys, verify reads.

Each test fails on 0.9.2. Covers C3-1 (an old signed release catalog in a
workspace), C3-5 (null header fields and a dropped Ed25519 public key minting
extra oids), C3-6 (a public key accepted as an Ed25519 seed), and the hardening
items: one read per verify, migrate-v3 pinned to the key that passed, strict
``--claim`` types, and singular reserved names in ``extra_secret_keys``.
"""

from __future__ import annotations

import argparse
import base64
import json
import shutil
from pathlib import Path

import pytest

from opentine import Run, cli
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
from opentine.signing import HAS_ED25519, verify_artifact

pytestmark = pytest.mark.skipif(not HAS_ED25519, reason="needs the crypto extra")

#: The release catalog of 2026-07-20, signed with the current release key.
OLD_RELEASE = Path(__file__).parent / "fixtures" / "pricing" / "release_catalog_2026_07_20.json"
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


def _invoke(capsys, *argv: str) -> tuple[int, str]:
    try:
        cli.main(list(argv))
        code = 0
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, (captured.out + captured.err).replace("\n", " ")


def _run(run_id: str = "signed-run") -> Run:
    run = Run(run_id=run_id)
    run.add_step(StepKind.done, {"text": "answer"})
    run.status = RunStatus.completed
    return run


# --- C3-1: an old signed release catalog shipped in a workspace ------------------ #


def _changed_card(old: dict) -> tuple[str, str]:
    """A (provider, model) whose card the bundled catalog has since replaced."""
    bundled = load_catalogs([BUNDLED_CATALOG])
    stale = catalog.PricingCatalog.from_dict(old, require_signature=True)
    for card in stale.cards:
        for model in (card.model, *getattr(card, "aliases", ())):
            current = bundled.lookup(card.provider, model)
            if current is not None and current.id != card.id:
                return card.provider, model
    raise AssertionError("the fixture catalog has no card the bundled one replaced")


def test_an_old_signed_release_catalog_in_a_workspace_does_not_roll_prices_back(
    workspace, monkeypatch
):
    old = json.loads(OLD_RELEASE.read_text(encoding="utf-8"))
    assert catalog.PricingCatalog.from_dict(old, require_signature=True).signed
    provider, model = _changed_card(old)
    (workspace / ".tine").mkdir()
    shutil.copy(OLD_RELEASE, workspace / ".tine" / "pricing.json")
    skipped: list[Path] = []
    monkeypatch.setattr(catalog, "stale_catalog_hook", skipped.append)

    loaded = load_catalogs(workspace=workspace).lookup(provider, model)

    assert loaded.id == load_catalogs([BUNDLED_CATALOG]).lookup(provider, model).id
    assert skipped == [workspace / ".tine" / "pricing.json"]


def test_the_cli_names_the_skipped_workspace_catalog(workspace, capsys, monkeypatch):
    from opentine import _cli_guard

    monkeypatch.setattr(_cli_guard, "_warned", set())
    (workspace / ".tine").mkdir()
    shutil.copy(OLD_RELEASE, workspace / ".tine" / "pricing.json")
    code, out = _invoke(capsys, "pricing", "show", "openai", "gpt-4o")
    assert code == 0 and "newer signed pricing catalog" in out


@pytest.fixture
def release_key(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
        message = _catalog_verify.signed_message(_catalog_verify.SCHEME_V2, body)
        value = base64.b64encode(private.sign(message)).decode()
        data["signature"] = {
            "algorithm": _catalog_verify.SCHEME_V2,
            "key_id": "test-release",
            "value": value,
        }
        return json.dumps(data).encode()

    return sign


def _gpt4o_input(workspace: Path) -> float:
    card = load_catalogs(workspace=workspace).lookup("openai", "gpt-4o")
    return float(card.rates["input"])


def test_a_workspace_catalog_older_than_the_installed_one_is_skipped(
    workspace, release_key, monkeypatch
):
    user = catalog.user_catalog_path()
    user.parent.mkdir(parents=True)
    user.write_bytes(release_key("2099-06-01T00:00:00Z", input_rate="7"))
    (workspace / ".tine").mkdir()
    overlay = workspace / ".tine" / "pricing.json"
    overlay.write_bytes(release_key("2099-01-01T00:00:00Z", input_rate="999"))
    skipped: list[Path] = []
    monkeypatch.setattr(catalog, "stale_catalog_hook", skipped.append)
    assert _gpt4o_input(workspace) == 7
    assert skipped == [overlay]

    overlay.write_bytes(release_key("2099-12-01T00:00:00Z", input_rate="999"))
    assert _gpt4o_input(workspace) == 999  # a newer signed overlay still applies


def test_two_catalogs_signed_at_the_same_moment_cannot_replace_each_other(
    workspace, release_key, monkeypatch
):
    dest = workspace / "user.json"
    install_catalog(release_key("2099-01-01T00:00:00Z", input_rate="5"), dest)
    with pytest.raises(CatalogError, match="roll prices back"):
        install_catalog(release_key("2099-01-01T00:00:00Z", input_rate="0"), dest)
    # The identical catalog re-installs.
    same = dest.read_bytes()
    install_catalog(same, dest)

    user = catalog.user_catalog_path()
    user.parent.mkdir(parents=True)
    user.write_bytes(release_key("2099-01-01T00:00:00Z", input_rate="5"))
    (workspace / ".tine").mkdir()
    (workspace / ".tine" / "pricing.json").write_bytes(
        release_key("2099-01-01T00:00:00Z", input_rate="0")
    )
    monkeypatch.setattr(catalog, "stale_catalog_hook", None)
    assert _gpt4o_input(workspace) == 5


# --- C3-5: one signature, one oid ------------------------------------------------ #


def _signed_data(tmp_path: Path, algorithm: str) -> tuple[dict, object]:
    from opentine.signing import ed25519_private_from_file

    path = tmp_path / "s.tine"
    if algorithm == "ed25519":
        cli.main(["keygen", "--out", str(tmp_path / "ed")])
        key = ed25519_private_from_file(tmp_path / "ed")
        _run().save(path, sign_key=key, sign_algorithm="ed25519")
        verify_key = {"public_key": (tmp_path / "ed.pub").read_text().strip()}
    else:
        _run().save(path, sign_key=HMAC_KEY.encode(), sign_algorithm="hmac-sha256")
        verify_key = {"hmac_key": HMAC_KEY.encode()}
    return json.loads(path.read_text(encoding="utf-8")), verify_key


@pytest.mark.parametrize("algorithm", ["hmac-sha256", "ed25519"])
@pytest.mark.parametrize("field", ["key_id", "signed_at", "signer"])
def test_an_explicit_null_header_field_is_a_malformed_block(tmp_path, algorithm, field):
    data, key = _signed_data(tmp_path, algorithm)
    block = data["metadata"]["integrity"]["signature"]
    assert verify_artifact(data, **key).state == "verified"
    if field in block:
        pytest.skip(f"{field} is part of the signed header here")
    block[field] = None
    result = verify_artifact(data, **key)
    assert result.state == "error" and not result.ok


@pytest.mark.parametrize("respelling", ["dropped", "null"])
def test_an_ed25519_block_without_its_public_key_is_malformed(tmp_path, respelling):
    data, key = _signed_data(tmp_path, "ed25519")
    block = data["metadata"]["integrity"]["signature"]
    if respelling == "dropped":
        del block["public_key"]
    else:
        block["public_key"] = None
    result = verify_artifact(data, **key)
    assert result.state == "error" and not result.ok


# --- C3-6: a public key is no signing key ---------------------------------------- #


def test_signing_with_a_public_key_file_is_refused(workspace, capsys):
    cli.main(["keygen", "--out", str(workspace / "signer.key")])
    artifact = workspace / "run.tine"
    _run().save(artifact)
    capsys.readouterr()
    code, out = _invoke(
        capsys,
        "sign",
        str(artifact),
        "--algorithm",
        "ed25519",
        "--ed25519-key-file",
        str(workspace / "signer.key.pub"),
    )
    assert code == 1 and "public key" in out
    assert "signature" not in json.loads(artifact.read_text())["metadata"].get("integrity", {})


def test_a_copy_of_the_public_key_beside_its_pub_file_is_refused(workspace):
    from opentine._key_hygiene import ed25519_private
    from opentine.signing import SignatureError

    cli.main(["keygen", "--out", str(workspace / "k")])
    public = (workspace / "k.pub").read_bytes()
    (workspace / "copy").write_bytes(public)
    (workspace / "copy").chmod(0o600)
    (workspace / "copy.pub").write_bytes(public)
    with pytest.raises(SignatureError, match="public key"):
        ed25519_private(str(workspace / "copy"))
    assert ed25519_private(str(workspace / "k")) is not None  # the real seed still loads


# --- hardening: one read per verdict; migrate-v3 pinned to the key that passed --- #


def test_verify_reads_the_artifact_once_for_verdict_and_fingerprint(workspace, monkeypatch):
    from opentine import _cli_security, _cli_verify_report, _graph_persistence

    cli.main(["keygen", "--out", str(workspace / "ed")])
    from opentine.signing import ed25519_private_from_file

    path = workspace / "s.tine"
    key = ed25519_private_from_file(workspace / "ed")
    _run().save(path, sign_key=key, sign_algorithm="ed25519")
    reads: list[object] = []
    for module in (_cli_verify_report, _graph_persistence):
        original = module.read_artifact_json

        def counted(source, _original=original):
            reads.append(source)
            return _original(source)

        monkeypatch.setattr(module, "read_artifact_json", counted)
    args = argparse.Namespace(trust_embedded_key=True, pin=None, key_env=None, key_file=None)
    args.pubkey = None
    result, fingerprint = _cli_security.signature_result(args, path)
    assert result.state == "verified-tofu" and fingerprint
    assert len(reads) == 1


def test_migrate_v3_checks_the_import_against_the_pinned_key(workspace):
    import hashlib

    from opentine._repo_cli_migrate import migration_keys
    from opentine.signing import ed25519_private_from_file

    cli.main(["keygen", "--out", str(workspace / "ed")])
    public = (workspace / "ed.pub").read_text().strip()
    path = workspace / "s.tine"
    key = ed25519_private_from_file(workspace / "ed")
    _run().save(path, sign_key=key, sign_algorithm="ed25519")
    pin = "sha256:" + hashlib.sha256(bytes.fromhex(public)).hexdigest()
    args = argparse.Namespace(
        source=str(path),
        allow_unverified=False,
        pin=[pin],
        key_env=None,
        key_file=None,
        pubkey=None,
        trust_embedded_key=False,
    )
    keys = migration_keys(args)
    assert keys["public_key"] == public and keys["trust_embedded"] is False


# --- hardening: --claim compares JSON types; extra_secret_keys singulars ---------- #


def test_claim_selection_does_not_equate_true_with_one():
    from opentine._repo_cli_verify import _same_json, _selects

    assert not _same_json(True, 1) and not _same_json(1, True) and not _same_json(0, False)
    assert _same_json(1, 1.0) and _same_json({"a": [1, "x"]}, {"a": [1.0, "x"]})
    assert not _same_json({"a": None}, {"a": 0}) and not _same_json("1", 1)
    row = {"signer": "ci", "claim": {"approved": 1}}
    assert not _selects(row, [], {"approved": True})
    assert _selects({"signer": "ci", "claim": {"approved": True}}, [], {"approved": True})


@pytest.mark.parametrize("name", ["output", "input", "step", "tag", "ref", "parent_id"])
def test_extra_secret_keys_refuse_the_singular_of_a_reserved_field(name):
    from opentine.policies import RedactionPolicy

    with pytest.raises(ValueError, match="extra_secret_keys"):
        RedactionPolicy(extra_secret_keys=(name,))
