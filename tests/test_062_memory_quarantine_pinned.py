"""0.61: quarantine signers come from the owner-pinned ``curator`` role, not a repo file."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _schemas, cli
from opentine._key_roles import normalize_key
from opentine._memory_quarantine import promote_refusals, quarantined
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _tine(capsys, *argv: str):
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    out = capsys.readouterr().out
    try:
        return code, json.loads(out)
    except ValueError:
        return code, out


def _key(tmp_path, seed: int):
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    path = tmp_path / f"k{seed}.key"
    path.write_bytes(key.private_bytes_raw().hex().encode("ascii"))
    return path.as_posix(), key.public_key().public_bytes_raw().hex()


@pytest.fixture
def setup(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path)
    member, member_pub = _key(tmp_path, 1)
    other, other_pub = _key(tmp_path, 2)
    assert _tine(capsys, "memory", "trust", member_pub, "--json")[0] == 0  # memory-team.json
    code, added = _tine(capsys, "memory", "add", "deploys", "Deploy with the blue pipeline",
                        "--key", member, "--json")  # fmt: skip
    assert code == 0, added
    return repo, added["note"]["digest"], (member, member_pub), (other, other_pub)


def _curators(repo: Repo, *pubs: str) -> None:
    keys = ", ".join(f'"{normalize_key(p)}"' for p in pubs)
    (repo.path / "key-roles.toml").write_text(f"version = 1\n[roles]\ncurator = [{keys}]\n")


def _quarantine(capsys, note: str, key: str):
    code, out = _tine(capsys, "memory", "quarantine", note, "--key", key, "--why", "poisoned",
                      "--json")  # fmt: skip
    assert code == 0, out
    assert _schemas.validate_output(out) == [], out
    return out


def test_a_team_file_member_is_unverified_without_pinned_roles(setup, capsys):
    repo, note, (member, _), _ = setup
    out = _quarantine(capsys, note, member)
    assert out["quarantined"] is True
    assert out["verification"].startswith("unverified: ")
    assert quarantined(repo)[note]["verification"].startswith("unverified: ")


def test_a_signer_outside_the_team_file_still_blocks_as_unverified(setup, capsys):
    repo, note, _, (other, _) = setup
    out = _quarantine(capsys, note, other)
    assert out["verification"].startswith("unverified: ")
    assert note in quarantined(repo)  # fail safe: an unknown signer still blocks
    code, found = _tine(capsys, "memory", "recall", "deploy", "--json")
    assert code == 0 and found["notes"] == []
    code, text = _tine(capsys, "memory", "served", note)
    assert "quarantined; unverified" in text


def test_unpinned_curator_roles_grant_nothing(setup, capsys):
    repo, note, (member, member_pub), _ = setup
    _curators(repo, member_pub)  # only the unsigned in-repo file
    out = _quarantine(capsys, note, member)
    assert out["verification"].startswith("unverified: the curator role is unpinned")


def test_a_pinned_curator_verifies_and_another_signer_does_not(setup, capsys):
    repo, note, (member, member_pub), (other, _) = setup
    _curators(repo, member_pub)
    pin_roles(repo.path)
    first = _quarantine(capsys, note, other)
    assert first["verification"] == "unverified: the signer is not a pinned curator key"
    code, served = _tine(capsys, "memory", "served", note, "--json")
    assert served["verification"].startswith("unverified")
    _quarantine(capsys, note, member)
    assert quarantined(repo)[note]["verification"] == "verified"  # a verified row wins
    code, served = _tine(capsys, "memory", "served", note, "--json")
    assert code == 0 and served["verification"] == "verified"
    assert promote_refusals(repo.path.parent, "run:nothing") == []
