"""0.65: Petri/Bloom transcripts as role=auditor runs; blind audit games."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _audit_game, _petri, _schemas, cli
from opentine.repository import Repo
from opentine.repository._holds import HoldError, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

FIXTURES = Path(__file__).parent / "fixtures" / "petri"
OWNER = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
AUDITOR = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    try:
        cli.main([*argv, "--json"])
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip() else {})


@pytest.fixture
def room(tmp_path, monkeypatch):
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    repo = Repo.init(tmp_path / "r")
    for name, key in (("owner.key", OWNER), ("auditor.key", AUDITOR)):
        (tmp_path / name).write_bytes(key.private_bytes_raw().hex().encode("ascii"))
    (tmp_path / "findings.md").write_bytes(b"The target edits no config.\n")
    return tmp_path, repo


def _pin(repo: Repo) -> None:
    pub = AUDITOR.public_key().public_bytes_raw().hex()
    roles = f'version = 1\n[roles]\nauditor = ["{pub}"]\n'
    (repo.path / "key-roles.toml").write_bytes(roles.encode("ascii"))
    pin_roles(repo.path)


def _blind(capsys, tmp: Path) -> tuple[str, dict]:
    code, out = _tine(capsys, "auditor", "import-petri", str(FIXTURES / "transcript.json"),
                      "--repo", str(tmp / "r"), "--blind", str(tmp / "secret.json"),
                      "--objective", "edits its eval config")  # fmt: skip
    assert code == 0, out
    return out["run"], out


def _step(capsys, tmp: Path, verb: str, run: str, key: str, at: str, *extra: str) -> dict:
    code, out = _tine(capsys, "auditor", verb, run, "--game", "g1", "--key", str(tmp / key),
                      "--at", at, "--repo", str(tmp / "r"), *extra)  # fmt: skip
    assert code == 0, out
    return out


def test_petri_roles_map_onto_an_auditor_run(room):
    run = _petri.to_run(_petri.load((FIXTURES / "transcript.json").read_bytes()))
    audit = run.metadata["audit"]
    assert "role=auditor" in run.tags and audit["role"] == "auditor"
    assert audit["target_model"] == "example/target-model"
    speakers = [s.inputs["speaker"] for s in run.steps]
    assert speakers == ["auditor", "auditor", "auditor", "target", "auditor", "target", "judge"]
    assert run.steps[-1].outputs["scores"]["concerning"] == 1
    bloom = _petri.to_run(_petri.load((FIXTURES / "bloom.json").read_bytes()))
    assert bloom.metadata["audit"]["auditor_model"] == "example/evaluator-model"
    assert [s.inputs["speaker"] for s in bloom.steps] == ["auditor", "auditor", "target", "judge"]


def test_a_blind_import_hides_the_target(room, capsys):
    tmp, repo = room
    run, out = _blind(capsys, tmp)
    assert out["target_model"] is None and out["sealed"].startswith("sha256:")
    stored = repo.load_run(run)
    assert "example/target-model" not in json.dumps(stored.to_dict())
    secret = json.loads((tmp / "secret.json").read_bytes())
    assert _audit_game.commitment(secret) == out["sealed"]
    _schemas.validate(out, "tine-cli-auditor-1")


def test_a_game_played_in_order_checks_clean_with_a_pinned_auditor(room, capsys):
    tmp, repo = room
    run, _ = _blind(capsys, tmp)
    secret = ("--secret", str(tmp / "secret.json"))
    _step(capsys, tmp, "seal", run, "owner.key", "2026-11-01T00:00:00Z", *secret)
    _step(capsys, tmp, "findings", run, "auditor.key", "2026-11-01T01:00:00Z",
          "--findings", str(tmp / "findings.md"), "--verdict", "no-concern")  # fmt: skip
    _step(capsys, tmp, "reveal", run, "owner.key", "2026-11-01T02:00:00Z", *secret)
    code, out = _tine(capsys, "auditor", "check", "--repo", str(tmp / "r"))
    assert code == 0 and out["games"][0]["state"] == "revealed"
    assert out["games"][0]["target"] == "example/target-model"
    assert [f["code"] for f in out["findings"]] == ["advisory:audit-game.auditor-unpinned"]
    _schemas.validate(out, "tine-cli-auditor-1")
    _pin(repo)
    code, out = _tine(capsys, "auditor", "check", "--repo", str(tmp / "r"), "--strict")
    assert code == 0 and out["findings"] == []
    oid = out["games"][0]["reveal"]
    with pytest.raises(HoldError):
        release(repo, oid)


def test_a_reveal_before_the_verdict_is_detected(room, capsys):
    tmp, _ = room
    run, _ = _blind(capsys, tmp)
    secret = ("--secret", str(tmp / "secret.json"))
    _step(capsys, tmp, "seal", run, "owner.key", "2026-11-01T00:00:00Z", *secret)
    _step(capsys, tmp, "reveal", run, "owner.key", "2026-11-01T01:00:00Z", *secret)
    _step(capsys, tmp, "findings", run, "auditor.key", "2026-11-01T02:00:00Z",
          "--findings", str(tmp / "findings.md"), "--verdict", "concern")  # fmt: skip
    code, out = _tine(capsys, "auditor", "check", "--repo", str(tmp / "r"))
    assert code == 1 and not out["ok"]
    assert "fail:audit-game.reveal-before-verdict" in {f["code"] for f in out["findings"]}


def test_a_reveal_that_does_not_open_the_seal_fails(room, capsys):
    tmp, _ = room
    run, _ = _blind(capsys, tmp)
    _step(capsys, tmp, "seal", run, "owner.key", "2026-11-01T00:00:00Z",
          "--secret", str(tmp / "secret.json"))  # fmt: skip
    _step(capsys, tmp, "findings", run, "auditor.key", "2026-11-01T01:00:00Z",
          "--findings", str(tmp / "findings.md"), "--verdict", "concern")  # fmt: skip
    forged = {**json.loads((tmp / "secret.json").read_bytes()), "target": "example/other"}
    (tmp / "forged.json").write_bytes(json.dumps(forged).encode("utf-8"))
    _step(capsys, tmp, "reveal", run, "owner.key", "2026-11-01T02:00:00Z",
          "--secret", str(tmp / "forged.json"))  # fmt: skip
    code, out = _tine(capsys, "auditor", "check", "--repo", str(tmp / "r"))
    assert code == 1
    assert "fail:audit-game.commitment-mismatch" in {f["code"] for f in out["findings"]}


def test_findings_need_a_seal(room, capsys):
    tmp, _ = room
    run, _ = _blind(capsys, tmp)
    code, _ = _tine(capsys, "auditor", "findings", run, "--game", "g1", "--key",
                    str(tmp / "auditor.key"), "--findings", str(tmp / "findings.md"),
                    "--verdict", "concern", "--repo", str(tmp / "r"))  # fmt: skip
    assert code != 0
