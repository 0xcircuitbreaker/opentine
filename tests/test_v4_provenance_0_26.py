"""0.26.0 phase 4: ``upgraded_from`` inside the run, ``tine migrate --to v4`` and
the ``provenance`` check of ``tine verify --offline`` (SPEC 9.9, 8.2).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._artifact_io import read_artifact_bytes, read_artifact_json
from opentine._artifact_v4 import read_v4, write_v4
from opentine._format_v4 import is_v4_artifact, write_format
from opentine._provenance_v4 import valid_upgraded_from
from opentine.kernel import canonical_json
from opentine.signing import HAS_ED25519, generate_ed25519

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
VERIFIER = ROOT / "docs" / "conformance" / "minimal_verifier.py"
EPOCH = "1700000000"
needs_ed25519 = pytest.mark.skipif(not HAS_ED25519, reason="ed25519 needs the crypto extra")
COMPAT = (FIXTURES / "compat").rglob("*.tine")
GOLDEN = sorted(FIXTURES.glob("golden_*.tine")) + sorted(p for p in COMPAT if p.is_file())
REPOS = sorted(p for p in (FIXTURES / "compat").glob("*/repo") if p.is_dir())


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", EPOCH)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="prov", model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.think, {"text": "thinking", "cost_hint": 0.25})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    with write_format(2):  # the migration sources are v2 files (v4 is the 0.26 default)
        run.save(tmp_path / "src.tine")
        if HAS_ED25519:
            seed, public = generate_ed25519()
            (tmp_path / "ed.pub").write_text(public + "\n", encoding="utf-8")
            run.save(tmp_path / "signed.tine", sign_key=seed, sign_algorithm="ed25519")
    return tmp_path


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, " ".join((captured.out + captured.err).split())


def _payload(path: Path) -> dict:
    data = read_artifact_json(path)
    return data["objects"][data["root"]]["body"]


def _offline(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(["verify", *argv, "--offline", "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _provenance(report: dict) -> tuple[str, str]:
    check = next(c for c in report["checks"] if c["name"] == "provenance")
    assert check["required"] is False
    return check["outcome"], check["reason"]


def test_migrate_writes_a_new_file_and_never_touches_the_original(room, capsys):
    before = (room / "src.tine").read_bytes()
    code, out = _tine(capsys, "migrate", "src.tine", "--to", "v4")
    assert code == 0, out
    assert (room / "src.tine").read_bytes() == before
    assert Run.load(room / "src.v4.tine").id == "prov"
    assert not list(room.glob("*.bak"))


def test_upgraded_from_digest_is_the_sha256_of_the_unwrapped_source(room, capsys):
    assert _tine(capsys, "migrate", "src.tine", "--to", "v4", "-o", "out.tine")[0] == 0
    record = _payload(room / "out.tine")["upgraded_from"]
    assert valid_upgraded_from(record)
    expected = hashlib.sha256(read_artifact_bytes(room / "src.tine")).hexdigest()
    assert record["digest"] == expected and record["format"] == "tine/2"
    assert (
        record["integrity_digest"]
        == read_artifact_json(room / "src.tine")["metadata"]["integrity"]["digest"]
    )
    assert record["signature"]["state"] == "unsigned"
    assert record["upgraded_at"] == "2023-11-14T22:13:20Z"


def test_upgraded_from_is_covered_by_the_root_and_survives_a_rewrite(room, capsys):
    assert _tine(capsys, "migrate", "src.tine", "--to", "v4", "-o", "out.tine")[0] == 0
    data = read_artifact_json(room / "out.tine")
    run = read_v4(canonical_json(data))
    assert canonical_json(json.loads(write_v4(run))) == canonical_json(data)  # read, write: same
    root = data["root"]
    data["objects"][root]["body"]["upgraded_from"]["digest"] = "0" * 64
    with pytest.raises(ValueError, match="object id mismatch"):
        read_v4(canonical_json(data))
    (room / "bad.tine").write_bytes(canonical_json(data))
    code, report = _offline(capsys, "bad.tine")
    assert code == 1 and report["checks"][0]["outcome"] == "fail"


def test_in_place_keeps_a_v2_backup_and_warns(room, capsys):
    before = (room / "src.tine").read_bytes()
    code, out = _tine(capsys, "migrate", "src.tine", "--to", "v4", "--in-place")
    assert code == 0, out
    assert (room / "src.tine.v2.bak").read_bytes() == before
    assert read_artifact_json(room / "src.tine")["kind"] == "tine-artifact/4"
    assert "orphaned" in out


def test_flag_conflicts_are_refused(room, capsys):
    for extra, phrase in (
        (["--in-place", "-o", "x.tine"], "cannot be combined"),
        (["--dry-run", "-o", "x.tine"], "no effect"),
        (["--save", "x.tine"], "no effect"),
    ):
        code, out = _tine(capsys, "migrate", "src.tine", "--to", "v4", *extra)
        assert code == 1 and phrase in out, out
    code, out = _tine(capsys, "migrate", "src.tine", "--to", "2", "-o", "x.tine")
    assert code == 1 and "without --to v4" in out
    assert not (room / "x.tine").exists()


def test_integers_beyond_2_53_are_refused_never_rounded(room, capsys):
    data = read_artifact_json(room / "src.tine")
    run = Run.load(room / "src.tine")
    run.steps[0].outputs["big"] = 2**60
    with write_format(2):  # a v2 source holding a wide integer
        run.save(room / "big.tine")
    assert data  # the source itself stays a valid v2 file
    code, out = _tine(capsys, "migrate", "big.tine", "--to", "v4")
    assert code == 1 and "2**53-1" in out and "big" in out
    assert not (room / "big.v4.tine").exists()


@needs_ed25519
def test_a_signed_source_records_a_verified_state(room, capsys):
    argv = ("migrate", "signed.tine", "--to", "v4", "--pubkey", "ed.pub", "-o", "s4.tine")
    assert _tine(capsys, *argv)[0] == 0
    block = _payload(room / "s4.tine")["upgraded_from"]["signature"]
    assert block["state"] == "verified" and block["scheme"] == "tine-sig/2"
    assert block["key_fingerprint"] and "--pubkey" in block["trust_basis"]
    assert _tine(capsys, "migrate", "signed.tine", "--to", "v4", "-o", "n4.tine")[0] == 0
    assert _payload(room / "n4.tine")["upgraded_from"]["signature"]["state"] == "no-key"


def test_verify_provenance_codes(room, capsys):
    assert _tine(capsys, "migrate", "src.tine", "--to", "v4", "-o", "out.tine")[0] == 0
    assert _provenance(_offline(capsys, "src.tine")[1]) == ("not-applicable", "provenance.none")
    code, report = _offline(capsys, "out.tine")
    assert code == 0 and _provenance(report) == ("unavailable-offline", "provenance.recorded")
    names = [c["name"] for c in report["checks"]]
    assert names.index("provenance") == names.index("signature") + 1
    code, report = _offline(capsys, "out.tine", "--source", "src.tine")
    assert code == 0 and _provenance(report) == ("pass", "provenance.source-match")
    other = Run.load(room / "src.tine")
    other.steps[0].outputs["text"] = "edited"
    with write_format(2):
        other.save(room / "other.tine")
    code, report = _offline(capsys, "out.tine", "--source", "other.tine")
    assert code == 1 and _provenance(report) == ("fail", "provenance.source-mismatch")


def test_source_without_offline_is_refused(room, capsys):
    code, out = _tine(capsys, "verify", "src.tine", "--source", "src.tine")
    assert code == 1 and "--source" in out and "no effect" in out


def _minimal(*argv: str) -> tuple[int, dict]:
    done = subprocess.run(
        [sys.executable, "-I", str(VERIFIER), "artifact", *argv],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return done.returncode, json.loads(done.stdout)


def _agree(capsys, target: str, *extra: str) -> dict:
    code, mine = _minimal(target, *extra)
    ref_code, ref = _offline(capsys, target, *extra)
    assert (code, mine["verdict"]) == (ref_code, ref["verdict"])
    theirs = {c["name"]: (c["outcome"], c["reason"]) for c in ref["checks"]}
    for check in mine["checks"]:
        if check["reason"] != "signature.crypto-unavailable":
            assert (check["outcome"], check["reason"]) == theirs[check["name"]], check
    return mine


def test_minimal_verifier_agrees_on_v4(room, capsys, monkeypatch):
    assert _tine(capsys, "migrate", "src.tine", "--to", "v4", "-o", "up.tine")[0] == 0
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    Run.load(room / "src.tine").save(room / "plain4.tine")
    _agree(capsys, "plain4.tine")
    _agree(capsys, "up.tine")
    assert _agree(capsys, "up.tine", "--source", "src.tine")["checks"][2]["reason"] == (
        "provenance.source-match"
    )
    _agree(capsys, "up.tine", "--source", "plain4.tine")
    data = read_artifact_json(room / "up.tine")
    event = next(oid for oid in data["objects"] if oid.startswith("event:"))
    data["objects"][event]["body"]["cost"] = 12345
    (room / "tampered.tine").write_bytes(canonical_json(data))
    assert _agree(capsys, "tampered.tine")["verdict"] == "fail"


@needs_ed25519
def test_minimal_verifier_agrees_on_signed_v4(room, capsys, monkeypatch):
    seed, public = generate_ed25519()
    (room / "k.pub").write_text(public + "\n", encoding="utf-8")
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    Run.load(room / "src.tine").save(room / "s4.tine", sign_key=seed, sign_algorithm="ed25519")
    assert _agree(capsys, "s4.tine")["checks"][1]["reason"] == "signature.no-key"
    _agree(capsys, "s4.tine", "--pubkey", "k.pub")


def test_a_v3_repository_run_upgrades_to_a_v4_file(room, capsys):
    shutil.copytree(FIXTURES / "compat" / "v0_18_0" / "repo", room / "repo")
    argv = ("migrate", "heads/main", "--to", "v4", "--repo", "repo", "-o", "r4.tine")
    code, out = _tine(capsys, *argv)
    assert code == 0, out
    # SPEC 9.10: the stored envelopes, verbatim -- the root IS the repository oid,
    # so no upgraded_from is added (it would move the root).
    from opentine.repository import Repo

    assert read_artifact_json(room / "r4.tine")["root"] == Repo.open("repo").read_ref("heads/main")
    assert "upgraded_from" not in _payload(room / "r4.tine")
    code, _ = _offline(capsys, "r4.tine")
    assert code == 0


def _root(capsys, source: Path, out: str) -> str:
    code, text = _tine(capsys, "migrate", str(source), "--to", "v4", "-o", out, "--force")
    assert code == 0, text
    return read_artifact_json(Path(out))["root"]


@pytest.mark.parametrize("source", GOLDEN, ids=lambda p: str(p.relative_to(FIXTURES)))
def test_every_golden_artifact_migrates_to_a_stable_root(room, capsys, source):
    before = source.read_bytes()
    if is_v4_artifact(read_artifact_json(source)):  # 0.26.0+ wrote v4 already
        code, text = _tine(capsys, "migrate", str(source), "--to", "v4", "-o", "a.tine")
        assert code == 0 and "already format v4" in text, text
        assert not (room / "a.tine").exists() and source.read_bytes() == before
        return
    first = _root(capsys, source, "a.tine")
    second = _root(capsys, source, "b.tine")
    if "linear" not in source.name:  # 0.1.0 recorded no created_at: the loader stamps now
        assert second == first
        assert (room / "a.tine").read_bytes() == (room / "b.tine").read_bytes()
    assert source.read_bytes() == before
    assert Run.load(room / "a.tine").id == Run.load(source).id


@pytest.mark.parametrize("repo", REPOS, ids=lambda p: p.parent.name)
def test_every_golden_repository_migrates_to_a_stable_root(room, capsys, repo):
    shutil.copytree(repo, room / "repo")
    roots = []
    for out in ("a.tine", "b.tine"):
        argv = ("migrate", "heads/main", "--to", "v4", "--repo", "repo", "-o", out, "--force")
        code, text = _tine(capsys, *argv)
        assert code == 0, text
        roots.append(read_artifact_json(room / out)["root"])
    assert roots[0] == roots[1]
