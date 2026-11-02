"""0.25.0 phases 3-4: --locate, claims cross-check, dataset mode, evidence export.

Every tamper vector flips one byte in one region of an otherwise valid run.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import socket
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine import _actions_manifest as manifest_mod
from opentine._actions_verdict import manifest_path, save_manifest
from opentine._artifact_io import read_artifact_json
from opentine._evidence_export import verify_custody
from opentine._verify_dataset import leaf_hash, merkle_root
from opentine.signing import HAS_ED25519, generate_ed25519

needs_ed25519 = pytest.mark.skipif(not HAS_ED25519, reason="ed25519 needs the crypto extra")


def _run(run_id: str = "locate_run") -> Run:
    run = Run(id=run_id, model_info="mock-model", user_prompt="test prompt")
    run.add_step(StepKind.think, {"text": "thinking"})
    run.add_step(
        StepKind.tool, {"name": "bash", "arguments": {"command": "ls"}}, outputs={"output": "a.txt"}
    )
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    return run


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.delenv("OPENTINE_OUTPUT", raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: calls.append("dns"))
    run = _run()
    run.save(tmp_path / "run.tine")
    if HAS_ED25519:
        seed, public = generate_ed25519()
        (tmp_path / "ed.hex").write_text(seed + "\n", encoding="utf-8")
        (tmp_path / "ed.pub").write_text(public + "\n", encoding="utf-8")
        run.save(tmp_path / "ed.tine", sign_key=seed, sign_algorithm="ed25519")
    return tmp_path


def _invoke(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _locate(capsys, target: str, *extra: str) -> tuple[int, dict]:
    code, out = _invoke(capsys, "verify", target, "--offline", "--locate", "--json", *extra)
    return code, json.loads(out)


def _tamper(room: Path, edit, name: str = "bad.tine", source: str = "run.tine") -> str:
    data = read_artifact_json(room / source)
    edit(data)
    (room / name).write_text(json.dumps(data), encoding="utf-8")
    return name


def _steps(data: dict) -> list[dict]:
    return [data["graph"]["steps"][key] for key in data["graph"]["order"]]


def _flip(text: str) -> str:
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def _sign_manifest(room: Path) -> Path:
    return save_manifest(
        room / ".tine_runs" / "manifests",
        manifest_mod.sign(Run.load(room / "run.tine"), b"k" * 32, algorithm="hmac-sha256"),
    )


def _check(doc: dict, name: str) -> dict:
    return next(c for c in doc["checks"] if c["name"] == name)


def test_flipped_step_byte_is_localised_to_that_step(room, capsys):
    def edit(data):
        _steps(data)[1]["inputs"]["arguments"]["command"] = "lt"

    code, doc = _locate(capsys, _tamper(room, edit))
    where = doc["location"]
    order = read_artifact_json(room / "run.tine")["graph"]["order"]
    assert code == 1 and where["region"] == "step" and where["reason"] == "locate.step-id-mismatch"
    assert where["step_index"] == 1 and where["step_id"] == order[1]
    assert where["field_path"] == f"graph.steps.{order[1]}" and "inputs" in where["covered_fields"]
    assert isinstance(where["byte_offset"], int) and "redacted" in where["byte_offset_basis"]


def test_flipped_digest_byte_is_unlocalisable_without_more_evidence(room, capsys):
    def edit(data):
        integrity = data["metadata"]["integrity"]
        integrity["digest"] = _flip(integrity["digest"])

    code, doc = _locate(capsys, _tamper(room, edit))
    assert code == 1 and doc["location"]["reason"] == "locate.unlocalisable"
    assert doc["location"]["localised"] is False  # no guess


@needs_ed25519
def test_flipped_digest_byte_is_the_digest_field_given_an_attestation(room, capsys):
    argv = ("export", "run.tine", "--format", "intoto", "--ed25519-key-file", "ed.hex")
    assert _invoke(capsys, *argv, "--output", "a.jsonl")[0] == 0

    def edit(data):
        integrity = data["metadata"]["integrity"]
        integrity["digest"] = _flip(integrity["digest"])

    bad = _tamper(room, edit)
    code, doc = _locate(capsys, bad, "--attestation", "a.jsonl", "--pubkey", "ed.pub")
    assert code == 1 and doc["location"]["region"] == "digest"
    assert doc["location"]["reason"] == "locate.digest-field"


def test_flipped_byte_outside_any_step_is_not_guessed(room, capsys):
    def edit(data):
        data["created_at"] = data["created_at"] + 1

    code, doc = _locate(capsys, _tamper(room, edit))
    assert code == 1 and doc["location"]["reason"] == "locate.unlocalisable"


def test_flipped_meter_byte_is_found_through_the_action_manifest(room, capsys):
    _sign_manifest(room)

    def edit(data):
        _steps(data)[0]["timestamp"] += 1

    code, doc = _locate(capsys, _tamper(room, edit))
    assert code == 1 and doc["location"]["reason"] == "locate.graph-meters-changed"


@needs_ed25519
def test_flipped_signed_metadata_byte_is_the_signature_region(room, capsys):
    def edit(data):
        data["metadata"]["user_prompt"] = "test prompT"

    bad = _tamper(room, edit, source="ed.tine")
    code, doc = _locate(capsys, bad, "--pubkey", "ed.pub")
    assert code == 1 and _check(doc, "digest")["outcome"] == "pass"
    assert doc["location"]["region"] == "signature"


def test_flipped_manifest_entry_byte_is_the_manifest_region(room, capsys):
    path = _sign_manifest(room)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    entry = manifest["body"]["entries"][0]
    entry["digest"] = _flip(entry["digest"])
    path.write_text(json.dumps(manifest), encoding="utf-8")
    code, doc = _locate(capsys, "run.tine")
    assert code == 1 and _check(doc, "claims")["reason"] == "claims.digest-mismatch"
    assert doc["location"]["region"] == "manifest-entry"


def test_claims_map_to_recorded_tool_steps(room, capsys):
    _sign_manifest(room)
    code, doc = _locate(capsys, "run.tine")
    claims = _check(doc, "claims")
    assert code == 0 and claims["outcome"] == "pass" and claims["detail"].startswith("1 claim")
    assert doc["location"]["reason"] == "locate.nothing-to-locate"


def test_a_tool_output_flip_breaks_the_claim(room, capsys):
    _sign_manifest(room)

    def edit(data):
        _steps(data)[1]["outputs"]["output"] = "a.txT"

    code, doc = _locate(capsys, _tamper(room, edit))
    assert code == 1 and _check(doc, "claims")["reason"] == "claims.output-mismatch"


def test_a_claim_naming_no_tool_step_fails(room, capsys):
    path = _sign_manifest(room)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["body"]["entries"][0]["step_id"] = "0" * 64
    path.write_text(json.dumps(manifest), encoding="utf-8")
    code, doc = _locate(capsys, "run.tine")
    assert code == 1 and _check(doc, "claims")["reason"] == "claims.no-tool-step"
    assert manifest_path(room / ".tine_runs" / "manifests", "locate_run").is_file()


def test_locate_is_refused_without_offline(room, capsys):
    code, out = _invoke(capsys, "verify", "run.tine", "--locate")
    assert code == 1 and "--locate" in out and "no effect" in out


# ------------------------------------------------------------------ dataset


def test_merkle_root_is_documented_hashing():
    a, b, c = ("r1", "aa"), ("r2", "bb"), ("r3", "cc")
    assert merkle_root([]) == hashlib.sha256(b"").hexdigest()
    assert merkle_root([a]) == leaf_hash(*a).hex()
    ab = hashlib.sha256(b"\x01" + leaf_hash(*a) + leaf_hash(*b)).digest()
    assert merkle_root([b, a]) == ab.hex()  # sorted first
    assert merkle_root([c, a, b]) == hashlib.sha256(b"\x01" + ab + leaf_hash(*c)).hexdigest()


def test_directory_dataset_report(room, capsys):
    data = room / "data"
    data.mkdir()
    _run("ds_one").save(data / "one.tine")
    _run("ds_two").save(data / "sub" / "two.tine") if (data / "sub").mkdir() is None else None
    code, out = _invoke(capsys, "verify", str(data), "--offline", "--json")
    doc = json.loads(out)
    assert code == 0 and doc["schema"] == "tine-verify-dataset/1" and doc["count"] == 2
    pairs = [(r["run_id"], r["digest"]) for r in doc["runs"]]
    assert doc["merkle"]["root"] == merkle_root(pairs) and all(len(d) == 64 for _, d in pairs)
    raw = (data / "one.tine").read_bytes()
    loaded = read_artifact_json(data / "one.tine")
    _steps(loaded)[0]["inputs"]["text"] = "thinkinG"
    (data / "one.tine").write_text(json.dumps(loaded), encoding="utf-8")
    code, out = _invoke(capsys, "verify", str(data), "--offline", "--json")
    assert code == 1 and json.loads(out)["verdict"] == "fail" and raw


def test_repository_dataset_report(room, capsys):
    from opentine.repository import Repo

    repo = Repo.init(room / "repo")
    repo.put_run(_run("repo_run"), ref="heads/main")
    code, out = _invoke(capsys, "verify", str(room / "repo"), "--offline", "--json")
    doc = json.loads(out)
    assert doc["kind"] == "repository" and doc["checks"][0]["name"] == "repository"
    assert code == 0 and len(doc["runs"]) == 1 and doc["runs"][0]["run_id"].startswith("run:")
    assert len(doc["runs"][0]["digest"]) == 64


# ------------------------------------------------------------------ evidence


def _export(capsys, out: str, *extra: str) -> int:
    return _invoke(capsys, "evidence", "export", "run.tine", "--out", out, *extra)[0]


@needs_ed25519
def test_evidence_export_layout_and_custody_signature(room, capsys):
    argv = ("--sign", "ed.hex", "--pubkey", "ed.pub", "--operator", "analyst")
    assert _export(capsys, "ev", *argv) == 0
    ev = room / "ev"
    for name in ("MANIFEST.sha256", "custody.jsonl", "timeline.jsonl", "timeline.csv"):
        assert (ev / name).is_file(), name
    assert (ev / "runs" / "run.tine").read_bytes() == (room / "run.tine").read_bytes()
    assert (ev / "trust" / "pubkey.pub").is_file() and (
        ev / "trust" / "custody-signer.pub"
    ).is_file()
    for line in (ev / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        digest, rel = line.split("  ", 1)
        assert hashlib.sha256((ev / rel).read_bytes()).hexdigest() == digest
    record = json.loads((ev / "custody.jsonl").read_text(encoding="utf-8"))
    assert record["exported_by"] == "analyst" and verify_custody(record)
    manifest_hash = hashlib.sha256((ev / "MANIFEST.sha256").read_bytes()).hexdigest()
    assert record["manifest_sha256"] == manifest_hash
    record["exported_by"] = "someone else"
    assert not verify_custody(record)
    rows = list(csv.DictReader((ev / "timeline.csv").open(encoding="utf-8")))
    assert [r["kind"] for r in rows] == ["think", "tool", "done"] and rows[1]["tool"] == "bash"
    report = json.loads((ev / "verify-report.json").read_text(encoding="utf-8"))
    assert report["ok"] and report["runs"][0]["path"] == "runs/run.tine"
    assert str(room) not in (ev / "verify-report.json").read_text(encoding="utf-8")


def test_evidence_export_is_deterministic_but_for_the_custody_time(room, capsys):
    assert _export(capsys, "a", "--operator", "x") == 0
    assert _export(capsys, "b", "--operator", "x") == 0
    files = sorted(p.relative_to(room / "a") for p in (room / "a").rglob("*") if p.is_file())
    assert files == sorted(
        p.relative_to(room / "b") for p in (room / "b").rglob("*") if p.is_file()
    )
    for rel in files:
        left, right = (room / "a" / rel).read_bytes(), (room / "b" / rel).read_bytes()
        if rel.name == "custody.jsonl":
            left, right = (re.sub(rb'"exported_at":"[^"]*"', b"", v) for v in (left, right))
        assert left == right, rel


def test_evidence_export_refuses_a_non_empty_out(room, capsys):
    (room / "full").mkdir()
    (room / "full" / "x").write_text("x", encoding="utf-8")
    assert _export(capsys, "full") == 1
