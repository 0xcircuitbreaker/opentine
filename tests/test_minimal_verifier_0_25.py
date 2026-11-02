"""0.25.0 phase 5: the standalone verifier agrees with ``tine verify --offline``.

``docs/conformance/minimal_verifier.py`` is run as a separate ``python -I``
process, so it cannot borrow opentine from this interpreter, and its verdicts
are held to the reference's on a valid run, tampered runs, an evidence export
and a dataset Merkle root.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._artifact_io import read_artifact_json
from opentine.signing import HAS_ED25519, generate_ed25519

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "docs" / "conformance" / "minimal_verifier.py"
needs_ed25519 = pytest.mark.skipif(not HAS_ED25519, reason="ed25519 needs the crypto extra")


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.delenv("OPENTINE_OUTPUT", raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    for run_id in ("alpha", "beta"):
        run = Run(id=run_id, model_info="mock-model", user_prompt="p")
        run.add_step(StepKind.think, {"text": f"thinking {run_id}"})
        run.add_step(StepKind.done, {"text": "done"})
        run.status = RunStatus.completed
        run.save(tmp_path / f"{run_id}.tine")
        if HAS_ED25519 and run_id == "alpha":
            seed, public = generate_ed25519()
            (tmp_path / "ed.hex").write_text(seed + "\n", encoding="utf-8")
            (tmp_path / "ed.pub").write_text(public + "\n", encoding="utf-8")
            run.save(tmp_path / "signed.tine", sign_key=seed, sign_algorithm="ed25519")
    return tmp_path


def _minimal(*argv: str, flags: tuple[str, ...] = ("-I",)) -> tuple[int, dict]:
    done = subprocess.run(
        [sys.executable, *flags, str(VERIFIER), *argv], capture_output=True, text=True, timeout=60
    )
    return done.returncode, json.loads(done.stdout)


def _reference(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(["verify", *argv, "--offline", "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _checks(report: dict) -> dict[str, tuple[str, str]]:
    return {c["name"]: (c["outcome"], c["reason"]) for c in report["checks"]}


def _tamper(room: Path, source: str, edit) -> str:
    data = read_artifact_json(room / source)
    edit(data)
    name = f"tampered-{source}"
    (room / name).write_text(json.dumps(data), encoding="utf-8")
    return name


def _agree(capsys, target: str, *keys: str) -> dict:
    code, mine = _minimal("artifact", target, *keys)
    ref_code, ref = _reference(capsys, target, *keys)
    assert (code, mine["verdict"]) == (ref_code, ref["verdict"])
    ours, theirs = _checks(mine), _checks(ref)
    for name in ("digest", "signature"):
        assert ours[name] == theirs[name], name
    return mine


def test_the_minimal_verifier_imports_nothing_but_the_standard_library():
    tree = ast.parse(VERIFIER.read_text(encoding="utf-8"))
    names = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
             for alias in node.names}  # fmt: skip
    names |= {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    optional = {"cryptography.exceptions", "cryptography.hazmat.primitives.asymmetric.ed25519"}
    assert not any(name.startswith("opentine") for name in names)
    assert names - optional <= set(sys.stdlib_module_names) | {"__future__", "compression"}


def test_a_valid_run_passes_in_both(room, capsys):
    report = _agree(capsys, "beta.tine")
    assert report["ok"] and _checks(report)["signature"][1] == "signature.unsigned"


def test_a_tampered_step_fails_in_both(room, capsys):
    def edit(data: dict) -> None:
        first = data["graph"]["order"][0]
        data["graph"]["steps"][first]["inputs"]["text"] = "rewritten"

    report = _agree(capsys, _tamper(room, "beta.tine", edit))
    assert not report["ok"] and _checks(report)["digest"] == ("fail", "digest.mismatch")


def test_a_format_version_1_artifact_passes_in_both(room, capsys):
    from opentine._canon import _integrity_digest

    def edit(data: dict) -> None:
        data["format_version"] = 1
        data["metadata"]["integrity"]["digest"] = _integrity_digest(data)

    report = _agree(capsys, _tamper(room, "beta.tine", edit))
    assert report["ok"] and _checks(report)["digest"] == ("pass", "digest.match")


def test_an_unsupported_format_version_fails_in_both(room, capsys):
    report = _agree(capsys, _tamper(room, "beta.tine", lambda d: d.update(format_version=9)))
    assert _checks(report)["digest"] == ("fail", "digest.unsupported-format")


@needs_ed25519
def test_signatures_agree_with_and_without_a_key(room, capsys):
    assert _checks(_agree(capsys, "signed.tine"))["signature"][1] == "signature.no-key"
    report = _agree(capsys, "signed.tine", "--pubkey", "ed.pub")
    assert _checks(report)["signature"] == ("pass", "signature.verified")
    # metadata sits outside the digest but inside tine-sig/2
    edited = _tamper(room, "signed.tine", lambda d: d["metadata"].update(user_prompt="x"))
    report = _agree(capsys, edited, "--pubkey", "ed.pub")
    assert _checks(report)["signature"] == ("fail", "signature.mismatch")


@needs_ed25519
def test_without_cryptography_the_signature_is_unavailable_never_passed(room):
    code, report = _minimal("artifact", "signed.tine", "--pubkey", "ed.pub", flags=("-I", "-S"))
    assert _checks(report)["signature"] == ("unavailable-offline", "signature.crypto-unavailable")
    assert code == 0 and report["ok"]


def test_a_dataset_root_matches_the_reference(room, capsys):
    (room / "ds").mkdir()
    for name in ("alpha.tine", "beta.tine"):
        (room / "ds" / name).write_bytes((room / name).read_bytes())
    code, mine = _minimal("dataset", "ds")
    ref_code, ref = _reference(capsys, "ds")
    assert (code, mine["verdict"]) == (ref_code, ref["verdict"]) == (0, "pass")
    assert mine["merkle"]["root"] == ref["merkle"]["root"]
    assert [(r["run_id"], r["digest"]) for r in mine["runs"]] == [
        (r["run_id"], r["digest"]) for r in ref["runs"]
    ]


@needs_ed25519
def test_an_evidence_export_verifies_and_a_changed_file_is_caught(room, capsys):
    try:
        cli.main(["evidence", "export", "alpha.tine", "--out", "ev", "--sign", "ed.hex"])
    except SystemExit as exc:
        assert not exc.code
    capsys.readouterr()
    code, mine = _minimal("evidence", "ev")
    ref_code, ref = _reference(capsys, "ev")
    assert (code, mine["verdict"]) == (ref_code, ref["verdict"]) == (0, "pass")
    assert mine["merkle"]["root"] == ref["merkle"]["root"]
    checks = _checks(mine)
    assert checks["manifest"] == ("pass", "evidence.manifest-match")
    assert checks["custody"] == ("pass", "evidence.custody-linked")
    assert checks["custody-signature"][0] == "pass"
    (room / "ev" / "timeline.csv").write_text("forged\n", encoding="utf-8")
    code, mine = _minimal("evidence", "ev")
    assert code == 1 and _checks(mine)["manifest"] == ("fail", "evidence.manifest-mismatch")
