"""0.42.0: ``.tine`` v5 is the default writer (SPEC Part 10).

``--for-legacy`` (``--format 4``, ``OPENTINE_FORMAT=4``) still writes v4 for
readers before 0.40, ``tine evidence export`` copies runs as v4, and a run
saved both ways has the same root and the same signature.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._artifact_io import read_artifact_bytes, read_artifact_json
from opentine._cli_parser import _build_parser
from opentine._format_v4 import FORMAT_ENV
from opentine._pyz_build import build_bytes
from opentine._signing_v4 import verify_artifact_v4
from opentine._tine_v5 import ARTIFACT_V5_KIND, to_v4
from opentine.kernel import canonical_json
from opentine.signing import HAS_ED25519, generate_ed25519

AT = "2026-11-01T00:00:00Z"


@pytest.fixture(autouse=True)
def _room(tmp_path, monkeypatch):
    monkeypatch.delenv(FORMAT_ENV, raising=False)
    monkeypatch.chdir(tmp_path)


def _run(name: str = "r42") -> Run:
    run = Run(id=name, model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.think, {"text": "line one\nline two\n" * 20})
    run.add_step(StepKind.done, {"text": "done é"})
    run.status = RunStatus.completed
    return run


def _kind(path) -> str:
    return json.loads(read_artifact_bytes(path))["kind"]


def test_the_parser_maps_for_legacy_to_format_4():
    parser = _build_parser()
    assert parser.parse_args(["--for-legacy", "ls"]).write_format == 4
    assert parser.parse_args(["--format", "4", "ls"]).write_format == 4
    assert parser.parse_args(["ls"]).write_format is None
    with pytest.raises(SystemExit):
        parser.parse_args(["--for-legacy", "--format", "5", "ls"])


def test_the_cli_writes_v5_by_default_and_v4_for_legacy(tmp_path):
    _run().save(tmp_path / "src.tine")
    assert _kind(tmp_path / "src.tine") == ARTIFACT_V5_KIND
    (tmp_path / "k.key").write_bytes(b"k" * 32)
    for flags, kind in (([], ARTIFACT_V5_KIND), (["--for-legacy"], "tine-artifact/4")):
        out = tmp_path / f"out{len(flags)}.tine"
        cli.main([*flags, "sign", "src.tine", "--key-file", "k.key", "--save", str(out)])
        assert _kind(out) == kind


@pytest.mark.skipif(not HAS_ED25519, reason="ed25519 needs the crypto extra")
def test_v4_and_v5_have_the_same_root_and_ed25519_signature(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed, _public = generate_ed25519()
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    sign = {
        "sign_key": bytes.fromhex(seed),
        "sign_algorithm": "ed25519",
        "key_id": "k",
        "signed_at": AT,
    }
    run = _run()
    run.save(tmp_path / "v5.tine", **sign)
    monkeypatch.setenv(FORMAT_ENV, "4")
    run.save(tmp_path / "v4.tine", **sign)
    v5 = read_artifact_json(tmp_path / "v5.tine")
    v4 = read_artifact_json(tmp_path / "v4.tine")
    raw5 = json.loads(read_artifact_bytes(tmp_path / "v5.tine"))
    assert raw5["kind"] == ARTIFACT_V5_KIND and v4["kind"] == "tine-artifact/4"
    assert raw5["root"] == v4["root"] and raw5["signatures"] == v4["signatures"]
    assert canonical_json(to_v4(raw5)) == canonical_json(v4)
    for document in (raw5, v5, v4):
        result = verify_artifact_v4(document, public_key=key.public_key())
        assert result.ok and result.state == "verified"


def test_evidence_export_keeps_runs_on_v4(tmp_path):
    _run().save(tmp_path / "run.tine")
    assert _kind(tmp_path / "run.tine") == ARTIFACT_V5_KIND
    root = json.loads(read_artifact_bytes(tmp_path / "run.tine"))["root"]
    cli.main(["evidence", "export", "run.tine", "--out", "ev", "--with-verifier"])
    copied = tmp_path / "ev" / "runs" / "run.tine"
    assert _kind(copied) == "tine-artifact/4"
    assert json.loads(read_artifact_bytes(copied))["root"] == root
    done = subprocess.run(
        [sys.executable, "-I", "-S", str(tmp_path / "ev" / "tine-verify.pyz"), "ev"],
        capture_output=True, text=True, timeout=120, cwd=tmp_path,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout


def test_the_offline_pyz_verifies_the_default_output(tmp_path):
    _run().save(tmp_path / "run.tine")
    (tmp_path / "tine-verify.pyz").write_bytes(build_bytes())
    done = subprocess.run(
        [sys.executable, "-I", "-S", "tine-verify.pyz", "run.tine"],
        capture_output=True, text=True, timeout=60, cwd=tmp_path,
    )  # fmt: skip
    report = json.loads(done.stdout)
    assert report["verdict"] in {"pass", "fail"}
    assert report["checks"][0]["outcome"] == "pass", report
