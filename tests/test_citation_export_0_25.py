"""0.25.0 phase 6: ``tine export --format citation | ro-crate``, and the trust
material ``tine evidence export`` now carries (``--attestation``, ``--trusted-root``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._version import __version__
from opentine.signing import HAS_ED25519, generate_ed25519

needs_ed25519 = pytest.mark.skipif(not HAS_ED25519, reason="ed25519 needs the crypto extra")
CFF_REQUIRED = ("cff-version", "message", "title", "authors")


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.delenv("OPENTINE_OUTPUT", raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="cite_run", model_info="model-a", user_prompt="p")
    run.created_at = 1767225600.0
    run.add_step(StepKind.think, {"text": "t"}, model_info="model-b")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
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


def _digest(room: Path) -> str:
    return "sha256:" + Run.verify_integrity(room / "run.tine").actual


def _cff(text: str) -> dict[str, str]:
    """Top-level ``key: value`` pairs of the CFF document (values JSON-quoted)."""
    out = {}
    for line in text.splitlines():
        if line and not line.startswith((" ", "-")):
            key, _, value = line.partition(":")
            out[key] = value.strip()
    return out


def test_citation_cff_has_the_required_keys_and_the_run_facts(room, capsys):
    code, text = _invoke(capsys, "export", "run.tine", "--format", "citation")
    assert code == 0
    top = _cff(text)
    for key in CFF_REQUIRED:
        assert key in top, key
    assert top["cff-version"] == "1.2.0" and top["type"] == "dataset"
    assert json.loads(top["date-released"]) == "2026-01-01"
    for needle in (_digest(room), "opentine-run:cite_run", f"opentine:{__version__}"):
        assert json.dumps(needle) in text, needle
    assert '  - "model-a"' in text and '  - "model-b"' in text
    assert "  - name: " in text  # at least one author entity


def test_citation_output_is_deterministic_and_writes_a_file(room, capsys):
    first = _invoke(capsys, "export", "run.tine", "--format", "citation")[1]
    assert first == _invoke(capsys, "export", "run.tine", "--format", "citation")[1]
    argv = ("export", "run.tine", "--format", "citation", "--output", "CITATION.cff")
    assert _invoke(capsys, *argv)[0] == 0
    assert (room / "CITATION.cff").read_text(encoding="utf-8") == first


def test_ro_crate_has_a_root_dataset_and_a_metadata_descriptor(room, capsys):
    code, text = _invoke(capsys, "export", "run.tine", "--format", "ro-crate")
    assert code == 0
    doc = json.loads(text)
    assert doc["@context"] == "https://w3id.org/ro/crate/1.1/context"
    graph = {entity["@id"]: entity for entity in doc["@graph"]}
    descriptor = graph["ro-crate-metadata.json"]
    assert descriptor["@type"] == "CreativeWork"
    assert descriptor["about"] == {"@id": "./"}
    assert descriptor["conformsTo"] == {"@id": "https://w3id.org/ro/crate/1.1"}
    root = graph["./"]
    assert root["@type"] == "Dataset" and root["identifier"] == _digest(room)
    assert root["datePublished"] == "2026-01-01" and "name" in root and "description" in root
    assert {"@id": "run.tine"} in root["hasPart"] and graph["run.tine"]["@type"] == "File"
    names = {e.get("name") for e in graph.values() if e["@type"] == "SoftwareApplication"}
    assert {"opentine", "model-a", "model-b"} <= names
    tool = next(e for e in graph.values() if e.get("name") == "opentine")
    assert tool["version"] == __version__
    assert text == _invoke(capsys, "export", "run.tine", "--format", "ro-crate")[1]


def test_a_run_whose_digest_fails_is_not_cited(room, capsys):
    from opentine._artifact_io import read_artifact_json

    data = read_artifact_json(room / "run.tine")
    data["run_id"] = "someone_else"
    (room / "bad.tine").write_text(json.dumps(data), encoding="utf-8")
    for fmt in ("citation", "ro-crate"):
        code, out = _invoke(capsys, "export", "bad.tine", "--format", fmt)
        assert code == 1 and "@context" not in out and "cff-version" not in out


def test_citation_refuses_an_endpoint(room, capsys):
    argv = ("export", "run.tine", "--format", "citation", "--endpoint", "http://127.0.0.1:9")
    assert _invoke(capsys, *argv)[0] == 1


@needs_ed25519
def test_evidence_export_carries_the_attestation(room, capsys):
    argv = ("export", "ed.tine", "--format", "intoto", "--ed25519-key-file", "ed.hex")
    assert _invoke(capsys, *argv, "--output", "a.intoto.jsonl")[0] == 0
    argv = ("evidence", "export", "ed.tine", "--out", "ev", "--pubkey", "ed.pub")
    assert _invoke(capsys, *argv, "--attestation", "a.intoto.jsonl")[0] == 0
    copied = (room / "ev" / "trust" / "attestation.intoto.jsonl").read_bytes()
    assert copied == (room / "a.intoto.jsonl").read_bytes()
    report = json.loads((room / "ev" / "verify-report.json").read_text(encoding="utf-8"))
    attestation = next(c for c in report["runs"][0]["checks"] if c["name"] == "attestation")
    assert attestation["outcome"] == "pass"
    manifest = (room / "ev" / "MANIFEST.sha256").read_text(encoding="utf-8")
    assert "trust/attestation.intoto.jsonl" in manifest
    # a trusted root only checks a keyless attestation: refused, never silently copied
    (room / "root.json").write_text("{}\n", encoding="utf-8")
    argv = ("evidence", "export", "ed.tine", "--out", "ev2", "--trusted-root", "root.json")
    assert _invoke(capsys, *argv)[0] == 1
    keyed = ("--attestation", "a.intoto.jsonl", "--pubkey", "ed.pub")
    assert _invoke(capsys, *argv, *keyed)[0] == 1
    assert not (room / "ev2" / "trust").exists()


@needs_ed25519
def test_evidence_export_refuses_one_attestation_for_two_runs(room, capsys):
    argv = ("evidence", "export", "ed.tine", "run.tine", "--out", "ev")
    assert _invoke(capsys, *argv, "--attestation", "a.intoto.jsonl")[0] == 1
    assert not (room / "ev").exists()
