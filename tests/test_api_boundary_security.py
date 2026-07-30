"""Regression coverage for public artifact, MCP, catalog, and filesystem boundaries."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import opentine._cli_common as cli_common
import opentine.index as run_index
import opentine.mcp_server as legacy_mcp
from opentine import Run, RunStatus, StepKind
from opentine.billing import PricingCatalog
from opentine.billing.catalog import BUNDLED_CATALOG, CatalogError, install_catalog
from opentine.repository import Repo
from opentine.signing import SignatureError
from opentine.tools import fs

HMAC_KEY = b"0123456789abcdef0123456789abcdef"


def _saved_run(path: Path, run_id: str, steps: int = 1) -> Run:
    run = Run(id=run_id, model_info="test-model")
    for index in range(steps):
        run.add_step(StepKind.think, {"text": f"step {index}"})
    run.save(path)
    return run


def test_signature_verification_rejects_weak_keys_and_malformed_shapes(tmp_path: Path):
    path = tmp_path / "signed.tine"
    run = _saved_run(path, "signed")
    run.status = RunStatus.completed
    run.save(path, sign_key=HMAC_KEY)
    data = json.loads(path.read_text(encoding="utf-8"))

    weak = Run.verify_signature(data, hmac_key=b"short")
    malformed = Run.verify_signature({"metadata": []}, hmac_key=HMAC_KEY)
    data["metadata"]["integrity"]["signature"]["key_id"] = []
    malformed_header = Run.verify_signature(data, hmac_key=HMAC_KEY)

    assert not weak.ok and weak.state == "error" and "too short" in weak.reason
    assert not malformed.ok and malformed.state == "error"
    assert not malformed_header.ok and malformed_header.state == "error"


def test_integrity_verification_rejects_malformed_metadata_without_crashing():
    result = Run.verify_integrity({"format_version": 2, "metadata": ["not", "an", "object"]})
    assert not result.ok and result.reason == "missing integrity digest"

    cyclic: dict[str, object] = {"format_version": 2}
    cyclic["metadata"] = {"integrity": {"algorithm": "sha256", "digest": "0" * 64}}
    cyclic["body"] = cyclic
    result = Run.verify_integrity(cyclic)
    assert not result.ok and result.actual is None


def test_v2_migration_rejects_non_object_root_and_empty_verification_key(tmp_path: Path):
    repo = Repo.init(tmp_path / "repo")
    malformed = tmp_path / "array.tine"
    malformed.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="requires a .tine object"):
        repo.migrate_v2(malformed)

    artifact = tmp_path / "unsigned.tine"
    _saved_run(artifact, "unsigned")
    with pytest.raises(SignatureError, match="signature not verified"):
        repo.migrate_v2(artifact, hmac_key=b"")


def test_artifact_parser_rejects_duplicate_keys_and_non_finite_numbers(tmp_path: Path):
    artifact = tmp_path / "valid.tine"
    _saved_run(artifact, "valid")
    raw = artifact.read_text(encoding="utf-8")
    artifact.write_text('{"format_version":999,' + raw[1:], encoding="utf-8")
    result = Run.verify_integrity(artifact)
    assert not result.ok and "duplicate .tine object key" in result.reason
    with pytest.raises(ValueError, match="duplicate .tine object key"):
        Run.load(artifact)

    artifact.write_text('{"format_version":2,"value":NaN}', encoding="utf-8")
    result = Run.verify_integrity(artifact)
    assert not result.ok and "non-finite number" in result.reason


def test_artifact_save_rejects_non_finite_nested_values(tmp_path: Path):
    run = Run(id="non-finite")
    run.metadata["unsafe"] = {"value": float("nan")}
    with pytest.raises(ValueError, match="Out of range float values"):
        run.save(tmp_path / "unsafe.tine")


def test_legacy_mcp_prefixes_are_unambiguous_and_exact_ids_win(tmp_path: Path):
    first = tmp_path / "abc111.tine"
    second = tmp_path / "abc222.tine"
    _saved_run(first, "abc111")
    _saved_run(second, "abc222")

    assert legacy_mcp.find_run("abc111", tmp_path) == first
    with pytest.raises(ValueError, match="Ambiguous"):
        legacy_mcp.find_run("abc", tmp_path)


def test_legacy_mcp_fork_refuses_to_overwrite_an_occupied_artifact_path(tmp_path: Path):
    # 0.4.0: a v2 fork id names the fork ACT (lineage + slice + intent + a recorded
    # nonce), so two forks of one point no longer collide on one filename. The MCP
    # dead end is gone WITHOUT weakening the refusal: an explicitly named destination
    # that already exists is still refused, with no force escape.
    source_path = tmp_path / "source.tine"
    _saved_run(source_path, "source")
    source_bytes = source_path.read_bytes()

    first = legacy_mcp.fork_run_file("source", 0, runs_dir=tmp_path)
    first_path = Path(first["path"])
    first_bytes = first_path.read_bytes()

    # Two repeat forks of the same point get distinct ids and distinct paths.
    second = legacy_mcp.fork_run_file("source", 0, runs_dir=tmp_path)
    second_path = Path(second["path"])
    assert first["new_run_id"] != second["new_run_id"]
    assert first_path != second_path and second_path.exists()
    assert first_path.read_bytes() == first_bytes  # the first fork was never touched

    # save= at an occupied path is still refused with no force escape, whether it
    # points at the first fork's artifact or at the source run itself.
    for occupied in (first_path, source_path):
        with pytest.raises(FileExistsError, match="refusing to overwrite"):
            legacy_mcp.fork_run_file("source", 0, runs_dir=tmp_path, save=occupied)

    assert first_path.read_bytes() == first_bytes
    assert source_path.read_bytes() == source_bytes


def test_legacy_mcp_scan_summary_and_rendering_are_bounded(tmp_path: Path, monkeypatch):
    for index in range(3):
        _saved_run(tmp_path / f"run-{index}.tine", f"run-{index}", steps=4)
    monkeypatch.setattr(legacy_mcp, "MAX_MCP_LIST_RUNS", 1)
    monkeypatch.setattr(legacy_mcp, "MAX_MCP_RENDER_STEPS", 2)
    monkeypatch.setattr(legacy_mcp, "MAX_MCP_TEXT_CHARS", 1_000)

    summaries = legacy_mcp.list_run_summaries(tmp_path)
    rendered = legacy_mcp.format_run_for_llm(Run.load(tmp_path / "run-0.tine"))

    assert len(summaries) == 2 and summaries[-1]["status"] == "truncated"
    assert "2 steps omitted" in rendered
    assert len(rendered) <= 1_000

    monkeypatch.setattr(legacy_mcp, "MAX_MCP_TEXT_CHARS", 120)
    rendered = legacy_mcp.format_run_for_llm(Run.load(tmp_path / "run-0.tine"))
    assert len(rendered) <= 120 and rendered.endswith("... (truncated)")


def test_legacy_mcp_refuses_unbounded_prefix_scans(tmp_path: Path, monkeypatch):
    _saved_run(tmp_path / "one.tine", "one")
    _saved_run(tmp_path / "two.tine", "two")
    monkeypatch.setattr(legacy_mcp, "MAX_MCP_SCAN_RUNS", 1)

    with pytest.raises(ValueError, match="too many saved runs"):
        legacy_mcp.find_run("missing", tmp_path)


def test_filesystem_listing_bounds_entries_and_escapes_line_breaks(tmp_path: Path, monkeypatch):
    for name in ("a", "b", "c"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    monkeypatch.setattr(fs, "MAX_LIST_ENTRIES", 2)
    listing = fs.ls(policy=fs.FilesystemPolicy(roots=(str(tmp_path),)))
    assert "truncated after 2 entries" in listing

    monkeypatch.setattr(fs, "MAX_LIST_ENTRIES", 10)
    try:
        (tmp_path / "line\nbreak").write_text("x", encoding="utf-8")
    except OSError:  # pragma: no cover - unsupported filename on Windows
        return
    listing = fs.ls(policy=fs.FilesystemPolicy(roots=(str(tmp_path),)))
    assert "line\\nbreak" in listing
    assert "line\nbreak" not in listing


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO files are POSIX-only")
def test_filesystem_content_tools_reject_special_files(tmp_path: Path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    policy = fs.FilesystemPolicy(
        roots=(str(tmp_path),),
        write_roots=(str(tmp_path),),
    )
    for operation in (
        lambda: fs.read(str(fifo), policy=policy),
        lambda: fs.edit(str(fifo), "old", "new", policy=policy),
        lambda: fs.write(str(fifo), "new", policy=policy),
    ):
        with pytest.raises(ValueError, match="not a regular file"):
            operation()


def test_legacy_cli_and_index_bound_implicit_artifact_scans(tmp_path: Path, monkeypatch):
    runs = tmp_path / "runs"
    runs.mkdir()
    _saved_run(runs / "one.tine", "one")
    _saved_run(runs / "two.tine", "two")
    monkeypatch.setattr(cli_common, "RUNS_DIR", runs)
    monkeypatch.setattr(cli_common, "MAX_CLI_SCAN_RUNS", 1)
    assert cli_common._find_run("missing-prefix") is None
    assert cli_common._find_run("one") == (runs / "one.tine").resolve()

    monkeypatch.setattr(run_index, "MAX_INDEX_RUNS", 1)
    with pytest.raises(ValueError, match="artifact-count limit"):
        run_index.RunIndex.open(runs).sync()


def test_legacy_index_does_not_follow_scanned_symlinks(tmp_path: Path):
    runs = tmp_path / "runs"
    runs.mkdir()
    outside = tmp_path / "outside.tine"
    _saved_run(outside, "outside")
    try:
        (runs / "linked.tine").symlink_to(outside)
    except OSError:
        pytest.skip("file symlinks are unavailable")
    assert run_index.RunIndex.open(runs).sync().entries == {}


def test_catalog_parser_rejects_signature_malleation_and_bad_json_shapes(tmp_path: Path):
    data = json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))
    signature = data["signature"]["value"]
    data["signature"]["value"] = signature[:12] + "\n" + signature[12:]
    with pytest.raises(CatalogError):
        PricingCatalog.from_dict(data)

    with pytest.raises(CatalogError, match="root is not an object"):
        install_catalog(b"[]", tmp_path / "bad.json")
    with pytest.raises(CatalogError, match="duplicate pricing catalog key"):
        install_catalog(b'{"schema":"a","schema":"b"}', tmp_path / "duplicate.json")
    with pytest.raises(CatalogError, match="non-finite JSON number"):
        install_catalog(b'{"schema":NaN}', tmp_path / "nan.json")

    malformed_card = {
        "schema": "opentine-pricing/1",
        "cards": [{"id": "bad", "provider": "x", "model": "x", "rates": {"input": "nope"}}],
    }
    with pytest.raises(CatalogError, match="invalid pricing rate card"):
        PricingCatalog.from_dict(malformed_card, verify=False, require_signature=False)

    malformed_identity = {"cards": [{"id": "bad", "provider": [], "model": "x", "rates": {}}]}
    with pytest.raises(CatalogError, match="provider must be"):
        PricingCatalog.from_dict(malformed_identity, verify=False, require_signature=False)
    for malformed_field in (
        {"aliases": "alias"},
        {"source_urls": "https://example.test"},
        {"unmetered": "false"},
    ):
        card = {"id": "bad", "provider": "x", "model": "x", "rates": {}, **malformed_field}
        with pytest.raises(CatalogError, match="invalid pricing rate card"):
            PricingCatalog.from_dict({"cards": [card]}, verify=False, require_signature=False)
