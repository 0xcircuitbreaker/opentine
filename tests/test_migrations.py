"""Format migration + atomic-write coverage (v1 -> v2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine._canon import FORMAT_VERSION, _integrity_digest, atomic_write_text
from opentine.migrations import MigrationError, migrate_dict

FIXTURES = Path(__file__).parent / "fixtures"


def _golden_v1_raw() -> dict:
    return json.loads((FIXTURES / "golden_v1.tine").read_text(encoding="utf-8"))


# --- migrate_dict -----------------------------------------------------------


def test_migrate_v1_to_v2_is_additive_and_preserves_step_ids():
    raw = _golden_v1_raw()
    migrated = migrate_dict(raw, FORMAT_VERSION)

    assert migrated["format_version"] == 2
    # input is not mutated (pure function)
    assert raw["format_version"] == 1
    # step ids are unchanged — content addressing is stable across migration
    assert set(migrated["graph"]["steps"]) == set(raw["graph"]["steps"])
    assert migrated["graph"]["order"] == raw["graph"]["order"]
    # migration breadcrumb recorded
    chain = migrated["metadata"]["migration"]
    assert chain[-1]["from"] == 1 and chain[-1]["to"] == 2
    # digest recomputed over the v2 body and self-consistent
    assert migrated["metadata"]["integrity"]["digest"] == _integrity_digest(migrated)
    assert Run.verify_integrity(migrated).ok


def test_migrate_dict_noop_when_already_current():
    raw = json.loads((FIXTURES / "golden_v2.tine").read_text(encoding="utf-8"))
    migrated = migrate_dict(raw, FORMAT_VERSION)
    assert migrated == raw  # deep-copied, structurally identical


def test_migrate_dict_rejects_downgrade():
    raw = json.loads((FIXTURES / "golden_v2.tine").read_text(encoding="utf-8"))
    with pytest.raises(MigrationError):
        migrate_dict(raw, 1)


def test_migrate_dict_rejects_missing_and_future():
    with pytest.raises(MigrationError):
        migrate_dict({"run_id": "x"}, FORMAT_VERSION)  # missing format_version
    with pytest.raises(MigrationError):
        migrate_dict({"format_version": 99}, FORMAT_VERSION)  # newer than supported


def test_migrate_drops_stray_signature_and_rewrites_digest():
    raw = _golden_v1_raw()
    raw["metadata"]["integrity"]["signature"] = {"scheme": "tine-sig/1", "value": "deadbeef"}
    migrated = migrate_dict(raw, FORMAT_VERSION)
    assert "signature" not in migrated["metadata"]["integrity"]


# --- Run.load auto-migration ------------------------------------------------


def test_load_auto_migrates_v1_in_memory_without_rewriting_file(tmp_path: Path):
    src = tmp_path / "v1.tine"
    src.write_text((FIXTURES / "golden_v1.tine").read_text(encoding="utf-8"), encoding="utf-8")

    run = Run.load(src)
    assert run.format_version == FORMAT_VERSION  # migrated in memory
    # the on-disk file is untouched by load
    on_disk = json.loads(src.read_text(encoding="utf-8"))
    assert on_disk["format_version"] == 1


def test_v1_verifies_under_v1_then_resave_upgrades(tmp_path: Path):
    src = FIXTURES / "golden_v1.tine"
    # v1 still verifies under its own version (verify never migrates)
    assert Run.verify_integrity(src).ok

    run = Run.load(src)
    out = tmp_path / "out.tine"
    run.save(out)
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["format_version"] == 2
    assert Run.verify_integrity(out).ok
    # step ids preserved end to end
    assert set(saved["graph"]["steps"]) == set(json.loads(src.read_text())["graph"]["steps"])


def test_golden_v2_native_roundtrip(tmp_path: Path):
    src = FIXTURES / "golden_v2.tine"
    assert Run.verify_integrity(src).ok
    run = Run.load(src)
    assert run.id == "golden-v2"
    assert [s.kind for s in run.steps] == [StepKind.think, StepKind.tool, StepKind.done]
    out = tmp_path / "rt.tine"
    run.save(out)
    assert Run.verify_integrity(out).ok


# --- atomic write -----------------------------------------------------------


def test_atomic_write_leaves_no_temp_and_is_byte_exact(tmp_path: Path):
    target = tmp_path / "a.tine"
    atomic_write_text(target, "hello\nworld")
    assert target.read_text(encoding="utf-8") == "hello\nworld"
    # no leftover temp files in the directory
    assert [p.name for p in tmp_path.iterdir()] == ["a.tine"]


def test_atomic_write_preserves_original_on_replace_failure(tmp_path: Path, monkeypatch):
    target = tmp_path / "a.tine"
    target.write_text("ORIGINAL", encoding="utf-8")

    import opentine._canon as canon

    def boom(src, dst):
        raise OSError("simulated crash during replace")

    monkeypatch.setattr(canon.os, "replace", boom)
    with pytest.raises(OSError):
        atomic_write_text(target, "NEW CONTENT")

    # original is intact and no temp file is left behind
    assert target.read_text(encoding="utf-8") == "ORIGINAL"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tine"]
