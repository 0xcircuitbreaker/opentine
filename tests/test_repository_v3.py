"""Golden identity, migration, pack, and integrity gates for v3 repositories."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine.kernel import KernelError, ObjectEnvelope, canonical_json
from opentine.repository import Repo
from opentine.repository.pack import create_pack, reachable

FIXTURES = Path(__file__).parent / "fixtures"


def test_rfc8785_and_cross_process_object_id_vector():
    value = {"numbers": [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27]}
    assert canonical_json(value) == (b'{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}')
    # Integers beyond the exactly representable range (2**53-1) are rejected rather than
    # silently coerced to a float, which would collide distinct values onto one object id.
    with pytest.raises(KernelError, match="2\\*\\*53"):
        canonical_json(9_223_372_036_854_775_807)
    with pytest.raises(KernelError, match="2\\*\\*53"):
        canonical_json(10**400)
    payload = {"b": 1, "a": "x"}
    expected = "annotation:sha256:92adcc2f0178432f0f4d7200df2465f30009cccd94e5c87df6068c55d49ddffc"
    assert ObjectEnvelope.create("annotation", payload).oid == expected
    script = (
        "from opentine.kernel import ObjectEnvelope; "
        "print(ObjectEnvelope.create('annotation', {'b': 1, 'a': 'x'}).oid)"
    )
    assert subprocess.check_output([sys.executable, "-c", script], text=True).strip() == expected


def test_redaction_precedes_hashing_and_objects_deduplicate(tmp_path: Path):
    repo = Repo.init(tmp_path)
    target = repo.put("blob", b"target", redact=False)
    secret = repo.put(
        "annotation",
        {"target_id": target, "value": {"api_key": "top-secret", "input_tokens": 17}},
    )
    redacted = repo.put(
        "annotation",
        {"target_id": target, "value": {"api_key": "[REDACTED]", "input_tokens": 17}},
        redact=False,
    )
    assert secret == redacted
    assert repo.get(secret).payload()["value"] == {
        "api_key": "[REDACTED]",
        "input_tokens": 17,
    }
    assert repo.put("blob", b"target", redact=False) == target
    assert len(repo.iter_oids()) == 2

    json_secret = repo.put("blob", b'{"api_key":"secret","input_tokens":7}')
    json_redacted = repo.put("blob", b'{"api_key":"[REDACTED]","input_tokens":7}', redact=False)
    assert json_secret == json_redacted
    assert b'"input_tokens":7' in repo.get(json_secret).body


def test_typed_parent_manifest_and_annotation_links_are_enforced(tmp_path: Path):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"value", redact=False)
    with pytest.raises(KernelError, match="parent_ids must contain event ids"):
        repo.put("event", {"causal_ids": [], "parent_ids": [blob]})
    event = repo.put("event", {"causal_ids": [], "parent_ids": []})
    with pytest.raises(KernelError, match="tips must be a subset"):
        repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": [event]})
    with pytest.raises(KernelError, match="previous_id must contain an annotation"):
        repo.put("annotation", {"previous_id": blob, "target_id": blob, "value": {}})


def _chain(repo: Repo) -> tuple[str, str, str]:
    blob = repo.put("blob", b"payload", redact=False)
    first = repo.put(
        "event",
        {"causal_ids": [], "input_blob": blob, "output_blob": blob, "parent_ids": []},
    )
    second = repo.put(
        "event",
        {"causal_ids": [], "input_blob": blob, "output_blob": blob, "parent_ids": [first]},
    )
    run = repo.put(
        "run",
        {"events": [first, second], "manifests": {}, "roots": [first], "tips": [second]},
    )
    return first, second, run


def test_pack_round_trip_shallow_boundary_and_cas(tmp_path: Path):
    source = Repo.init(tmp_path / "source")
    first, _, run = _chain(source)
    source.update_ref("heads/main", run, expected_old=None)

    full = Repo.init(tmp_path / "full")
    full.import_pack(source.pack())
    assert full.fsck().ok
    assert set(full.iter_oids()) == set(source.iter_oids())

    selection = reachable(source, [run], depth=1)
    shallow = Repo.init(tmp_path / "shallow")
    shallow.import_pack(create_pack(source, selection))
    assert first not in shallow.iter_oids()
    assert first in shallow.shallow_oids()
    assert shallow.fsck().ok

    replacement = source.put("blob", b"replacement", redact=False)
    with pytest.raises(ValueError, match="concurrent ref update"):
        source.update_ref("heads/main", replacement, expected_old=None)


def test_deep_fsck_detects_corruption(tmp_path: Path):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"uncorrupted", redact=False)
    path = repo._object_path(blob)
    path.write_bytes(repo.raw(blob) + b"corruption")
    result = repo.fsck()
    assert not result.ok
    assert any("object id mismatch" in error for error in result.errors)
    with pytest.raises(KernelError, match="object id mismatch"):
        repo.get(blob)

    event_repo = Repo.init(tmp_path / "events")
    first, _, _ = _chain(event_repo)
    event_path = event_repo._object_path(first)
    event_path.write_bytes(event_repo.raw(first) + b"corruption")
    event_result = event_repo.fsck()
    assert not event_result.ok
    assert any(first in error for error in event_result.errors)


def test_malformed_envelopes_fail_with_kernel_errors():
    with pytest.raises(KernelError, match="header"):
        ObjectEnvelope.decode(b"[]\n{}")
    with pytest.raises(KernelError, match="schema"):
        ObjectEnvelope.decode(b'{"encoding":"json","schema":true,"type":"run"}\n{}')


def test_v2_migration_preserves_legacy_scope_and_deterministic_map(tmp_path: Path):
    source = FIXTURES / "golden_signed_v2.tine"
    repo = Repo.init(tmp_path)
    migrated = repo.migrate_v2(
        source,
        ref="heads/migrated",
        hmac_key=b"golden-tine-signing-key-01234567",
    )
    payload = repo.get(migrated.run_id).payload()
    assert repo.get(payload["legacy_blob"]).body == source.read_bytes()
    assert payload["signature_scope"] == "legacy_blob_only"
    assert payload["legacy_verification"]["integrity"]["ok"] is True
    assert payload["legacy_verification"]["signature"]["ok"] is True
    mapping = json.loads(repo.get(payload["migration_map_blob"]).body)
    assert mapping == migrated.event_map
    assert repo.read_ref("heads/migrated") == migrated.run_id
    assert repo.fsck().ok


def test_run_save_load_compatibility_wrapper_accepts_worktree(tmp_path: Path):
    Repo.init(tmp_path)
    source = Run(id="compat", user_prompt="hello", tags=["accepted"])
    source.metadata["note"] = "round trip"
    source.add_step(StepKind.done, {"text": "stored"}, usage={"input": 1})
    assert source.save(tmp_path) == tmp_path
    loaded = Run.load(tmp_path)
    assert loaded.id == "compat"
    assert loaded.steps[0].inputs == {"text": "stored"}
    assert loaded.tags == ["accepted"] and loaded.metadata["note"] == "round trip"
    assert Repo.open(tmp_path).fsck().ok
