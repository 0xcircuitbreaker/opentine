"""Golden identity, migration, pack, and integrity gates for v3 repositories."""

from __future__ import annotations

import json
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine.kernel import KernelError, ObjectEnvelope, canonical_json
from opentine.repository import Repo
from opentine.repository.pack import MAGIC, create_pack, reachable

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
    with pytest.raises(KernelError, match="malformed object JSON"):
        ObjectEnvelope.decode(b'{"encoding":"json","schema":1,"type":"event"}\n\xff')
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


def test_run_graph_structure_rejects_duplicates_external_parents_and_false_tips(
    tmp_path: Path,
):
    repo = Repo.init(tmp_path)
    first = repo.put("event", {"causal_ids": [], "parent_ids": []})
    second = repo.put("event", {"causal_ids": [], "parent_ids": [first]})
    with pytest.raises(KernelError, match="unique event ids"):
        repo.put(
            "run",
            {"events": [first, first], "manifests": {}, "roots": [first], "tips": [first]},
        )
    with pytest.raises(KernelError, match="parent outside"):
        repo.put(
            "run",
            {"events": [second], "manifests": {}, "roots": [second], "tips": [second]},
        )
    with pytest.raises(KernelError, match="leaves"):
        repo.put(
            "run",
            {
                "events": [first, second],
                "manifests": {},
                "roots": [first],
                "tips": [first],
            },
        )
    with pytest.raises(KernelError, match="parent-before-child"):
        repo.put(
            "run",
            {
                "events": [second, first],
                "manifests": {},
                "roots": [first],
                "tips": [second],
            },
        )
    with pytest.raises(KernelError, match="legacy_refs"):
        repo.put(
            "run",
            {
                "events": [first],
                "legacy_refs": {"bad": []},
                "manifests": {},
                "roots": [first],
                "tips": [first],
            },
        )


@pytest.mark.parametrize("field,value", [("cost", -1), ("duration", "NaN"), ("cost", True)])
def test_event_metrics_are_finite_and_nonnegative(tmp_path: Path, field: str, value):
    repo = Repo.init(tmp_path)
    with pytest.raises(KernelError, match=f"event {field}"):
        repo.put("event", {"causal_ids": [], "parent_ids": [], field: value})
    with pytest.raises(KernelError, match="event usage.input"):
        repo.put(
            "event",
            {"causal_ids": [], "parent_ids": [], "usage": {"input": value}},
        )


@pytest.mark.parametrize("value", [1.5, float(2**53)])
def test_event_core_token_usage_requires_safe_integers(tmp_path: Path, value):
    repo = Repo.init(tmp_path)
    with pytest.raises(KernelError, match="safe integer token count"):
        repo.put("event", {"causal_ids": [], "parent_ids": [], "usage": {"input": value}})
    event = repo.put("event", {"causal_ids": [], "parent_ids": [], "usage": {"eval_seconds": 1.5}})
    assert repo.get(event).payload()["usage"]["eval_seconds"] == 1.5


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
    shallow.import_pack(create_pack(source, source.iter_oids()))
    assert first not in shallow.shallow_oids()
    assert shallow.fsck().ok

    replacement = source.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})
    with pytest.raises(ValueError, match="concurrent ref update"):
        source.update_ref("heads/main", replacement, expected_old=None)


def test_valid_pack_reimport_rejects_corrupt_existing_object_and_pack(tmp_path: Path):
    source = Repo.init(tmp_path / "source-reimport")
    oid = source.put("blob", b"verified", redact=False)
    packed = source.pack()
    destination = Repo.init(tmp_path / "destination-reimport")
    object_path = destination._object_path(oid)
    object_path.parent.mkdir(parents=True, exist_ok=True)
    object_path.write_bytes(b"corrupt")
    with pytest.raises(KernelError, match="existing object"):
        destination.import_pack(packed)

    object_path.write_bytes(source.raw(oid))
    result = destination.import_pack(packed)
    pack_path = destination.path / "packs" / f"{result.pack_id[7:]}.pack"
    body = zlib.decompress(packed[len(MAGIC) + 32 :])
    alternate = packed[: len(MAGIC) + 32] + zlib.compress(body, 1)
    assert destination.import_pack(alternate).pack_id == result.pack_id
    pack_path.write_bytes(b"corrupt")
    with pytest.raises(KernelError, match="existing pack"):
        destination.import_pack(packed)


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
    with pytest.raises(KernelError, match="object id mismatch"):
        repo.update_ref("tags/corrupt", blob, expected_old=None)

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


def test_compatibility_wrapper_preserves_branches_and_v3_identity(tmp_path: Path):
    repo = Repo.init(tmp_path)
    source = Run(id="branched")
    root = source.add_step(StepKind.model, {"text": "root"}, tool_info={"v3_kind": "user-owned"})
    left = source.add_step(StepKind.done, {"text": "left"}, parent_id=root.id, ref="left")
    right = source.add_step(StepKind.done, {"text": "right"}, parent_id=root.id, ref="right")

    stored = repo.put_run(source, ref="heads/main")
    payload = repo.get(stored.run_id).payload()
    assert set(payload["tips"]) == {stored.event_map[left.id], stored.event_map[right.id]}
    assert payload["legacy_refs"]["main"] == stored.event_map[root.id]

    loaded = repo.load_run(stored.run_id)
    assert loaded.refs == payload["legacy_refs"]
    assert loaded.steps[0].tool_info["v3_kind"] == "user-owned"
    assert loaded.steps[0].v3_kind == StepKind.model.value
    restored = repo.put_run(loaded)
    assert restored.run_id == stored.run_id
    forked = repo.fork(stored.run_id, stored.event_map[left.id])
    fork_payload = repo.get(forked).payload()
    assert set(fork_payload["legacy_refs"].values()) <= set(fork_payload["events"])
    assert repo.fsck().ok


def test_compatibility_wrapper_preserves_resume_state_and_identity(tmp_path: Path):
    repo = Repo.init(tmp_path)
    source = Run(
        id="resumable",
        model_info="anthropic/claude-sonnet-5",
        transcript=[
            {"role": "user", "content": "Use the tool."},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"id": "call_1", "name": "lookup", "arguments": {}}],
                "anthropic_content": [
                    {"type": "thinking", "thinking": "plan", "signature": "signed-state"},
                    {"type": "tool_use", "id": "call_1", "name": "lookup", "input": {}},
                ],
            },
        ],
        manifest={"model": {"name": "anthropic/claude-sonnet-5"}},
        policies={"strict_cost": True},
        cache={"model:1": {"kind": "model.complete", "response": {"text": ""}}},
    )
    source_step = source.add_step(StepKind.model, {"text": "stored"}, model_info=source.model_info)
    source.transcript[-1]["step_id"] = source_step.id

    stored = repo.put_run(source)
    loaded = repo.load_run(stored.run_id)

    assert loaded.transcript[:-1] == source.transcript[:-1]
    assert loaded.transcript[-1] == {
        **source.transcript[-1],
        "step_id": stored.event_map[source_step.id],
    }
    assert loaded.cache == source.cache
    assert loaded.manifest == source.manifest
    assert loaded.policies == source.policies
    assert loaded.model_info == source.model_info
    assert repo.put_run(loaded).run_id == stored.run_id
    assert repo.fsck().ok


def test_compatibility_annotations_have_atomic_heads_and_support_clearing(tmp_path: Path):
    repo = Repo.init(tmp_path)
    source = Run(id="annotated", metadata={"note": "old"}, tags=["accepted"])
    source.add_step(StepKind.done, {"text": "stored"})

    first = repo.put_run(source)
    assert first.annotation_id
    source.metadata = {"note": "new"}
    source.tags = []
    second = repo.put_run(source)
    assert second.run_id == first.run_id and second.annotation_id != first.annotation_id
    assert repo.get(second.annotation_id).payload()["previous_id"] == first.annotation_id
    assert repo.load_run(second.run_id).metadata == {"note": "new"}
    assert repo.load_run(second.run_id).tags == []

    source.metadata = {}
    cleared = repo.put_run(source)
    assert cleared.run_id == first.run_id
    loaded = repo.load_run(cleared.run_id)
    assert loaded.metadata == {} and loaded.tags == []
    unchanged = repo.put_run(loaded)
    assert unchanged.annotation_id == cleared.annotation_id
    assert repo.fsck().ok


def test_cloned_annotation_chain_is_adopted_before_metadata_update(tmp_path: Path):
    origin = Repo.init(tmp_path / "origin")
    source = Run(id="annotated", metadata={"note": "old"})
    source.add_step(StepKind.done, {"text": "stored"})
    first = origin.put_run(source)

    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(origin.pack())
    loaded = clone.load_run(first.run_id)
    loaded.metadata = {"note": "new"}
    second = clone.put_run(loaded)

    assert clone.get(second.annotation_id).payload()["previous_id"] == first.annotation_id
    assert clone.load_run(first.run_id).metadata == {"note": "new"}


def test_annotation_ref_name_is_bound_to_target_run(tmp_path: Path):
    repo = Repo.init(tmp_path)
    first = repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})
    second = repo.put(
        "run", {"events": [], "manifests": {}, "roots": [], "tips": [], "status": "running"}
    )
    annotation = repo.put("annotation", {"previous_id": None, "target_id": second, "value": {}})
    digest = first.rsplit(":", 1)[-1]
    with pytest.raises(ValueError, match="match its target run"):
        repo.update_ref(f"annotations/{digest}", annotation, expected_old=None)


def test_repo_fork_slices_transcript_cache_and_pricing_state(tmp_path: Path):
    repo = Repo.init(tmp_path)
    source = Run(
        id="future-state",
        model_info="model-a",
        cache={"future-secret": {"kind": "model.complete", "value": "future"}},
    )
    first = source.add_step(StepKind.done, {"text": "first"}, model_info="model-a")
    second = source.add_step(StepKind.done, {"text": "future"}, model_info="model-b")
    source.transcript = [
        {"role": "user", "content": "start"},
        {"step_id": first.id, "role": "assistant", "content": "first"},
        {"role": "user", "content": "future prompt"},
        {"step_id": second.id, "role": "assistant", "content": "future"},
    ]
    source.manifest["pricing"] = {
        "complete": True,
        "invocations": [
            {"status": "complete", "step_id": first.id},
            {"status": "complete", "step_id": second.id},
        ],
        "rate_cards": {first.id: "first-card", second.id: "future-card"},
    }
    stored = repo.put_run(source)
    forked = repo.fork(stored.run_id, stored.event_map[first.id])
    loaded = repo.load_run(forked)

    assert len(loaded.steps) == 1
    assert [item["content"] for item in loaded.transcript] == ["start", "first"]
    assert loaded.cache == {}
    assert loaded.model_info == "model-a"
    assert loaded.manifest["pricing"]["invocations"] == [
        {"status": "complete", "step_id": stored.event_map[first.id]}
    ]
    assert stored.event_map[second.id] not in reachable(repo, [forked])


def test_compatibility_roundtrip_preserves_authenticated_event_extensions(tmp_path: Path):
    repo = Repo.init(tmp_path)
    source = Run(id="extended")
    step = source.add_step(StepKind.done, {"text": "stored"})
    stored = repo.put_run(source)
    original_event = repo.get(stored.event_map[step.id]).payload()
    artifact = repo.put("blob", b"artifact", redact=False)
    extended = repo.put(
        "event",
        {
            **original_event,
            "artifact_blob": artifact,
            "attributes": {"framework": "real"},
            "span_id": "span-1",
            "trace_id": "trace-1",
        },
    )
    run_payload = repo.get(stored.run_id).payload()
    extended_run = repo.put(
        "run",
        {
            **run_payload,
            "events": [extended],
            "legacy_refs": {"main": extended},
            "roots": [extended],
            "tips": [extended],
        },
    )

    restored = repo.put_run(repo.load_run(extended_run))
    assert restored.event_map[extended] == extended
    assert repo.get(extended).payload()["artifact_blob"] == artifact
    assert repo.get(extended).payload()["attributes"] == {"framework": "real"}
