"""Final bounded-enumeration and durable-ref regressions for v0.3.0."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from opentine.kernel import KernelError, ObjectEnvelope
from opentine.repository import Repo, _associations, _objects, _ref_store
from opentine.repository._associations import associated_map
from opentine.repository._migration_preflight import _MemoryRepo
from opentine.repository._semantic_view import SemanticView


def _run(repo: Repo, label: str = "run") -> str:
    return repo.put(
        "run",
        {"events": [], "label": label, "manifests": {}, "roots": [], "tips": []},
    )


def test_association_enumeration_has_a_hard_scan_limit(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    run = _run(repo)
    repo.put("annotation", {"target_id": run, "value": {"index": 1}})
    repo.put("annotation", {"target_id": run, "value": {"index": 2}})
    monkeypatch.setattr(_associations, "MAX_ASSOCIATION_SCAN", 1)

    with pytest.raises(ValueError, match="typed object scan exceeds"):
        associated_map(repo, [run], limit=10)


def test_semantic_diff_validates_only_matching_attestation_claims(tmp_path):
    repo = Repo.init(tmp_path)
    target = _run(repo, "target")
    unrelated = _run(repo, "unrelated")
    repo.put("attestation", {"claim": "unrelated-malformed", "target_id": unrelated})
    valid = repo.attest(
        target,
        {"kind": "evaluation", "scores": {"quality": 1}},
        signer="test",
    )

    result = repo.diff(target, target)
    assert result.summary["evaluations"]["left"] == [
        {"attestation": valid, "scores": {"quality": 1}}
    ]

    repo.put("attestation", {"claim": "matching-malformed", "target_id": target})
    with pytest.raises(ValueError, match="attestation claim must be an object"):
        repo.diff(target, target)


def test_semantic_diff_attestation_scan_is_bounded(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    target = _run(repo)
    for index in range(2):
        repo.attest(target, {"kind": "note", "index": index}, signer="test")
    monkeypatch.setattr(_associations, "MAX_ASSOCIATION_SCAN", 1)

    with pytest.raises(ValueError, match="typed object scan exceeds"):
        repo.diff(target, target)


def test_memory_typed_enumeration_does_not_materialize_its_base(monkeypatch):
    touched = False
    oid = "annotation:sha256:" + "1" * 64

    def source(path, object_types, *, limit):
        nonlocal touched
        del path, object_types, limit
        touched = True
        yield oid

    monkeypatch.setattr(_objects, "iter_typed_object_oids", source)
    repo = _MemoryRepo(SimpleNamespace(path=object()))
    values = repo.iter_typed_oids({"annotation"})
    assert not touched
    assert next(values) == oid
    assert touched


def test_semantic_view_checks_encoded_size_before_read_and_can_retry():
    envelope = ObjectEnvelope.create(
        "event",
        {"causal_ids": [], "parent_ids": []},
    )
    stored = envelope.encode()

    class Base:
        def __init__(self):
            self.size_calls = 0
            self.raw_calls = 0

        def has(self, oid):
            return oid == envelope.oid

        def raw_size(self, oid):
            assert oid == envelope.oid
            self.size_calls += 1
            return len(stored) + 1 if self.size_calls == 1 else len(stored)

        def raw(self, oid):
            assert oid == envelope.oid
            self.raw_calls += 1
            return stored

    base = Base()
    view = SemanticView(base, max_source_bytes=len(stored))
    with pytest.raises(KernelError, match="semantic source limit"):
        view.get(envelope.oid)
    assert base.raw_calls == 0
    assert view._source_bytes == 0 and not view._source_seen

    assert view.get(envelope.oid).oid == envelope.oid
    assert base.raw_calls == 1
    assert view._source_bytes == len(stored)


def test_repo_raw_size_uses_the_confined_object_reader(tmp_path):
    repo = Repo.init(tmp_path)
    oid = repo.put("blob", b"payload", redact=False)
    assert repo.raw_size(oid) == len(repo.raw(oid))


def test_log_uses_validated_ref_resolution(tmp_path):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"not a run", redact=False)
    path = repo.path / "refs" / "heads" / "main"
    path.write_text(blob + "\n", encoding="ascii")

    with pytest.raises(ValueError, match="heads refs require run"):
        repo.log("heads/main")


def test_ref_guard_orders_ref_and_reflog_across_writers(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    competing = Repo.open(tmp_path)
    old = repo.put("blob", b"old", redact=False)
    first = repo.put("blob", b"first", redact=False)
    second = repo.put("blob", b"second", redact=False)
    repo.update_ref("tags/main", old)
    entered = threading.Event()
    release = threading.Event()
    original = _ref_store.append_reflog

    def delayed(base, normalized, entry):
        entered.set()
        assert release.wait(5)
        original(base, normalized, entry)

    monkeypatch.setattr(_ref_store, "append_reflog", delayed)
    errors: list[BaseException] = []

    def update():
        try:
            repo.update_ref("tags/main", first, expected_old=old)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    worker = threading.Thread(target=update)
    worker.start()
    assert entered.wait(5)
    assert (repo.path / "refs" / "tags" / "main.lock").exists()
    assert competing.list_refs()["tags/main"] == first
    with pytest.raises(ValueError, match="locked by a concurrent write"):
        competing.update_ref("tags/main", second, expected_old=first)
    release.set()
    worker.join(5)
    assert not worker.is_alive() and not errors

    competing.update_ref("tags/main", second, expected_old=first)
    rows = [
        json.loads(line) for line in (repo.path / "logs" / "tags" / "main").read_text().splitlines()
    ]
    assert [row["new"] for row in rows] == [old, first, second]
    assert not (repo.path / "refs" / "tags" / "main.lock").exists()
    assert not (repo.path / "refs" / "tags" / "main.new.lock").exists()
