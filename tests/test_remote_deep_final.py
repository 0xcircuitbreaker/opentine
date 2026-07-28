"""Final remote resource-bound and storage-integrity regressions."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from opentine.kernel import ObjectEnvelope
from opentine.remote import _tenant_repo
from opentine.remote._object_file import MAX_ENCRYPTED_OBJECT_BYTES
from opentine.remote._tenant_repo import validate_ref_listing
from opentine.remote._uploads import UploadRegistry
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend, valid_ref
from opentine.remote.security import LocalKeyProvider


def _annotation(run: ObjectEnvelope, value: str = "ok") -> ObjectEnvelope:
    return ObjectEnvelope.create(
        "annotation", {"previous_id": None, "target_id": run.oid, "value": value}
    )


def test_ref_annotation_size_is_prechecked_and_aggregated(monkeypatch):
    runs = [
        ObjectEnvelope.create(
            "run", {"events": [], "manifests": {}, "roots": [], "tips": [], "index": index}
        )
        for index in range(2)
    ]
    annotations = [_annotation(run, "x" * 32) for run in runs]
    values = {item.oid: item.encode() for item in annotations}

    class Store:
        reads = 0

        def has(self, _tenant, oid):
            return oid in values

        def size(self, _tenant, oid):
            return len(values[oid])

        def get(self, _tenant, oid):
            self.reads += 1
            return values[oid]

    refs = {
        f"annotations/{run.oid.rsplit(':', 1)[1]}": annotation.oid
        for run, annotation in zip(runs, annotations)
    }
    store = Store()
    monkeypatch.setattr(_tenant_repo, "MAX_REF_ANNOTATION_BYTES", 1_000)
    monkeypatch.setattr(
        _tenant_repo,
        "MAX_REF_ANNOTATION_TOTAL_BYTES",
        len(values[annotations[0].oid]) + len(values[annotations[1].oid]) - 1,
    )
    with pytest.raises(ValueError, match="byte limit"):
        validate_ref_listing("acme", store, object(), refs)
    assert store.reads == 1

    store.reads = 0
    monkeypatch.setattr(_tenant_repo, "MAX_REF_ANNOTATION_BYTES", 1)
    with pytest.raises(ValueError, match="byte limit"):
        validate_ref_listing("acme", store, object(), refs)
    assert store.reads == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX link behavior differs on Windows")
def test_filesystem_object_store_rejects_linked_and_oversized_leaves(tmp_path: Path):
    store = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    envelope = ObjectEnvelope.create("blob", b"safe")
    store.put("acme", envelope.oid, envelope.encode())
    path = store._path("acme", envelope.oid)

    os.link(path, tmp_path / "second-link")
    assert store.has("acme", envelope.oid) is False
    with pytest.raises(ValueError, match="single-link regular"):
        store.get("acme", envelope.oid)
    (tmp_path / "second-link").unlink()

    path.unlink()
    outside = tmp_path / "outside"
    outside.write_bytes(b"not ciphertext")
    path.symlink_to(outside)
    assert store.has("acme", envelope.oid) is False
    with pytest.raises(ValueError, match="regular"):
        store.get("acme", envelope.oid)

    path.unlink()
    with path.open("wb") as handle:
        handle.truncate(MAX_ENCRYPTED_OBJECT_BYTES + 1)
    with pytest.raises(ValueError, match="size limit"):
        store.get("acme", envelope.oid)


@pytest.mark.parametrize(
    "name",
    ("heads/Main", "heads/a..b", "heads/con", "tags/trailing.", "heads/name.LOCK"),
)
def test_remote_ref_validation_matches_local_portable_rules(tmp_path: Path, name: str):
    with pytest.raises(ValueError, match="invalid ref name"):
        valid_ref(name)
    backend = SQLiteBackend(tmp_path / "refs.sqlite3", audit_key=b"a" * 32)
    with pytest.raises(ValueError, match="invalid ref name"):
        backend.update_ref("acme", name, "run:sha256:" + "1" * 64, None)


def test_upload_reaper_rechecks_active_state_before_deleting(tmp_path: Path, monkeypatch):
    registry = UploadRegistry(
        tmp_path / "uploads",
        LocalKeyProvider(b"u" * 32),
        ttl_seconds=0.001,
        max_pending=4,
    )
    upload_id = "a" * 32
    part, metadata = registry.create("acme", upload_id, {"sha256": "0" * 64, "size": 1})
    for path in (part, metadata):
        os.utime(path, (0, 0))

    reached_scan = threading.Event()
    resume_scan = threading.Event()
    original = Path.stat

    def paused_stat(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == metadata and not reached_scan.is_set():
            reached_scan.set()
            assert resume_scan.wait(5)
        return result

    monkeypatch.setattr(Path, "stat", paused_stat)
    worker = threading.Thread(target=lambda: registry.reap(force=True))
    worker.start()
    assert reached_scan.wait(5)
    with registry.locked("acme", upload_id):
        resume_scan.set()
        worker.join(5)
        assert not worker.is_alive()
        assert part.exists() and metadata.exists()
