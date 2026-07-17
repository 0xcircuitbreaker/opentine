"""Adversarial bounds for local shallow state and object negotiation."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentine.kernel import KernelError
from opentine.repository import Repo
from opentine.repository import _objects as object_storage
from opentine.repository import _shallow as shallow_storage
from opentine.repository import store as store_module
from opentine.repository.pack import create_pack


def _oid(number: int, object_type: str = "blob") -> str:
    return f"{object_type}:sha256:{number:064x}"


def test_shallow_state_is_validated_and_globally_bounded(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    path = repo.path / "shallow"
    path.write_text("not-an-object-id\n", encoding="ascii")
    with pytest.raises(KernelError, match="invalid typed object id"):
        repo.shallow_oids()

    path.write_text(f"{_oid(1)}\n{_oid(1)}\n", encoding="ascii")
    with pytest.raises(KernelError, match="duplicate"):
        repo.shallow_oids()

    path.write_text(f"{_oid(1)}\n{_oid(2)}\n", encoding="ascii")
    monkeypatch.setattr(shallow_storage, "MAX_SHALLOW_OBJECTS", 1)
    with pytest.raises(KernelError, match="object limit"):
        repo.shallow_oids()

    monkeypatch.setattr(shallow_storage, "MAX_SHALLOW_OBJECTS", 10)
    monkeypatch.setattr(shallow_storage, "MAX_SHALLOW_BYTES", len(_oid(1)) + 1)
    with pytest.raises(KernelError, match="byte limit"):
        repo.shallow_oids()


def test_shallow_membership_is_cached_and_pack_install_invalidates(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "destination")
    boundary = _oid(7)
    (repo.path / "shallow").write_bytes(shallow_storage.encode_shallow([boundary]))
    reads = 0
    original = store_module.read_shallow

    def counted(path: Path):
        nonlocal reads
        reads += 1
        return original(path)

    monkeypatch.setattr(store_module, "read_shallow", counted)
    assert all(repo._link_exists(boundary) for _ in range(100))
    assert repo.shallow_oids() == {boundary}
    assert reads == 1

    source = Repo.init(tmp_path / "source")
    repo.import_pack(source.pack())
    assert repo.shallow_oids() == {boundary}
    assert reads == 2


@pytest.mark.parametrize("limit_kind", ["objects", "bytes"])
def test_pack_rejects_shallow_union_before_install(tmp_path, monkeypatch, limit_kind):
    destination = Repo.init(tmp_path / "destination")
    existing = _oid(100)
    existing_body = shallow_storage.encode_shallow([existing])
    (destination.path / "shallow").write_bytes(existing_body)

    source = Repo.init(tmp_path / "source")
    blob = source.put("blob", b"boundary", redact=False)
    event = source.put(
        "event",
        {"causal_ids": [], "input_blob": blob, "parent_ids": []},
    )
    packed = create_pack(source, [event])
    if limit_kind == "objects":
        monkeypatch.setattr(shallow_storage, "MAX_SHALLOW_OBJECTS", 1)
    else:
        monkeypatch.setattr(shallow_storage, "MAX_SHALLOW_BYTES", len(existing_body))

    with pytest.raises(KernelError, match=f"{limit_kind[:-1]} limit"):
        destination.import_pack(packed)
    assert not destination.has(event)
    assert list((destination.path / "packs").iterdir()) == []
    assert (destination.path / "shallow").read_bytes() == existing_body


def test_limited_object_enumeration_stops_before_full_walk(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    for number in range(20):
        repo.put("blob", f"object-{number}".encode(), redact=False)
    original = object_storage._suffixes
    yielded = 0

    def counted(directory: Path):
        nonlocal yielded
        for suffix in original(directory):
            yielded += 1
            yield suffix

    monkeypatch.setattr(object_storage, "_suffixes", counted)
    with pytest.raises(ValueError, match="object listing"):
        repo.iter_oids(limit=3)
    assert yielded == 4

    yielded = 0
    subset = repo.iter_oids(limit=3, truncate=True)
    assert len(subset) == 3
    assert subset == sorted(subset)
    assert yielded == 3

    yielded = 0

    def corrupt_entries(_directory: Path):
        nonlocal yielded
        while True:
            yielded += 1
            yield "z" * 62

    monkeypatch.setattr(object_storage, "_suffixes", corrupt_entries)
    assert repo.iter_oids(limit=5, truncate=True) == []
    assert yielded == 5
