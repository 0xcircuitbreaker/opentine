"""Negotiation behavior for large and intentionally filtered repositories."""

from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from opentine.kernel import KernelError, ObjectEnvelope
from opentine.remote.backend import FilesystemObjectStore
from opentine.remote.security import LocalKeyProvider
from opentine.repository import Repo
from opentine.repository import client as repository_client
from opentine.repository.pack import MAX_PACK_OBJECTS, create_pack, inspect_pack, reachable


class _Repo:
    def __init__(self, *, target_present: bool = True):
        self.target_present = target_present
        self.updated: list[tuple[str, str]] = []
        self.iter_args: list[tuple[int | None, bool]] = []

    def iter_oids(self, *, limit: int | None = None, truncate: bool = False) -> list[str]:
        self.iter_args.append((limit, truncate))
        count = limit if truncate and limit is not None else MAX_PACK_OBJECTS + 1
        return [f"blob:sha256:{index:064x}" for index in range(count)]

    def import_pack(self, data: bytes):
        return SimpleNamespace(objects=(), pack_id="sha256:" + "2" * 64)

    def has(self, oid: str) -> bool:
        return self.target_present

    def read_ref(self, name: str):
        return None

    def update_ref(self, name: str, oid: str, *, expected_old=None):
        self.updated.append((name, oid))


def test_fetch_caps_haves_and_avoids_dangling_filtered_ref(monkeypatch):
    remote_run = "run:sha256:" + "1" * 64
    captured: dict = {}

    def request_json(client, method, url, **kwargs):
        if url.endswith("/capabilities"):
            return 200, {"object_format": "opentine-v3"}
        return 200, {"refs": {"heads/main": remote_run}}

    def request_pack(client, method, url, **kwargs):
        captured.update(kwargs["json"])
        return b"filtered-pack"

    monkeypatch.setattr(repository_client, "_client", lambda *args, **kwargs: nullcontext(object()))
    monkeypatch.setattr(repository_client, "_request_json", request_json)
    monkeypatch.setattr(repository_client, "_request_pack", request_pack)

    repo = _Repo(target_present=False)
    repository_client.fetch(
        repo,
        "https://remote.example",
        tenant="acme",
        token="secret",
        object_types={"blob"},
    )

    assert len(captured["haves"]) == MAX_PACK_OBJECTS
    assert repo.iter_args == [(MAX_PACK_OBJECTS, True)]
    assert repo.updated == []


def test_reachable_indexes_chained_annotations_once(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    run = repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})
    target = None
    associated = []
    for index in range(20):
        target = repo.put(
            "annotation",
            {
                "previous_id": target,
                "target_id": run,
                "value": {"index": index},
            },
        )
        associated.append(target)

    original = repo.iter_oids
    calls = 0

    def counted(*, limit=None, truncate=False):
        nonlocal calls
        calls += 1
        assert (limit, truncate) == (MAX_PACK_OBJECTS, False)
        return original(limit=limit, truncate=truncate)

    monkeypatch.setattr(repo, "iter_oids", counted)
    selected = reachable(repo, [run])
    assert set(associated) <= set(selected)
    assert calls == 0


def test_reachable_and_default_pack_fail_closed_at_protocol_cap(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    run = repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})
    calls = []

    def excessive(*, limit=None, truncate=False):
        calls.append((limit, truncate))
        raise ValueError("repository object listing exceeds search limit")

    monkeypatch.setattr(repo, "iter_oids", excessive)
    assert reachable(repo, [run]) == [run]
    with pytest.raises(ValueError, match="object listing"):
        repo.pack()
    assert calls == [(MAX_PACK_OBJECTS, False)]


def test_explicit_empty_pack_does_not_expand_to_the_repository(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    repo.put("blob", b"must not be packed", redact=False)
    monkeypatch.setattr(
        repo,
        "iter_oids",
        lambda **_kwargs: pytest.fail(
            "explicit object selection must not enumerate the repository"
        ),
    )
    pack_id, objects, shallow = inspect_pack(repo.pack([]))
    assert pack_id.startswith("sha256:")
    assert objects == []
    assert shallow == []


def test_reference_remote_object_listing_honors_protocol_limit(tmp_path):
    source = Repo.init(tmp_path / "source")
    first = source.put("blob", b"first", redact=False)
    second = source.put("blob", b"second", redact=False)
    store = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    for oid in (first, second):
        store.put("acme", oid, source.raw(oid))

    with pytest.raises(ValueError, match="object listing"):
        store.list("acme", limit=1)
    truncated = store.list("acme", limit=1, truncate=True)
    assert len(truncated) == 1
    assert truncated[0] in {first, second}


def test_pack_creation_rejects_excessive_shallow_links_before_encoding():
    links = [f"event:sha256:{number:064x}" for number in range(MAX_PACK_OBJECTS + 1)]
    envelope = ObjectEnvelope.create("event", {"causal_ids": [], "parent_ids": links})

    class LinkHeavyRepo:
        def get(self, oid):
            assert oid == envelope.oid
            return envelope

        def raw(self, _oid):
            pytest.fail("oversized shallow graphs must fail before raw object encoding")

    with pytest.raises(KernelError, match="shallow object count"):
        create_pack(LinkHeavyRepo(), [envelope.oid])
