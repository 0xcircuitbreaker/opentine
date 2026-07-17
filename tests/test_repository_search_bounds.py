"""Adversarial resource bounds for v3 search and object inspection."""

from __future__ import annotations

import json

import pytest

from opentine.kernel import KernelError
from opentine.repository import Repo
from opentine.repository import _inspect as inspect_module
from opentine.repository import search as search_module


def _completed_run(repo: Repo, blob: str, count: int = 1) -> str:
    events = [
        repo.put(
            "event",
            {
                "causal_ids": [],
                "input_blob": blob,
                "kind": f"model-{index}",
                "output_blob": blob,
                "parent_ids": [],
            },
        )
        for index in range(count)
    ]
    run = repo.put(
        "run",
        {
            "events": events,
            "manifests": {},
            "roots": events,
            "status": "completed",
            "tips": events,
        },
    )
    repo.update_ref("heads/main", run, expected_old=repo.read_ref("heads/main"))
    return run


def test_search_reads_a_repeated_content_address_only_once(monkeypatch, tmp_path):
    repo = Repo.init(tmp_path)
    body = json.dumps({"text": "bounded needle " + "x" * 32_000}).encode()
    blob = repo.put("blob", body, redact=False)
    run = _completed_run(repo, blob, count=250)
    original = search_module.read_verified_blob_prefix
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[1])
        return original(*args, **kwargs)

    monkeypatch.setattr(search_module, "read_verified_blob_prefix", counted)
    results = repo.search("bounded needle")
    assert [result.run_id for result in results] == [run]
    assert calls == [blob]
    assert len(results[0].matched_text) <= 240


def test_search_fails_closed_at_object_and_blob_source_limits(monkeypatch, tmp_path):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b'{"text":"needle in a large body"}', redact=False)
    _completed_run(repo, blob)
    monkeypatch.setattr(search_module, "MAX_SEARCH_OBJECTS", 1)
    with pytest.raises(ValueError, match="object listing"):
        repo.search("needle")

    monkeypatch.setattr(search_module, "MAX_SEARCH_OBJECTS", 100_000)
    monkeypatch.setattr(search_module, "MAX_SEARCH_BLOB_BYTES", 8)
    with pytest.raises(KernelError, match="source-byte limit"):
        repo.search("needle")


def test_search_caps_repeated_event_and_cached_text_work(monkeypatch, tmp_path):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b'{"text":"needle"}', redact=False)
    run = _completed_run(repo, blob, count=2)
    second = repo.put(
        "run",
        {**repo.get(run).payload(), "session_id": "second"},
    )
    repo.update_ref("heads/second", second, expected_old=None)

    raw = repo.raw
    reads = []

    def counted(oid):
        reads.append(oid)
        return raw(oid)

    monkeypatch.setattr(repo, "raw", counted)
    repo.search("")
    for oid in repo.get(run).payload()["events"]:
        assert reads.count(oid) == 1

    monkeypatch.setattr(search_module, "MAX_SEARCH_EVENT_REFERENCES", 3)
    with pytest.raises(ValueError, match="event-reference limit"):
        repo.search("")
    monkeypatch.setattr(search_module, "MAX_SEARCH_EVENT_REFERENCES", 100_000)
    monkeypatch.setattr(search_module, "MAX_SEARCH_TEXT_TOTAL", 20)
    with pytest.raises(ValueError, match="aggregate text limit"):
        repo.search("absent")


def test_search_counts_each_structured_object_once_against_aggregate_budget(monkeypatch, tmp_path):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b'{"text":"needle"}', redact=False)
    _completed_run(repo, blob, count=4)
    event_sizes = [
        search_module.stored_object_size(repo, oid)
        for oid in repo.iter_oids()
        if oid.startswith("event:")
    ]
    monkeypatch.setattr(
        search_module,
        "MAX_SEARCH_STRUCTURED_SOURCE_BYTES",
        sum(event_sizes) - 1,
    )
    with pytest.raises(ValueError, match="structured-source limit"):
        repo.search("")


def test_blob_and_resolved_object_inspection_return_bounded_prefixes(monkeypatch, tmp_path):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"a" * 100, redact=False)
    monkeypatch.setattr(inspect_module, "MAX_INSPECT_BLOB_BYTES", 16)
    inspected = repo.inspect(blob)
    assert inspected["payload"] == {
        "encoding": "utf-8",
        "size_bytes": 100,
        "text": "a" * 16,
        "truncated": True,
    }

    event = repo.put(
        "event", {"causal_ids": [], "input_blob": blob, "output_blob": blob, "parent_ids": []}
    )
    monkeypatch.setattr(inspect_module, "MAX_INSPECT_RESOLVED_BYTES", 24)
    resolved = repo.inspect(event, resolve_blobs=True)
    assert resolved["resolved_blobs_truncated"] is True
    assert sum(len(value.get("text", "")) for value in resolved["resolved_blobs"].values()) <= 24


def test_resolved_inspection_verifies_a_repeated_blob_once(monkeypatch, tmp_path):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b'{"safe":true}', redact=False)
    event = repo.put(
        "event", {"causal_ids": [], "input_blob": blob, "output_blob": blob, "parent_ids": []}
    )
    original = inspect_module.read_verified_blob_prefix
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[1])
        return original(*args, **kwargs)

    monkeypatch.setattr(inspect_module, "read_verified_blob_prefix", counted)
    resolved = repo.inspect(event, resolve_blobs=True)
    assert resolved["resolved_blobs"] == {
        "input_blob": {"safe": True},
        "output_blob": {"safe": True},
    }
    assert calls == [blob]
