"""Round-8 release-audit regressions: shallow reads, stray objects/ files, readdir order."""

from __future__ import annotations

import pytest

from opentine.kernel import KernelError
from opentine.repository import Repo
from opentine.repository import _objects as object_storage
from opentine.repository._objects import iter_typed_object_oids
from opentine.repository.pack import create_pack, install_pack, reachable


def _shallow_clone(tmp_path, depth: int):
    """A depth-limited clone exactly as fetch --depth produces one."""
    src = Repo.init(tmp_path / "src")
    blob = src.put("blob", b"payload text")
    first = src.put("event", {"cost": 1.0, "input_blob": blob, "kind": "model", "parent_ids": []})
    second = src.put("event", {"cost": 2.0, "kind": "model", "parent_ids": [first]})
    third = src.put("event", {"cost": 3.0, "kind": "model", "parent_ids": [second]})
    run = src.put(
        "run",
        {
            "events": [first, second, third],
            "roots": [first],
            "status": "completed",
            "tips": [third],
        },
    )
    src.update_ref("heads/main", run)
    dst = Repo.init(tmp_path / "dst")
    install_pack(dst, create_pack(src, reachable(src, [run], depth=depth)))
    dst.update_ref("heads/main", run)
    return src, dst, run, (first, second, third)


def _one_event_run(repo: Repo) -> str:
    event = repo.put("event", {"cost": 1.0, "kind": "model", "parent_ids": []})
    return repo.put(
        "run", {"events": [event], "roots": [event], "status": "completed", "tips": [event]}
    )


def test_log_and_context_slice_stop_at_the_shallow_fetch_boundary(tmp_path):
    # A depth-limited clone fsck'd healthy, but every graph reader crashed on the
    # first cut parent. Traversals now stop at the boundary, like git log.
    src, dst, run, (first, second, third) = _shallow_clone(tmp_path, depth=1)
    assert dst.fsck().ok
    assert [entry.oid for entry in dst.log("heads/main")] == [third]
    assert [entry.oid for entry in dst.context_slice(third)] == [third]

    dst.import_pack(src.pack())  # deepening restores the full history
    assert [entry.oid for entry in dst.log("heads/main")] == [third, second, first]


def test_depth_zero_readers_stay_empty_instead_of_crashing(tmp_path):
    _, dst, run, (_, _, third) = _shallow_clone(tmp_path, depth=0)
    assert dst.log("heads/main") == []
    assert dst.context_slice(third) == []
    assert dst.diff(run, run).summary["cost"] == {"left": 0.0, "right": 0.0}


def test_semantic_diff_covers_only_events_within_the_boundary(tmp_path):
    _, dst, run, events = _shallow_clone(tmp_path, depth=1)
    diff = dst.diff(run, run)
    assert diff.common_events == events  # ids come from the run payload itself
    assert diff.summary["cost"] == {"left": 3.0, "right": 3.0}  # present tip only


def test_load_run_on_a_shallow_clone_names_the_remedy(tmp_path):
    # Full materialization cannot stop at a boundary: it refuses with the remedy
    # instead of leaking a raw KeyError for the first cut event.
    _, dst, _, _ = _shallow_clone(tmp_path, depth=1)
    with pytest.raises(KernelError, match="deepen the fetch"):
        dst.load_run("heads/main")


def test_a_stray_file_in_objects_does_not_take_down_enumeration(tmp_path):
    # macOS Finder's .DS_Store in objects/ or objects/<type>/ raised out of
    # _validate_layout, killing iter_oids, fsck, search, pack, and fetch. The
    # refs/ policy applies here too: an illegal name is not part of the store.
    repo = Repo.init(tmp_path)
    run = _one_event_run(repo)
    repo.update_ref("heads/main", run)
    (repo.path / "objects" / ".DS_Store").write_bytes(b"junk")
    (repo.path / "objects" / "event" / ".DS_Store").write_bytes(b"junk")

    oids = repo.iter_oids()
    assert run in oids and any(oid.startswith("event:") for oid in oids)
    assert repo.fsck().ok
    assert repo.search("") == repo.search("")
    assert repo.pack()


def test_object_enumeration_does_not_leak_readdir_order(tmp_path, monkeypatch):
    # Suffixes streamed in raw os.scandir order — a per-filesystem hash order —
    # so two byte-identical repositories ordered diff evaluations differently.
    # Round 7 fixed the same shape for search results; this covers the scan.
    repo = Repo.init(tmp_path)
    run = _one_event_run(repo)
    prefixes: dict[str, str] = {}
    collided = False
    for score in range(300):  # until two attestations share a 2-hex prefix directory
        oid = repo.attest(run, {"kind": "evaluation", "scores": {"accuracy": score}}, signer="ci")
        prefix = oid.rsplit(":", 1)[1][:2]
        collided = prefix in prefixes
        if collided:
            break
        prefixes[prefix] = oid
    assert collided

    original = object_storage._entries

    def hostile_readdir(directory):
        return iter(sorted(original(directory), reverse=True))

    monkeypatch.setattr(object_storage, "_entries", hostile_readdir)
    scanned = list(iter_typed_object_oids(repo.path, {"attestation"}))
    assert scanned == sorted(scanned)
    order = [item["attestation"] for item in repo.diff(run, run).summary["evaluations"]["left"]]
    assert order == sorted(order)
