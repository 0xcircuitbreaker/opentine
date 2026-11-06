"""0.35: prune deletes through a quarantine (X4), and the minimal ``tine hold``."""

from __future__ import annotations

import json
import os
import shutil
import threading
import time

import pytest

from opentine import cli
from opentine.kernel import KernelError
from opentine.remote import FilesystemObjectStore, LocalKeyProvider
from opentine.repository import Repo, _gc_prune, _holds
from opentine.repository._gc_prune import prune
from opentine.repository._prune_quarantine import Quarantine

OLD = 30 * 86400
STRESS_ROUNDS = int(os.environ.get("OPENTINE_PRUNE_STRESS_ROUNDS", "50"))


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")


def _age(repo, oid, seconds=OLD) -> None:
    stamp = time.time() - seconds
    os.utime(repo._object_path(oid), (stamp, stamp))


def _orphan(repo, text="orphan payload referenced by id only") -> str:
    blob = repo.put("blob", text.encode())
    _age(repo, blob)
    return blob


def _link(repo, blob, ref="heads/main", salt="") -> str:
    event = repo.put("event", {"kind": "tool", "parent_ids": [], "output_blob": blob, "n": salt})
    run = repo.put(
        "run",
        {
            "events": [event],
            "manifests": {},
            "roots": [event],
            "tips": [event],
            "status": "completed",
        },
    )
    repo.update_ref(ref, run)
    return run


def _old_run(repo, ref) -> tuple[str, str]:
    """A run reachable from *ref*, then orphaned (ref deleted) and aged."""
    blob = repo.put("blob", f"body {ref}".encode())
    run = _link(repo, blob, ref)
    event = repo.get(run).payload()["events"][0]
    for oid in (blob, event, run):
        _age(repo, oid)
    (repo.path / "refs" / ref).unlink()
    shutil.rmtree(repo.path / "logs", ignore_errors=True)  # reflogs are roots too
    return run, blob


def _during_plan(monkeypatch, action) -> None:
    real = _gc_prune.reachable
    calls = []

    def slow(repo, roots):
        out = real(repo, roots)
        if not calls:
            calls.append(1)
            action()
        return out

    monkeypatch.setattr(_gc_prune, "reachable", slow)


# -- X4: prune against a concurrent link ---------------------------------------------


def test_a_blob_linked_by_id_while_prune_plans_is_kept(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    blob = _orphan(repo)
    _during_plan(monkeypatch, lambda: _link(Repo.open(repo.path), blob))
    result = prune(repo, delete=True, min_age=0, git_links=False)
    assert repo.has(blob) and result.deleted == 0 and result.restored >= 1
    assert repo.fsck().ok


def test_a_ref_moved_to_an_orphaned_run_while_prune_plans_keeps_its_closure(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    run, blob = _old_run(repo, "heads/old")
    _during_plan(monkeypatch, lambda: Repo.open(repo.path).update_ref("heads/back", run))
    prune(repo, delete=True, min_age=0, git_links=False)
    assert repo.has(run) and repo.has(blob)
    assert repo.fsck().ok


def test_a_packed_object_linked_while_prune_plans_is_kept(tmp_path, monkeypatch):
    from opentine.repository._gc import gc

    repo = Repo.init(tmp_path / "r")
    blob = repo.put("blob", b"packed orphan")
    gc(repo)
    stamp = time.time() - OLD
    for name in os.listdir(repo.path / "packs"):
        os.utime(repo.path / "packs" / name, (stamp, stamp))
    _during_plan(monkeypatch, lambda: _link(Repo.open(repo.path), blob))
    prune(repo, delete=True, min_age=0, git_links=False)
    assert repo.has(blob) and repo.fsck().ok


def test_a_link_after_the_move_is_refused_not_committed_broken(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    blob = _orphan(repo)
    errors = []
    real = Quarantine.move_loose

    def move_then_link(self, oid):
        real(self, oid)
        try:
            _link(Repo.open(repo.path), blob)
        except KernelError as exc:
            errors.append(exc)

    monkeypatch.setattr(Quarantine, "move_loose", move_then_link)
    prune(repo, delete=True, min_age=0, git_links=False)
    assert errors and "missing linked object" in str(errors[0])
    assert repo.read_ref("heads/main") is None and repo.fsck().ok


def test_a_crashed_prune_quarantine_is_restored_by_the_next_prune(tmp_path):
    repo = Repo.init(tmp_path / "r")
    blob = repo.put("blob", b"live")
    run = _link(repo, blob)
    quarantine = Quarantine(repo)
    quarantine.move_loose(blob)  # as a prune killed right after moving it
    assert not repo.has(blob)
    prune(repo, delete=True, min_age=0, git_links=False)
    assert repo.has(blob) and repo.read_ref("heads/main") == run and repo.fsck().ok
    assert not any((repo.path / "prune-quarantine").iterdir())


def test_unreachable_old_objects_are_still_deleted(tmp_path):
    repo = Repo.init(tmp_path / "r")
    blob = _orphan(repo)
    result = prune(repo, delete=True, min_age=0, git_links=False)
    assert result.deleted == 1 and not repo.has(blob)


def test_stress_prune_against_concurrent_links_loses_no_object(tmp_path):
    for round_ in range(STRESS_ROUNDS):
        repo = Repo.init(tmp_path / f"r{round_}")
        blob = _orphan(repo, f"orphan {round_}")
        start = threading.Barrier(2)
        linked: list[str] = []

        def writer(path=repo.path, blob=blob, start=start, linked=linked):
            start.wait()
            time.sleep((round_ % 7) * 0.0007)
            try:
                linked.append(_link(Repo.open(path), blob, salt=str(round_)))
            except KernelError as exc:
                assert "missing linked object" in str(exc)

        thread = threading.Thread(target=writer)
        thread.start()
        start.wait()
        prune(repo, delete=True, min_age=0, git_links=False)
        thread.join()
        check = Repo.open(repo.path)
        if linked:
            assert check.has(blob), f"round {round_}: a linked object was pruned"
        assert check.fsck().ok, f"round {round_}"


# -- hold ------------------------------------------------------------------------------


def _hold(capsys, repo, *argv) -> dict:
    capsys.readouterr()
    cli.main(["hold", *argv, "--repo", str(repo.path), "--json"])
    return json.loads(capsys.readouterr().out)


def test_hold_add_list_release(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    run = _link(repo, repo.put("blob", b"x"))
    added = _hold(capsys, repo, "add", "heads/main")
    assert added["holds"] == [{"oid": run, "target": "heads/main"}]
    assert _hold(capsys, repo, "list")["holds"] == added["holds"]
    data = json.loads((repo.path / "holds").read_bytes())
    assert data == {"format": "tine-holds/1", "holds": added["holds"]}
    assert _hold(capsys, repo, "release", run)["holds"] == added["holds"]
    assert _hold(capsys, repo, "list")["holds"] == []
    with pytest.raises(SystemExit):
        cli.main(["hold", "add", "heads/nope", "--repo", str(repo.path)])


def test_prune_and_gc_prune_now_keep_held_objects(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    held_run, held_blob = _old_run(repo, "heads/held")
    _holds.add(repo, held_run)
    loose_run, loose_blob = _old_run(repo, "heads/gone")
    for oid in (held_run, held_blob):
        _age(repo, oid)  # adding the hold re-touched the run
    capsys.readouterr()
    cli.main(["gc", "--repo", str(repo.path), "--json", "--prune=never"])
    assert "pruned" not in json.loads(capsys.readouterr().out)
    assert repo.has(loose_run)  # --prune=never deletes no unreachable object
    stamp = time.time() - OLD
    for name in os.listdir(repo.path / "packs"):
        os.utime(repo.path / "packs" / name, (stamp, stamp))
    cli.main(["gc", "--repo", str(repo.path), "--json", "--prune=now"])
    assert json.loads(capsys.readouterr().out)["pruned"] >= 2
    assert repo.has(held_run) and repo.has(held_blob)
    assert not repo.has(loose_run) and not repo.has(loose_blob)
    with pytest.raises(_holds.HoldError):
        _holds.refuse_held(repo, [held_blob], "delete")


def test_a_corrupt_holds_file_refuses_every_delete(tmp_path):
    repo = Repo.init(tmp_path / "r")
    blob = _orphan(repo)
    (repo.path / "holds").write_text("{not json")
    with pytest.raises(_holds.HoldError):
        prune(repo, delete=True, min_age=0, git_links=False)
    assert repo.has(blob)


def test_rewind_refuses_a_held_run(tmp_path):
    repo = Repo.init(tmp_path / "r")
    run = _link(repo, repo.put("blob", b"x"))
    _holds.refuse_held_names(tmp_path / "r", {run}, "rewind")  # nothing held yet
    _holds.add(repo, "heads/main")
    for name in (run, "heads/main"):
        with pytest.raises(_holds.HoldError, match="rewind"):
            _holds.refuse_held_names(tmp_path / "r", {name}, "rewind")


def test_the_remote_refuses_to_delete_a_held_object(tmp_path):
    store = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32), codec=None)
    local = Repo.init(tmp_path / "local")
    blob = local.put("blob", b"evidence")
    store.put("acme", blob, local.raw(blob))
    holds = tmp_path / "objects" / ".holds" / "acme"
    _holds.edit_holds(holds, lambda rows: [{"oid": blob, "target": blob}])
    with pytest.raises(PermissionError):
        store.delete("acme", blob)
    assert store.has("acme", blob)
    _holds.edit_holds(holds, lambda rows: [])
    store.delete("acme", blob)
    assert not store.has("acme", blob)


def test_the_remote_retention_hook_never_sees_a_held_object(tmp_path):
    offered: list[str] = []

    class Hook:
        def before_delete(self, tenant, oid):
            offered.append(oid)

    key = LocalKeyProvider(b"k" * 32)
    store = FilesystemObjectStore(tmp_path / "objects", key, codec=None, retention=Hook())
    local = Repo.init(tmp_path / "local")
    blob = local.put("blob", b"evidence")
    store.put("acme", blob, local.raw(blob))
    holds = tmp_path / "objects" / ".holds" / "acme"
    _holds.edit_holds(holds, lambda rows: [{"oid": blob, "target": blob}])
    with pytest.raises(PermissionError):
        store.delete("acme", blob)
    assert offered == []
