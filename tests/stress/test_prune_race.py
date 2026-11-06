"""Prune racing a writer that links the object being pruned, 1,000 rounds.

Either the link fails cleanly ("missing linked object") or the object
survives; a linked object is never deleted and fsck always passes.
"""

from __future__ import annotations

import os
import threading
import time

import pytest

from opentine.kernel import KernelError
from opentine.repository import Repo
from opentine.repository._gc_prune import prune

ROUNDS = int(os.environ.get("OPENTINE_STRESS_PRUNE_ROUNDS", "1000"))
OLD = 30 * 86400


def _link(repo: Repo, blob: str, salt: str) -> str:
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
    repo.update_ref("heads/main", run)
    return run


@pytest.mark.stress
def test_prune_never_deletes_an_object_a_concurrent_writer_linked(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    repo = Repo.init(tmp_path / "repo")
    linked_rounds = 0
    for round_ in range(ROUNDS):
        blob = repo.put("blob", f"orphan {round_}".encode())
        stamp = time.time() - OLD
        os.utime(repo._object_path(blob), (stamp, stamp))
        start = threading.Barrier(2)
        linked: list[str] = []
        errors: list[BaseException] = []

        def writer(blob=blob, start=start, linked=linked, errors=errors, round_=round_):
            start.wait()
            time.sleep((round_ % 7) * 0.0007)
            try:
                linked.append(_link(Repo.open(repo.path), blob, str(round_)))
            except KernelError as exc:
                if "missing linked object" not in str(exc):
                    errors.append(exc)
            except BaseException as exc:  # surfaced below, not lost in the thread
                errors.append(exc)

        thread = threading.Thread(target=writer)
        thread.start()
        start.wait()
        prune(repo, delete=True, min_age=0, git_links=False)
        thread.join()
        assert errors == [], f"round {round_}: {errors!r}"
        check = Repo.open(repo.path)
        if linked:
            linked_rounds += 1
            assert check.has(blob), f"round {round_}: a linked object was pruned"
        if round_ % 50 == 0 or round_ == ROUNDS - 1:
            assert check.fsck().ok, f"round {round_}"
    assert linked_rounds > 0  # the race was actually exercised
