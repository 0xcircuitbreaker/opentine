"""Concurrent gc and writers fighting over the gc lock (nightly, Windows included).

Several processes each write objects and refs and run ``gc`` in a loop. A gc
either packs or refuses with "another tine gc is running"; it never fails any
other way (the lock's two-name window on Windows, delete-pending lock files,
packs merged away under a reader). Afterwards every written object reads
back, fsck passes and no gc lock is left behind.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

from opentine.repository import Repo
from opentine.repository._paths import internal_path

WORKERS = int(os.environ.get("OPENTINE_STRESS_GC_WORKERS", "6"))
ROUNDS = int(os.environ.get("OPENTINE_STRESS_GC_ROUNDS", "40"))

_WORKER = textwrap.dedent(
    """
    import sys
    from opentine.kernel import KernelError
    from opentine.repository import Repo
    from opentine.repository._gc import gc

    repo = Repo.open(sys.argv[1])
    who, rounds = sys.argv[2], int(sys.argv[3])
    packed = refused = 0
    for i in range(rounds):
        oid = repo.put("blob", f"gc-lock {who}:{i}".encode("ascii"))
        print(oid, flush=True)
        repo.update_ref(f"tags/w{who}-{i}", oid)
        try:
            gc(repo, min_age=0, merge_packs=None)
            packed += 1
        except KernelError as exc:
            if "another tine gc is running" not in str(exc):
                raise
            refused += 1
    print(f"done {packed} {refused}", flush=True)
    """
)


@pytest.mark.stress
def test_concurrent_gc_and_writers_keep_every_object_and_release_the_lock(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _WORKER, str(repo.path), str(n), str(ROUNDS)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for n in range(WORKERS)
    ]
    written, failures, packed = [], [], 0
    results = []
    try:
        for proc in procs:
            results.append((proc, *proc.communicate(timeout=1800)))
    finally:
        for proc in procs:  # never leave a hung worker holding the lock
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
    for proc, out, err in results:
        lines = out.decode("ascii", errors="replace").split()
        if proc.returncode:
            failures.append(err.decode(errors="replace")[-2000:])
            continue
        done = lines.index("done")
        written.extend(lines[:done])
        packed += int(lines[done + 1])
    assert failures == []
    assert len(written) == WORKERS * ROUNDS
    assert packed > 0  # the lock was not held forever
    reopened = Repo.open(repo.path)
    for oid in written:
        assert reopened.get(oid).body.startswith(b"gc-lock ")
    assert not internal_path(repo.path, "gc.lock").exists()
    assert reopened.fsck().ok
