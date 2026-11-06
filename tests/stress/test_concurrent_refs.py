"""Sixteen processes updating refs at once lose no update."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

from opentine.repository import Repo
from opentine.repository._reflog import read_reflog

WRITERS = 16
UPDATES = int(os.environ.get("OPENTINE_STRESS_REF_UPDATES", "40"))

_WORKER = textwrap.dedent(
    """
    import sys
    from opentine.repository import Repo

    repo = Repo.open(sys.argv[1])
    who, count = sys.argv[2], int(sys.argv[3])
    own = None
    for i in range(count):
        def bump(current, i=i):
            return repo.put("blob", f"{current}|{who}:{i}".encode("ascii"))
        repo.update_ref_rebase("tags/shared", bump, actor=f"w{who}")
        new = repo.put("blob", f"own {who}:{i}".encode("ascii"))
        repo.update_ref(f"tags/own-{who}", new, expected_old=own)
        own = new
    """
)


@pytest.mark.stress
def test_sixteen_processes_lose_no_ref_update(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _WORKER, str(repo.path), str(n), str(UPDATES)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for n in range(WRITERS)
    ]
    failures = []
    for proc in procs:
        _, err = proc.communicate(timeout=600)
        if proc.returncode:
            failures.append(err.decode(errors="replace")[-2000:])
    assert failures == []
    assert len(read_reflog(repo.path, "tags/shared")) == WRITERS * UPDATES
    chain, oid = 0, repo.read_ref("tags/shared")
    while oid not in (None, "None"):
        chain += 1
        oid = repo.get(oid).body.decode("ascii").rsplit("|", 1)[0]
    assert chain == WRITERS * UPDATES
    for n in range(WRITERS):
        assert len(read_reflog(repo.path, f"tags/own-{n}")) == UPDATES
    assert repo.fsck().ok
