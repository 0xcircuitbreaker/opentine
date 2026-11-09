"""Writers killed mid-write never leave a repository that fails fsck.

``Popen.kill`` is SIGKILL on POSIX and TerminateProcess on Windows: either way
the writer gets no chance to clean up, which is the crash the atomic-write and
ref-lock paths must survive.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import textwrap
import time

import pytest

from opentine.repository import Repo

ROUNDS = int(os.environ.get("OPENTINE_STRESS_KILL_ROUNDS", "40"))

_WRITER = textwrap.dedent(
    """
    import sys
    from opentine import Run, StepKind
    from opentine.repository import Repo
    from opentine.kernel import KernelError
    from opentine.repository._gc import gc

    repo = Repo.open(sys.argv[1])
    tag = sys.argv[2]
    print("ready", flush=True)
    n = 0
    while True:
        run = Run(id=f"kill-{tag}-{n}", model_info="mock/stress")
        for i in range(8):
            run.add_step(StepKind.tool, {"i": i}, {"output": f"{tag}:{n}:{i} " * 400})
        repo.put_run(run, ref=f"heads/w{tag}")
        repo.update_ref("tags/latest", repo.put("blob", f"{tag}{n}".encode()))
        if n % 3 == 2:
            try:
                gc(repo)
            except KernelError as exc:  # the other live writer's gc holds the lock
                if "another tine gc is running" not in str(exc):
                    raise
        n += 1
    """
)


def _spawn(path, tag: str) -> subprocess.Popen:
    env = dict(os.environ, OPENTINE_AUTO_PACK="40")  # autopack fires mid-loop too
    proc = subprocess.Popen(
        [sys.executable, "-c", _WRITER, str(path), tag],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == b"ready"
    return proc


@pytest.mark.stress
def test_killed_writers_leave_a_repository_that_passes_fsck(tmp_path):
    rng = random.Random(0x37)
    repo = Repo.init(tmp_path / "repo")
    for round_ in range(ROUNDS):
        procs = [_spawn(repo.path, f"{round_}-{n}") for n in range(2)]
        time.sleep(rng.uniform(0.05, 0.6))
        for proc in procs:
            proc.kill()
        for proc in procs:
            _, err = proc.communicate(timeout=60)
            assert b"Traceback" not in err, err.decode(errors="replace")[-2000:]
        check = Repo.open(repo.path)
        check.recover_refs()  # what the next writer does on a stale lock
        result = check.fsck()
        assert result.ok, f"round {round_}: {result}"
        for name, oid in check.list_refs().items():
            assert check.has(oid), f"round {round_}: {name} -> missing {oid}"
