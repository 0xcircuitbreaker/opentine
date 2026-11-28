"""Helpers for the 0.91 supervised-run tests: hostile scripts and a child-side fixed clock.

The supervised child is a real ``python -m opentine.cli`` process, so its guard's
clock is injected the way a child's can be: a ``sitecustomize`` on
``PYTHONPATH`` that pins ``opentine._stop_guard._now_ms`` to the test's instant.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# A setsid grandchild (it leaves the process group) that sleeps forever. Popen's
# start_new_session is the setsid: a second os.setsid() in it raised EPERM, so the
# grandchild used to die at once and every test of it passed without a survivor.
_GRANDCHILD = (
    "import json, os, subprocess, sys\n"
    "ARGS = json.loads(os.environ['TINE_TEST_ARGS'])\n"
    "def grandchild(pidfile):\n"
    "    p = subprocess.Popen([sys.executable, '-c', 'import time; "
    "time.sleep(3600)'], start_new_session=True)\n"
    "    open(pidfile, 'w').write(str(p.pid))\n"
)

STOPS = (
    _GRANDCHILD
    + """\
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentine._stop_ops import issue_stop
from opentine.repo import Repo
other, channel, seed, pidfile, now = ARGS
grandchild(pidfile)
issue_stop(Repo.open(other), Path(channel), "fleet-a",
           Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)), reason="halt",
           now_ms=int(now))
while True:  # no model call, no tool call: only the watchdog can stop this
    time.sleep(0.05)
"""
)

CUTS = (
    _GRANDCHILD
    + """\
import os, time
channel, pidfile = ARGS
grandchild(pidfile)
os.rename(channel, channel + ".gone")  # the agent cuts the stop channel
while True:
    time.sleep(0.05)
"""
)


def child_clock(tmp_path: Path, monkeypatch, ms: int) -> None:
    site = tmp_path / "site"
    site.mkdir(exist_ok=True)
    (site / "sitecustomize.py").write_bytes(
        f"import opentine._stop_guard as g\ng._now_ms = lambda: {ms}\n".encode()
    )
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(filter(None, [
        site.as_posix(), os.environ.get("PYTHONPATH")])))  # fmt: skip


def script_args(monkeypatch, *values) -> None:
    """A run's script takes no argv: its arguments travel in ``$TINE_TEST_ARGS``."""
    monkeypatch.setenv("TINE_TEST_ARGS", json.dumps([str(v) for v in values]))


def dead(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] in ("Z", "X")
    except OSError:
        return True


__all__ = ["CUTS", "FORGES", "HALTS_SELF", "SLEEPS", "STOPS", "child_clock", "dead", "script_args"]

SLEEPS = (
    _GRANDCHILD
    + """\
import time
(pidfile,) = ARGS
grandchild(pidfile)
while True:
    time.sleep(0.05)
"""
)

# A hostile child: a setsid grandchild, a stop, a forged "compliant" record of its
# own (signed with the runner key it was given), then exit 3 at once.
FORGES = (
    _GRANDCHILD
    + """\
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentine._stop_guard import Halt
from opentine._stop_ops import issue_stop
from opentine._stop_runner import open_runner
from opentine.repo import Repo
other, channel, seed, pidfile, now, key = ARGS
grandchild(pidfile)
issue_stop(Repo.open(other), Path(channel), "fleet-a",
           Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)), reason="halt",
           now_ms=int(now))
runner = open_runner(Path.cwd(), "r", key)
try:
    runner.guard.check()
except Halt as halt:
    runner.supervised.reason, runner.supervised.requested_ms = halt, int(now)
assert runner.finish()["claim"]["compliant"] is True
os._exit(3)
"""
)

# The child's own watchdog wins the race: a setsid grandchild, a stop, then the
# child's own halt at once (what its watchdog runs), before the parent's ticks.
HALTS_SELF = (
    _GRANDCHILD
    + """\
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentine._stop_guard import Halt
from opentine._stop_ops import issue_stop
from opentine._stop_tree import _halt_self
from opentine.repo import Repo
other, channel, seed, pidfile, now = ARGS
grandchild(pidfile)
issue_stop(Repo.open(other), Path(channel), "fleet-a",
           Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)), reason="halt",
           now_ms=int(now))
_halt_self(Halt("stop.stopped", "halt"))
"""
)
