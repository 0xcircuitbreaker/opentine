"""Helpers for the 0.91 supervised-run tests: hostile scripts and a child-side fixed clock.

The supervised child is a real ``python -m opentine.cli`` process, so its guard's
clock is injected the way a child's can be: a ``sitecustomize`` on
``PYTHONPATH`` that pins ``opentine._stop_guard._now_ms`` to the test's instant.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# A setsid grandchild (it leaves the process group) that sleeps forever.
_GRANDCHILD = (
    "import json, os, subprocess, sys\n"
    "ARGS = json.loads(os.environ['TINE_TEST_ARGS'])\n"
    "def grandchild(pidfile):\n"
    "    p = subprocess.Popen([sys.executable, '-c', 'import os, time; os.setsid(); "
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


__all__ = ["CUTS", "STOPS", "child_clock", "dead", "script_args"]
