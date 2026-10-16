"""Linux: contain descendants that leave the process group (``setsid``).

A tool's process tree is killed as one process group. A descendant that calls
``setsid()``/``setpgid()`` leaves that group, and when its parent exits it is
re-parented to init -- out of reach, still running after the tool "returned"
(audit round 3, D3-7). On Linux a *child subreaper* (``PR_SET_CHILD_SUBREAPER``)
inherits such orphans instead of init, so a tiny supervisor
(:mod:`opentine.tools._subreaper_script`) sits between OpenTine and the command:
it runs the command, and when the command exits -- or OpenTine asks it to stop
with ``SIGTERM`` -- it kills every process left beneath it, whatever group or
session it moved to, before exiting itself.

The command must not be able to switch that off. A *shim* in a process group of
its own is the command's parent, so ``os.kill(os.getppid(), SIGKILL)`` or
``kill -9 0`` removes only the shim and the command's group, whose orphans the
supervisor still inherits and sweeps (round-4 re-audit). A command that walks
``/proc`` up to the supervisor and kills it is detected: the supervisor reports
its sweep with a nonce the command cannot read, so a forged report proves
nothing (re-audit round 2, #7). And OpenTine never trusts the supervisor alone:
after every command it kills each process still carrying the run's scope marker,
and after a supervisor that vanished without a sweep also the shim's group and
every same-user process started since the launch that hides its environment
(:mod:`opentine.tools._subreaper_sweep`). What remains is a same-user process
that kills the supervisor, scrubs the marker from its environment *and* stays
dumpable -- or simply outruns a ``/proc`` scan. POSIX without cgroups cannot
contain a same-user adversary; real isolation needs an OS sandbox
(SECURITY_MODEL).

macOS and the BSDs have no subreaper; there the group kill is all there is.
Windows uses the kill-on-close Job Object.
"""

from __future__ import annotations

import os
import secrets
import select
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

from opentine.tools._subreaper_script import SUPERVISOR
from opentine.tools._subreaper_sweep import SCOPE_ENV, boot_ticks, kill_hidden, kill_marked


@dataclass
class _Supervised:
    read: int  # OpenTine's end of the report pipe
    token: str  # the scope marker (not secret: it is in the command's environment)
    nonce: str  # proves a report came from the supervisor (secret)
    since: int  # boot ticks just before the launch


def available() -> bool:
    return sys.platform.startswith("linux") and os.path.isdir("/proc/self/task")


def popen(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
    """Start *argv* under the supervisor (Linux), or directly elsewhere."""
    if not available():
        process = subprocess.Popen(argv, **kwargs)
        process.opentine_supervised = None  # type: ignore[attr-defined]
        return process
    token, nonce = secrets.token_hex(16), secrets.token_hex(32)
    # The nonce travels on a pipe of its own, never argv or the environment
    # (both readable through /proc); the supervisor reads it and closes it.
    secret_read, secret_write = os.pipe()
    try:
        os.write(secret_write, nonce.encode())
    finally:
        os.close(secret_write)
    read, write = os.pipe()
    since = max(0, boot_ticks() - 2)
    command = [sys.executable, "-I", "-S", "-c", SUPERVISOR, str(write), str(secret_read), token]
    try:
        process = subprocess.Popen([*command, *argv], pass_fds=(write, secret_read), **kwargs)
    except BaseException:
        os.close(read)
        raise
    finally:
        os.close(write)
        os.close(secret_read)
    process.opentine_supervised = _Supervised(read, token, nonce, since)  # type: ignore[attr-defined]
    return process


def stop(process: Any, grace: float = 2.0) -> None:
    """Ask the supervisor to kill everything beneath it, then wait briefly."""
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=grace)
    except (OSError, subprocess.TimeoutExpired):
        pass


def finish(process: Any) -> bool:
    """After the supervisor is gone: sweep, and return whether it swept itself.

    Only nonce-prefixed report lines count. Whatever they say, every process
    still carrying the run's scope marker is killed; without a sweep report the
    shim's group and the run's hidden processes are killed too.
    """
    state = getattr(process, "opentine_supervised", None)
    if not isinstance(state, _Supervised):
        return True
    process.opentine_supervised = None
    prefix = f"{state.nonce} ".encode()
    lines = [
        line[len(prefix) :] for line in _drain(state.read).splitlines() if line.startswith(prefix)
    ]
    swept = any(line in (b"ok", b"unsupported") for line in lines)
    if not swept:
        for line in lines:
            if line.startswith(b"pid ") and line[4:].isdigit():
                try:
                    os.killpg(int(line[4:]), signal.SIGKILL)
                except OSError:
                    pass
    kill_marked(state.token)
    if not swept:
        kill_hidden(state.since)
    return swept


def _drain(read: int, budget: float = 1.0) -> bytes:
    data = b""
    deadline = time.monotonic() + budget
    try:
        while len(data) < 65536 and (left := deadline - time.monotonic()) > 0:
            if not select.select([read], [], [], left)[0]:
                break
            chunk = os.read(read, 65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    finally:
        os.close(read)
    return data


__all__ = ["SCOPE_ENV", "SUPERVISOR", "available", "finish", "kill_marked", "popen", "stop"]
