"""``tine verify --offline --hermetic``: re-run the verifier with no network at all.

The in-process guard (``_offline_guard``) refuses network calls from Python;
``--hermetic`` asks the operating system as well. On Linux the command re-execs
itself under ``bwrap --unshare-net`` (or ``unshare -rn``) so the process has no
network namespace to reach; on macOS under ``sandbox-exec`` with a deny-network
profile. Windows has no such primitive and the command exits with code 6, as it
does when no sandbox tool is installed: a hermetic run never falls back silently.
"""

from __future__ import annotations

import os
import shutil
import sys

CHILD_ENV = "OPENTINE_HERMETIC_CHILD"
UNSUPPORTED = 6
_MACOS_PROFILE = "(version 1)(allow default)(deny network*)"


def sandbox_prefix(platform: str = sys.platform) -> list[str] | None:
    """The argv that runs a command with no network, or ``None`` when unsupported."""
    if platform.startswith("linux"):
        if bwrap := shutil.which("bwrap"):
            return [bwrap, "--unshare-net", "--dev-bind", "/", "/", "--"]
        if unshare := shutil.which("unshare"):
            return [unshare, "-rn", "--"]
        return None
    if platform == "darwin" and (sandbox := shutil.which("sandbox-exec")):
        return [sandbox, "-p", _MACOS_PROFILE]
    return None


def reexec_hermetic() -> None:
    """Replace this process with the same command inside a no-network sandbox.

    Returns only inside the sandboxed child (marked by ``CHILD_ENV``).
    """
    if os.environ.get(CHILD_ENV) == "1":
        return
    prefix = sandbox_prefix()
    if prefix is None:
        print(
            f"tine: --hermetic is not supported here ({sys.platform}: no network sandbox)",
            file=sys.stderr,
        )
        raise SystemExit(UNSUPPORTED)
    argv = [*prefix, sys.executable, *sys.orig_argv[1:]]
    env = {**os.environ, CHILD_ENV: "1"}
    sys.stdout.flush()
    sys.stderr.flush()
    os.execve(argv[0], argv, env)


__all__ = ["CHILD_ENV", "UNSUPPORTED", "reexec_hermetic", "sandbox_prefix"]
