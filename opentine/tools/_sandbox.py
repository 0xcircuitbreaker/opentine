"""OS-level sandbox backends for the shell tool (X5, OS level).

The argument policy (``_shell_args``) decides what a command may be told; a
backend here makes the operating system enforce the same boundary even if an
argument check were bypassed. Each backend turns an argv into a wrapped argv:

* ``bwrap``: bubblewrap with a read-only bind of ``/``, a read-write bind of
  the policy root, new PID/IPC/UTS (and, by default, network) namespaces and
  ``--die-with-parent``; stacked with Landlock when the kernel has it.
* ``landlock``: a launcher that applies a Landlock ruleset (writes beneath the
  root, exec of allow-listed binaries only, no TCP) and then execs.
* ``sandbox-exec``: macOS with a generated deny-default SBPL profile.
* ``oci``: podman or docker with the root mounted and ``--network none``.

``auto`` picks the strongest available; a backend that is named but missing is
an error, never a silent unsandboxed run. Only ``none`` runs unsandboxed.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
import sys
from pathlib import Path

from opentine.tools import _landlock

BACKENDS = ("auto", "bwrap", "landlock", "sandbox-exec", "oci", "none")
_LAUNCHER = str(Path(_landlock.__file__).resolve())


class SandboxUnavailable(RuntimeError):
    """The policy names a sandbox backend this host can not provide."""


def _probe(argv: list[str]) -> bool:
    try:
        done = subprocess.run(argv, capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


@functools.cache
def bwrap_available() -> bool:
    exe = shutil.which("bwrap")
    return bool(exe) and _probe([exe, "--ro-bind", "/", "/", "--unshare-pid", "true"])


def landlock_available() -> bool:
    return _landlock.abi() >= 1


def sandbox_exec_available() -> bool:
    return sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").exists()


@functools.cache
def oci_runtime() -> str | None:
    for name in ("podman", "docker"):
        exe = shutil.which(name)
        if exe and _probe([exe, "info"]):
            return exe
    return None


def choose(name: str, *, image: str = "") -> str:
    """The backend ``name`` resolves to here, or raise ``SandboxUnavailable``."""
    if name not in BACKENDS:
        raise SandboxUnavailable(f"unknown shell sandbox {name!r}; use one of {BACKENDS}")
    checks = {
        "bwrap": bwrap_available,
        "landlock": landlock_available,
        "sandbox-exec": sandbox_exec_available,
        "oci": lambda: bool(image) and oci_runtime() is not None,
    }
    if name == "auto":
        for candidate in ("bwrap", "landlock", "sandbox-exec"):
            if checks[candidate]():
                return candidate
        raise SandboxUnavailable(
            "shell sandbox 'auto' found no OS backend (bwrap, landlock, sandbox-exec) "
            "on this host; install one or set ShellPolicy(sandbox='none') explicitly"
        )
    if name != "none" and not checks[name]():
        need = " with ShellPolicy.sandbox_image set" if name == "oci" else ""
        raise SandboxUnavailable(f"shell sandbox {name!r} is not available on this host{need}")
    return name


def _landlock_argv(argv: list[str], root: str, execs: list[str], network: bool) -> list[str]:
    flags = [flag for exe in execs for flag in ("--exec", exe)]
    net = ["--net"] if network else []
    return [sys.executable, "-I", _LAUNCHER, "--root", root, *flags, *net, "--", *argv]


def sbpl_profile(root: str, execs: list[str], network: bool) -> str:
    """A deny-default Seatbelt profile: read anywhere, write only beneath ``root``."""

    def quote(path: str) -> str:
        return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'

    # Seatbelt matches the resolved path, so a symlinked binary (a venv's python)
    # is allowed under both its given and its real path.
    paths = dict.fromkeys(p for exe in execs for p in (exe, os.path.realpath(exe)))
    exec_rule = " ".join(f"(literal {quote(exe)})" for exe in paths) or '(subpath "/")'
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow process-fork)",
        f"(allow process-exec {exec_rule})",
        "(allow file-read*)",
        f'(allow file-write* (subpath {quote(root)}) (literal "/dev/null"))',
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow signal (target self))",
    ]
    if network:
        lines.append("(allow network*)")
    return "\n".join(lines) + "\n"


def wrap(
    backend: str,
    argv: list[str],
    *,
    root: Path,
    cwd: Path,
    executables: list[str],
    network: bool,
    env: dict[str, str],
    image: str = "",
) -> list[str]:
    """``argv`` wrapped so it runs under ``backend`` (already chosen)."""
    root_s = str(root.resolve())
    execs = [exe for exe in executables if os.path.isabs(exe)]
    if backend == "none":
        return argv
    if backend == "landlock":
        return _landlock_argv(argv, root_s, execs, network)
    if backend == "bwrap":
        inner = _landlock_argv(argv, root_s, execs, network) if landlock_available() else argv
        net = [] if network else ["--unshare-net"]
        return [
            shutil.which("bwrap") or "bwrap",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
            "--bind", root_s, root_s, "--chdir", str(cwd),
            "--unshare-pid", "--unshare-ipc", "--unshare-uts", *net,
            "--die-with-parent", "--new-session", "--", *inner,
        ]  # fmt: skip
    if backend == "sandbox-exec":
        profile = sbpl_profile(root_s, execs, network)
        return ["/usr/bin/sandbox-exec", "-p", profile, *argv]
    if backend == "oci":
        runtime = oci_runtime() or "docker"
        net = [] if network else ["--network", "none"]
        envs = [flag for key, value in env.items() for flag in ("-e", f"{key}={value}")]
        command = [Path(argv[0]).name, *argv[1:]]
        return [
            runtime, "run", "--rm", "--read-only", *net, "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "-v", f"{root_s}:{root_s}:rw",
            "-w", str(cwd), *envs, image, *command,
        ]  # fmt: skip
    raise SandboxUnavailable(f"unknown shell sandbox {backend!r}")
