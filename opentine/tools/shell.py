"""Shell tool: disabled by default and command-array based internally."""

from __future__ import annotations

import shlex
import shutil
import sys
from pathlib import Path

from opentine.policies import ShellPolicy
from opentine.tools import _sandbox
from opentine.tools._git_guard import git_env, is_git, is_git_family
from opentine.tools._git_guard import hardened as hardened_git
from opentine.tools._git_guard import refusal as git_refusal
from opentine.tools._process import clean_env, run_bounded
from opentine.tools._shell_args import refusal as arg_refusal


def _strip_outer_quotes(part: str) -> str:
    if len(part) >= 2 and part[0] == part[-1] and part[0] in {"'", '"'}:
        return part[1:-1]
    return part


def _split_command(command: str) -> list[str]:
    parts = shlex.split(command, posix=(sys.platform != "win32"))
    if sys.platform == "win32":
        parts = [_strip_outer_quotes(part) for part in parts]
    return parts


def _subprocess_parts(parts: list[str]) -> list[str]:
    if sys.platform == "win32" and parts[0] in {"python", "python3"}:
        return [sys.executable, *parts[1:]]
    return parts


def _bound_executable(executable: str, allowed: tuple[str, ...]) -> str | None:
    """The absolute program an allowlist entry names, resolved now.

    An entry is compared as written, so a bare ``git`` ran whatever ``PATH``
    found first at spawn time. Resolving at policy bind time pins the program
    the operator meant; an entry that resolves to nothing is refused.
    """
    if executable not in allowed:
        return None
    if Path(executable).is_absolute():
        return executable
    return shutil.which(executable)


def _bound_or_none(executable: str) -> str | None:
    return executable if Path(executable).is_absolute() else shutil.which(executable)


def run(
    command: str,
    timeout: int = 30,
    allowlist: list[str] | None = None,
    sandbox: bool = True,
    policy: ShellPolicy | None = None,
) -> str:
    """Run a shell command and return stdout + stderr.

    If sandbox is True (the default), an allowlist must be provided and the
    executable (first token) must be in that list.  Set sandbox=False to
    allow arbitrary commands (use with caution).
    """
    try:
        parts = _split_command(command)
    except ValueError as e:
        return f"Error: failed to parse command: {e}"

    if not parts:
        return "Error: empty command"

    executable = parts[0]

    pol = policy or ShellPolicy(
        enabled=not sandbox,
        executables=tuple(allowlist or ()),
        timeout_seconds=timeout,
    )
    if not pol.enabled:
        return "Error: shell execution disabled by policy"
    if pol.executables and executable not in pol.executables:
        return f"Error: '{executable}' not in allowlist {list(pol.executables)}"
    if is_git_family(executable):
        return f"Error: '{executable}' is a git helper; run it through git"

    try:
        backend = _sandbox.choose(pol.sandbox, image=pol.sandbox_image)
    except _sandbox.SandboxUnavailable as exc:
        return f"Error: {exc}"

    cwd_root = Path(pol.cwd_root).resolve()
    try:
        Path.cwd().resolve().relative_to(cwd_root)
    except ValueError:
        return f"Error: cwd escapes shell policy root {cwd_root}"

    env = clean_env(pol.inherit_env, pol.env_allowlist)
    if is_git(executable):
        reason = git_refusal(
            parts[1:],
            root=cwd_root,
            cwd=Path.cwd().resolve(),
            network=pol.git_network,
            write_out=pol.git_write_out,
        )
        if reason:
            return f"Error: {reason}"
        parts = hardened_git(parts, network=pol.git_network)
        env = git_env(env)
    elif reason := arg_refusal(parts, root=cwd_root, cwd=Path.cwd().resolve()):
        return f"Error: {reason}"
    windows_python = sys.platform == "win32" and executable in {"python", "python3"}
    if pol.executables and not windows_python:
        bound = _bound_executable(executable, pol.executables)
        if bound is None:
            return f"Error: '{executable}' was not found on PATH"
        parts = [bound, *parts[1:]]

    # Every allow-listed program may be exec'd inside the sandbox, so the
    # command can still run what the policy already permits it to start.
    allowed = [] if backend == "none" else map(_bound_or_none, pol.executables)
    argv = _sandbox.wrap(
        backend,
        _subprocess_parts(parts),
        root=cwd_root,
        cwd=Path.cwd().resolve(),
        executables=[parts[0], *(exe for exe in allowed if exe)],
        network=pol.sandbox_network or (is_git(executable) and pol.git_network),
        env=env,
        image=pol.sandbox_image,
    )
    try:
        result = run_bounded(
            argv,
            timeout=pol.timeout_seconds,
            max_chars=pol.max_output_chars,
            cwd=str(Path.cwd()),
            env=env,
        )
        if result.timed_out:
            return result.output(
                pol.max_output_chars,
                prefix=f"Error: command timed out after {pol.timeout_seconds}s\n",
            )
        return result.output(pol.max_output_chars)
    except Exception as e:
        return f"Error: {e}"


# Registering the built-in directly remains disabled. Callers that intend to
# enable it bind a ShellPolicy in their own one-argument wrapper.
run.__opentine_hidden_parameters__ = frozenset({"timeout", "allowlist", "sandbox", "policy"})
