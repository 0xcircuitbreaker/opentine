"""Running git where a model can write files: what makes it execute commands.

git executes programs named in its configuration -- ``core.fsmonitor``, a
``filter.*.clean`` driver, an alias starting with ``!`` -- and in several of its
own options. Allowlisting the ``git`` executable therefore bounded nothing: a
model could write ``.git/config`` or pass ``-c alias.x=!cmd``, and the next git
invocation -- its own, or ``code_manifest`` after the run -- ran its command on
the host (audit 0.9.1, D-1/D-3).

Layers, each closing a different door:

* the fs tool refuses to write inside any ``.git`` (``tools.fs``), so a model
  cannot plant repository configuration or hooks;
* every git OpenTine starts runs with :func:`hardened_config` -- fsmonitor,
  hooks, pager and external diff off, implicit bare repositories refused, and
  every transport protocol off unless the policy opts in to the network -- and
  with :func:`git_env`, which drops ``GIT_*``/pager/editor variables (the
  environment spellings of ``-c`` and ``--git-dir``);
* the shell tool runs only listed subcommands with listed options
  (:mod:`opentine.tools._git_policy`), keeps every path and whole-tree form
  inside the shell root (:mod:`._git_tree`), refuses local and helper transports.

An allowlisted interpreter or test runner (``python``, ``pytest``, ``npm``) is
arbitrary code execution by design; only git's arguments are checked.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path, PurePath

from opentine.tools import _git_policy as policy
from opentine.tools._git_paths import pathspec_refusal, whole_tree_refusal

_Where = tuple[Path, Path]

#: Prepended to every git command line OpenTine starts (no network). An empty
#: ``core.fsmonitor`` reads as "off" on every git version; ``safe.bareRepository``
#: is ignored by git < 2.38; hooks resolve against the null device, so none run.
HARDENED_CONFIG = (
    "-c", "core.fsmonitor=",
    "-c", "safe.bareRepository=explicit",
    "-c", f"core.hooksPath={os.devnull}",
    "-c", "core.pager=cat",
    "-c", "diff.external=",
    "-c", "protocol.allow=never",
)  # fmt: skip

#: Added when the shell policy opts in to network subcommands.
NETWORK_CONFIG = ("-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always")

#: Environment git must never inherit, beyond every ``GIT_*`` name.
_ENV_DROP = frozenset({"PAGER", "EDITOR", "VISUAL", "LESS", "LESSOPEN", "LESSCLOSE"})
_ENV_PIN = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_PAGER": "cat",
    "GIT_EDITOR": "true",
    "GIT_PROTOCOL_FROM_USER": "0",
}

_GIT_NAMES = frozenset({"git", "git.exe"})
_FAMILY = re.compile(r"(?i)^(git-.+|scalar)(\.exe)?$")
_REMOTE_URL = re.compile(r"^(https://|ssh://)[^\s]+$|^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+$")
_REMOTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def hardened_config(*, network: bool = False) -> tuple[str, ...]:
    return HARDENED_CONFIG + (NETWORK_CONFIG if network else ())


def git_env(base: Mapping[str, str]) -> dict[str, str]:
    """*base* without ``GIT_*``, pager or editor variables, plus the pinned ones."""
    kept = {
        name: value
        for name, value in base.items()
        if not name.upper().startswith("GIT_") and name.upper() not in _ENV_DROP
    }
    return {**kept, **_ENV_PIN}


def is_git(executable: str) -> bool:
    return PurePath(executable).name.lower() in _GIT_NAMES


def is_git_family(executable: str) -> bool:
    """``git-*`` helpers and ``scalar``: git programs the guard cannot vouch for."""
    return bool(_FAMILY.match(PurePath(executable).name))


def _contained(value: str, where: _Where) -> bool:
    """Whether *value*, taken relative to git's directory, stays in the root.

    *where* is ``(root, cwd)``: the shell root, and the directory git runs in
    (the root, or where ``-C`` moved it).
    """
    root, cwd = where
    try:
        (cwd / value).resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def _global(arguments: list[str], root: Path, cwd: Path) -> tuple[int, _Where, str | None]:
    where = (root, cwd)
    index = 0
    while index < len(arguments) and arguments[index].startswith("-"):
        token = arguments[index]
        if token == "-C":
            if index + 1 >= len(arguments):
                return index, where, "git option '-C' needs a directory"
            if not _contained(arguments[index + 1], where):
                return index, where, "git -C must stay inside the shell root"
            where = (root, where[1] / arguments[index + 1])
            index += 2
            continue
        if token not in policy.GLOBAL_ALLOWED:
            name = token.split("=", 1)[0]
            return index, where, f"git option {name!r} is not allowed before the subcommand"
        index += 1
    return index, where, None


def _spec(subcommand: str, *, network: bool, write_out: bool):
    if subcommand in policy.SUBCOMMANDS:
        return policy.SUBCOMMANDS[subcommand], None
    if subcommand in policy.NETWORK:
        if not network:
            return None, f"git {subcommand} needs the shell policy's git_network opt-in"
        return policy.NETWORK[subcommand], None
    if subcommand in policy.WRITE_OUT:
        if not write_out:
            return None, f"git {subcommand} needs the shell policy's git_write_out opt-in"
        if subcommand == "clone" and not network:
            return None, "git clone needs the shell policy's git_network opt-in"
        return policy.WRITE_OUT[subcommand], None
    return None, f"git {subcommand} is not an allowed subcommand"


def _check_value(subcommand: str, option: str, value: str, root: _Where) -> str | None:
    if option in policy.PATH_OPTIONS.get(subcommand, ()) and not _contained(value, root):
        return f"git {subcommand} {option} must name a path inside the shell root"
    if option in {"--strategy", "-s"} and subcommand in {"merge", "pull"}:
        if value not in policy.STRATEGIES:
            return f"git {subcommand} strategy {value!r} is not one of git's own"
    return None


def _long(subcommand, token, rest, index, long_ok, root):
    name, eq, value = token.partition("=")
    if name not in long_ok:
        return index, f"git {subcommand} option {name!r} is not allowed"
    takes = name in policy.VALUE_LONG or name in policy.VALUE_LONG_FOR.get(subcommand, ())
    if not eq and takes and name not in policy.OPTIONAL_VALUE_LONG:
        if index >= len(rest):
            return index, f"git {subcommand} option {name!r} needs a value"
        value, index = rest[index], index + 1
        eq = "="
    return index, _check_value(subcommand, name, value, root) if eq else None


def _short(subcommand, token, rest, index, short_ok, root):
    takes = policy.VALUE_SHORT.get(subcommand, "")
    for offset, letter in enumerate(token[1:], start=1):
        if letter not in short_ok:
            return index, f"git {subcommand} option '-{letter}' is not allowed"
        if letter in policy.OPTIONAL_VALUE_SHORT.get(subcommand, ""):  # attached only
            return index, _check_value(subcommand, f"-{letter}", token[offset + 1 :], root)
        if letter in takes:
            value = token[offset + 1 :]
            if not value:
                if index >= len(rest):
                    return index, f"git {subcommand} option '-{letter}' needs a value"
                value, index = rest[index], index + 1
            return index, _check_value(subcommand, f"-{letter}", value, root)
    return index, None


def _options(subcommand: str, rest: list[str], spec, root: _Where) -> tuple[list[str], str | None]:
    long_ok, short_ok = spec
    positionals: list[str] = []
    index = 0
    while index < len(rest):
        token = rest[index]
        index += 1
        if token == "--":
            positionals.extend(rest[index:])
            break
        if token.startswith("--"):
            index, reason = _long(subcommand, token, rest, index, long_ok, root)
        elif token.startswith("-") and len(token) > 1 and not token[1:].isdigit():
            index, reason = _short(subcommand, token, rest, index, short_ok, root)
        else:
            positionals.append(token)
            reason = None
        if reason:
            return positionals, reason
    return positionals, None


def _check_positionals(subcommand: str, positionals: list[str], root: _Where) -> str | None:
    if subcommand in policy.NETWORK or subcommand == "clone":
        remote = positionals[0] if positionals else ""
        if remote and not (_REMOTE_URL.match(remote) or _REMOTE_NAME.match(remote)):
            return f"git {subcommand} remote {remote!r} must be an https/ssh URL or a remote name"
        if subcommand == "clone" and not _REMOTE_URL.match(remote):
            return "git clone needs an https or ssh source (local paths are refused)"
    if subcommand in policy.POSITIONAL_PATHS:
        paths = positionals[1:] if subcommand == "clone" else positionals
        outside = [path for path in paths if not _contained(path, root)]
        return f"git {subcommand} must write inside the shell root" if outside else None
    if subcommand in policy.NETWORK:  # remotes and refspecs, not paths
        return None
    return pathspec_refusal(subcommand, positionals, lambda value: _contained(value, root), root)


def refusal(
    arguments: list[str],
    *,
    root: str | Path | None = None,
    network: bool = False,
    write_out: bool = False,
    cwd: str | Path | None = None,
) -> str | None:
    """Why git must not run with *arguments* (everything after ``git``), or None.

    Every path must stay inside *root* (default: the current directory),
    resolved from *cwd*, the directory git runs in (default: *root*).
    """
    base = Path(root) if root is not None else Path.cwd()
    index, base, reason = _global(arguments, base, Path(cwd) if cwd is not None else base)
    if reason:
        return reason
    if index == len(arguments):
        return None
    subcommand, rest = arguments[index], arguments[index + 1 :]
    spec, reason = _spec(subcommand, network=network, write_out=write_out)
    if reason:
        return reason
    positionals, reason = _options(subcommand, rest, spec, base)
    reason = reason or _check_positionals(subcommand, positionals, base)
    return reason or whole_tree_refusal(subcommand, rest, positionals, base)


def hardened(parts: list[str], *, network: bool = False) -> list[str]:
    """*parts* (a git command line) with :func:`hardened_config` in front."""
    return [parts[0], *hardened_config(network=network), *parts[1:]]
