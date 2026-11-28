"""Which stop policy a command is under: every repository it touches, plus a pinned pointer.

0.91 review. A stop policy is discovered per repository, so a command run with
``--repo`` elsewhere, or from a directory with no ``.tine``, used to skip it.
:func:`find` now looks at every place the command reads or writes (the current
directory, ``--repo``, a harness ``--cwd``, the ``--save`` destination; each
searched up through its parents) and at a policy pointer:

* ``$XDG_CONFIG_HOME/opentine/stop-policy`` (the user's trust config, outside
  every repository, beside the pinned ``trust-owner``): one line naming a
  repository directory whose stop policy applies to every command;
* ``$OPENTINE_STOP_POLICY``: the same, for one environment.

A pointer only adds a policy, never lifts one, and a pointer that does not name
a repository with a usable stop policy refuses the command (fail closed). Two
different stop policies in force at once also refuse it: a run belongs to one
fleet. With no policy anywhere nothing changes (D12).

The boundary: the policy governs ``tine run`` (every mode), ``tine record`` and
``tine fan-out``, the commands that run agent code. Administrative writes
(``tine stop``, ``tine tripwire``, signing, imports) are not agent actions and
are not gated; a process that never calls ``tine`` is outside it entirely.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

POINTER_ENV = "OPENTINE_STOP_POLICY"
POINTER_FILE = "stop-policy"


class ScopeError(ValueError):
    """The stop policies that apply cannot be resolved: the command is refused."""


def pointers() -> list[str]:
    """Repository directories named by the pinned pointer file and the environment."""
    from opentine._config_home import config_dir

    named = []
    try:
        text = config_dir(POINTER_FILE).read_bytes().decode("utf-8").strip()
    except FileNotFoundError:
        text = ""
    except (OSError, UnicodeDecodeError) as exc:
        raise ScopeError(f"stop policy pointer unreadable: {exc}") from None
    if text:
        named.append(text)
    if os.environ.get(POINTER_ENV):
        named.append(os.environ[POINTER_ENV])
    return named


def find(places: Iterable[str | Path | None]) -> tuple[Any, dict[str, Any]] | None:
    """``(repository, policy)`` in force for a command touching *places*, else ``None``."""
    from opentine import _stop_policy

    found: dict[str, tuple[Any, dict[str, Any]]] = {}

    def consider(where: Any, pinned: bool) -> None:
        repo = _stop_policy.discover(where)
        policy = _stop_policy.load(repo) if repo is not None else None  # fails closed
        if policy is None:
            if pinned:
                raise ScopeError(f"the stop policy pointer names {where}, which has no "
                                 "stop policy")  # fmt: skip
            return
        found.setdefault(str(Path(repo.path).resolve()), (repo, policy))

    for where in pointers():
        if not Path(where).is_dir():
            raise ScopeError(f"the stop policy pointer names {where}, not a directory")
        consider(where, True)
    for where in [None, *places]:
        consider(where, False)
    fleets = {(p["fleet"], p["channel"], p["vkey"]) for _, p in found.values()}
    if len(fleets) > 1:
        raise ScopeError(
            "more than one stop policy applies to this command (fleets "
            f"{', '.join(sorted(f[0] for f in fleets))}); run it in one fleet"
        )
    if not found:
        return None
    return found[sorted(found)[0]]


__all__ = ["POINTER_ENV", "POINTER_FILE", "ScopeError", "find", "pointers"]
