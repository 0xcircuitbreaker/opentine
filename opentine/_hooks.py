"""Client-side repository hooks: ``.tine/hooks/{pre-record,post-run,pre-push,post-fetch}``.

Hooks are **off unless the operator turns them on** (``tine config set
hooks.enabled true``) in a porcelain file this machine trusts. A ``.tine``
directory that arrives inside a cloned project therefore cannot run anything:
its ``hooks.enabled`` is ignored until the operator has reviewed the file and
trusted it (see ``_porcelain_config``).

A hook is ``<name>`` (an executable) or ``<name>.py`` (run with the current
interpreter, so it works the same on Windows). It runs:

* from the repository's worktree, with no shell;
* with a scrubbed environment (opentine's tool scrub, so provider keys and
  tokens never reach it) plus ``OPENTINE_HOOK``, ``OPENTINE_REPO`` and the
  event's own ``OPENTINE_*`` variables;
* under a timeout (``hooks.timeout``, default 60 s) with bounded output.

A ``pre-*`` hook that exits non-zero, times out or cannot start aborts the
operation; a ``post-*`` hook's failure is reported but changes nothing.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from opentine import _porcelain_config as porcelain
from opentine.repository._paths import internal_path, linklike
from opentine.tools._env_scrub import clean_env
from opentine.tools._process import run_bounded

HOOKS = ("pre-record", "post-run", "pre-push", "post-fetch")
DEFAULT_TIMEOUT = 60.0
MAX_TIMEOUT = 3600.0
MAX_OUTPUT = 8_000


@dataclass(frozen=True)
class HookResult:
    name: str
    ran: bool
    ok: bool
    returncode: int | None = None
    output: str = ""


def _enabled(config: dict[str, str]) -> bool:
    return config.get("hooks.enabled", "").lower() in ("1", "true", "yes", "on")


def _timeout(config: dict[str, str]) -> float:
    try:
        value = float(config.get("hooks.timeout", DEFAULT_TIMEOUT))
    except ValueError:
        return DEFAULT_TIMEOUT
    return min(max(value, 1.0), MAX_TIMEOUT)


def _program(repo_path: Path, name: str) -> list[str] | None:
    for candidate, prefix in ((f"{name}.py", [sys.executable, "-I"]), (name, [])):
        path = internal_path(Path(repo_path), "hooks", candidate)
        if not path.exists():
            continue
        if linklike(path) or not path.is_file():
            raise ValueError(f"hook {candidate} must be a regular file, not a link")
        if not prefix and not os.access(path, os.X_OK):
            continue
        return [*prefix, str(path)]
    return None


def run_hook(repo_path: str | Path, name: str, env: dict[str, str] | None = None) -> HookResult:
    """Run hook *name* if hooks are enabled and trusted; never runs otherwise."""
    if name not in HOOKS:
        raise ValueError(f"unknown hook {name!r}")
    repo_path = Path(repo_path)
    config = porcelain.effective(repo_path)  # hooks.* is dropped from untrusted files
    if not _enabled(config):
        return HookResult(name, ran=False, ok=True)
    argv = _program(repo_path, name)
    if argv is None:
        return HookResult(name, ran=False, ok=True)
    hook_env = clean_env(True, ())
    hook_env.update({key: str(value) for key, value in (env or {}).items()})
    hook_env.update({"OPENTINE_HOOK": name, "OPENTINE_REPO": str(repo_path)})
    try:
        result = run_bounded(
            argv,
            cwd=str(repo_path.parent),
            env=hook_env,
            timeout=_timeout(config),
            max_chars=MAX_OUTPUT,
        )
    except OSError as exc:
        return HookResult(name, ran=True, ok=False, output=f"could not start: {exc}")
    output = (result.stdout + result.stderr).decode(errors="replace")[-MAX_OUTPUT:]
    if result.timed_out:
        return HookResult(name, ran=True, ok=False, output=f"timed out\n{output}")
    return HookResult(name, True, result.returncode == 0, result.returncode, output)


def require(repo_path: str | Path, name: str, env: dict[str, str] | None = None) -> HookResult:
    """Run a ``pre-*`` hook and refuse the operation when it fails."""
    result = run_hook(repo_path, name, env)
    if result.ran and not result.ok:
        detail = result.output.strip()[-500:]
        raise ValueError(f"{name} hook refused the operation" + (f": {detail}" if detail else ""))
    return result


__all__ = ["HOOKS", "HookResult", "require", "run_hook"]
