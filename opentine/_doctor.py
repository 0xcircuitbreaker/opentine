"""``tine doctor``: offline checks of the environment, keys, hooks, harnesses and remotes.

Every check is local: nothing here opens a socket. Remote capabilities are not
probed (that needs the network), so the remotes row lists configured remotes only.

The support bundle (``--bundle PATH``) is the same report passed through
:func:`opentine.redaction.redact_value`, plus a final scan that refuses to write
it if any credential-shaped bytes survive. Key rows carry fingerprints and
paths, never key material; environment rows carry variable *names* only.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from opentine._version import __version__

_ENV_PREFIXES = ("OPENTINE_", "TINE_")


def _row(check: str, status: str, detail: str) -> dict[str, str]:
    return {"check": check, "status": status, "detail": detail}


def _environment() -> list[dict[str, str]]:
    rows = [
        _row("opentine", "ok", __version__),
        _row("python", "ok" if sys.version_info >= (3, 11) else "fail", platform.python_version()),
        _row("platform", "ok", f"{platform.system()} {platform.machine()}"),
        _row("git", "ok" if shutil.which("git") else "warn", shutil.which("git") or "not on PATH"),
    ]
    names = sorted(name for name in os.environ if name.startswith(_ENV_PREFIXES))
    rows.append(_row("env", "ok", ", ".join(names) if names else "no OPENTINE_/TINE_ variables"))
    return rows


def _keys() -> list[dict[str, str]]:
    from opentine._agent_keys import key_dir

    folder = key_dir()
    if not folder.is_dir():
        return [_row("agent-keys", "warn", f"no key directory ({folder.as_posix()})")]
    public = sorted(path.stem for path in folder.glob("*.pub"))
    private = {path.stem for path in folder.glob("*.key")}
    unpaired = sorted(private - set(public))
    status = "warn" if unpaired else "ok"
    detail = f"{len(public)} agent key(s): {', '.join(public) or 'none'}"
    if unpaired:
        detail += f"; private key without .pub: {', '.join(unpaired)}"
    return [_row("agent-keys", status, detail)]


def _hooks_dir(start: Path) -> Path | None:
    """The hooks directory git uses here (``core.hooksPath``, linked worktrees), or ``None``."""
    from opentine.tools._git_guard import git_env

    exe = shutil.which("git")
    if exe:
        try:
            done = subprocess.run(  # hardened: no fsmonitor, no transport, no GIT_* env
                [exe, "-c", "core.fsmonitor=", "-c", "protocol.allow=never", "-C"]
                + [start.as_posix(), "rev-parse", "--git-path", "hooks"],
                capture_output=True,
                env=git_env(os.environ),
                stdin=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            done = None
        out = done.stdout.decode("utf-8", "replace").strip() if done and not done.returncode else ""
        if out:
            return Path(out) if Path(out).is_absolute() else start / out
        if done is not None and done.returncode:
            return None  # git ran and says: not a checkout
    for folder in (start, *start.parents):  # no usable git binary: the plain layout only
        if (folder / ".git" / "hooks").is_dir():
            return folder / ".git" / "hooks"
    return None


def _is_tine_hook(path: Path) -> bool:
    try:
        return path.is_file() and b"tine" in path.read_bytes()[: 1 << 20]
    except OSError:
        return False


def _hooks(start: Path) -> list[dict[str, str]]:
    hooks = _hooks_dir(start)
    if hooks is None or not start.is_dir():
        return [_row("git-hooks", "warn", "not inside a git checkout")]
    if not hooks.is_dir():
        return [_row("git-hooks", "warn", "no tine hooks installed")]
    ours = sorted(
        path.name
        for path in hooks.iterdir()
        if not path.name.endswith(".sample") and _is_tine_hook(path)
    )
    status = "ok" if ours else "warn"
    return [_row("git-hooks", status, ", ".join(ours) or "no tine hooks installed")]


def _harnesses() -> list[dict[str, str]]:
    from opentine._agent_detect import present
    from opentine._cli_harnesses import harness_rows

    found = [row["name"] for row in harness_rows() if row["installed"]]
    agents = present()
    return [
        _row("harnesses", "ok" if found else "warn", ", ".join(found) or "none on PATH"),
        _row(
            "agent-capture", "ok" if agents else "warn", ", ".join(agents) or "no agent CLI found"
        ),
    ]


def _repository(path: Path) -> list[dict[str, str]]:
    from opentine._cli_git_sync import configured_remotes
    from opentine.repository import Repo

    try:
        repo = Repo.open(path)
    except Exception as exc:  # noqa: BLE001 - "no repository here" is a finding
        return [_row("repository", "warn", f"no v3 repository: {type(exc).__name__}")]
    refs = repo.list_refs()
    rows = [_row("repository", "ok", f"{len(refs)} ref(s)")]
    try:
        remotes = configured_remotes(repo)
    except Exception:  # noqa: BLE001 - an unreadable config is a finding
        return [*rows, _row("remotes", "warn", "remote config unreadable")]
    detail = ", ".join(remotes) + " (offline: capabilities not probed)" if remotes else "none"
    return [*rows, _row("remotes", "ok", detail)]


def report(repo: str = ".") -> dict[str, Any]:
    path = Path(repo)
    checks = [
        *_environment(),
        *_keys(),
        *_hooks(path.resolve()),
        *_harnesses(),
        *_repository(path),
    ]
    worst = "fail" if any(c["status"] == "fail" for c in checks) else "ok"
    return {"kind": "opentine.doctor", "doctor_version": 1, "status": worst, "checks": checks}


def bundle(body: dict[str, Any]) -> bytes:
    """The redacted support bundle; ``ValueError`` if any secret shape survives."""
    from opentine.kernel import canonical_json
    from opentine.redaction import redact_blob, redact_value

    data = canonical_json(redact_value(body))
    if redact_blob(data) != data:
        raise ValueError("support bundle still holds credential-shaped bytes; not written")
    return data


__all__ = ["bundle", "report"]
