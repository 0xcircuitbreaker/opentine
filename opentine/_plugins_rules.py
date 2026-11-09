"""Loading rules for plugins (0.47): decided from metadata, before any import.

A candidate entry point may load only when all of these hold:

1. **Allow-listed.** The user's allow-list has an entry with the same kind,
   entry-point name, distribution name and exact version.
2. **Installed, not dropped in.** The distribution lives under one of this
   interpreter's site-packages directories (``sysconfig`` purelib/platlib or
   the user site). A distribution found through the current directory, a
   relative ``sys.path`` entry or ``PYTHONPATH`` pointing elsewhere is refused.
3. **Not shadowed.** The top-level module the entry point names resolves
   (``importlib.util.find_spec``, which reads the path but runs nothing) to a
   file inside that distribution's directory, so a same-named module earlier on
   ``sys.path`` cannot be what gets imported.
4. **Not writable by others** (POSIX): the module's directory is not group- or
   world-writable.

Each refusal is one short reason string; ``""`` means the candidate may load.
"""

from __future__ import annotations

import importlib.util
import os
import site
import stat
import sysconfig
from importlib import metadata
from pathlib import Path


def trusted_roots() -> list[Path]:
    """This interpreter's site-packages directories (resolved)."""
    paths = sysconfig.get_paths()
    roots = [paths.get("purelib"), paths.get("platlib")]
    try:
        roots.append(site.getusersitepackages())
    except AttributeError:  # pragma: no cover - some embedded interpreters
        pass
    return sorted({Path(item).resolve() for item in roots if item})


def _inside(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def _location(dist: metadata.Distribution) -> Path | None:
    try:
        return Path(str(dist.locate_file(""))).resolve()
    except (OSError, TypeError, ValueError):
        return None


def _recorded(dist: metadata.Distribution) -> set[Path]:
    files = dist.files or []
    out = set()
    for item in files[:100_000]:
        try:
            out.add(Path(str(item.locate())).resolve())
        except (OSError, ValueError):
            continue
    return out


def _others_can_write(directory: Path) -> bool:
    if os.name != "posix":
        return False
    try:
        mode = directory.stat().st_mode
    except OSError:
        return True
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH)) and not mode & stat.S_ISVTX


def refusal(
    kind: str, entry: metadata.EntryPoint, name: str, version: str, allow: list[dict[str, str]]
) -> str:
    """Why *entry* may not load, or ``""`` when it may."""
    wanted = {"kind": kind, "name": entry.name, "distribution": name, "version": version}
    if wanted not in allow:
        return "not in the allow-list (tine plugins allow)"
    dist = entry.dist
    location = _location(dist) if dist else None
    if location is None:
        return "its distribution has no location on disk"
    if not any(_inside(location, root) for root in trusted_roots()):
        return "installed outside this interpreter's site-packages"
    module = entry.module.partition(".")[0]
    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, ValueError):
        spec = None
    origin = Path(spec.origin).resolve() if spec and spec.origin else None
    if origin is None or origin not in _recorded(dist):
        return f"module {module!r} does not resolve to a file its distribution installed"
    if _others_can_write(origin.parent):
        return f"{origin.parent.as_posix()} is writable by other users"
    return ""


__all__ = ["refusal", "trusted_roots"]
