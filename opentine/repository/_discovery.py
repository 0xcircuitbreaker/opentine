"""Finding the repository a path belongs to.

Split out of ``store`` for the module line cap. Discovery walks every parent of
the start directory, which is what makes ``tine`` usable from any subdirectory --
and what made a repository planted in a shared ancestor dangerous, so an
ancestor another user owns is refused rather than adopted.
"""

from __future__ import annotations

import os
from pathlib import Path

from opentine.kernel import KernelError
from opentine.repository._config import validate_config
from opentine.repository._paths import ensure_layout, linklike

#: Repository directories the caller trusts even when another user owns them,
#: ``os.pathsep``-separated; ``*`` trusts every one (git's ``safe.directory``).
SAFE_DIRECTORIES_ENV = "OPENTINE_SAFE_DIRECTORIES"


def find_repository(path: str | Path = ".") -> Path:
    """The ``.tine`` directory (or bare repository root) *path* belongs to."""
    source = Path(path).expanduser()
    if source.name == ".tine" and linklike(source):
        raise KernelError("repository root cannot be a symlink")
    candidate = source.resolve()
    if candidate.is_file():
        candidate = candidate.parent
    if candidate.name != ".tine" and _is_bare_repo(candidate):
        # ``init --bare DIR`` writes config.json at DIR itself: named explicitly,
        # it is the repository, never shadowed by one in a parent directory.
        return candidate
    for base in (candidate, *candidate.parents):
        tine = base if base.name == ".tine" else base / ".tine"
        if (tine / "config.json").exists():
            if base != candidate:
                _refuse_foreign_ancestor(tine)
            # Recreate any structural directory a version-control checkout
            # dropped while empty, so a committed repository opens intact.
            # Best-effort: read-only media cannot be healed, but the objects
            # and refs are still readable there, so opening must not fail.
            try:
                ensure_layout(tine)
            except OSError:
                pass
            return tine
    raise FileNotFoundError(f"no .tine repository from {path}")


def _is_bare_repo(path: Path) -> bool:
    if not (path / "config.json").is_file():
        return False
    try:
        validate_config(path / "config.json")
    except (OSError, ValueError):
        return False
    return True


def _refuse_foreign_ancestor(tine: Path) -> None:
    """Refuse a repository found *above* the start directory that another user owns.

    A ``.tine`` planted in a shared ancestor (``/tmp``, a group-writable project
    root) was adopted silently: a signing key then attested the planter's runs,
    and ``migrate-v3`` copied private runs into the planter's repository -- git's
    CVE-2022-24765 class. A directory the caller names, or the current one, is
    trusted as before. Windows has no ``st_uid`` to compare, so the check is
    POSIX-only (documented in SECURITY_MODEL).
    """
    if os.name == "nt" or not hasattr(os, "geteuid"):
        return
    allowed = os.environ.get(SAFE_DIRECTORIES_ENV, "")
    if allowed.strip() == "*" or str(tine) in allowed.split(os.pathsep):
        return
    owner = tine.stat().st_uid
    if owner != os.geteuid():
        raise KernelError(
            f"refusing repository {tine}: it is in a parent directory and owned by uid "
            f"{owner}, not you; pass --repo explicitly, or list it in "
            f"{SAFE_DIRECTORIES_ENV} to trust it"
        )
