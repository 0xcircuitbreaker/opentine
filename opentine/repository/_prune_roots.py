"""What ``tine prune`` must keep: every root, and everything reachable from one.

Roots are found conservatively, by *scanning* rather than by parsing, so a
namespace or record a later release adds is still honoured:

* every file under ``refs/`` (heads, tags, notes, annotations, any namespace),
  ``logs/`` (every unexpired reflog row, old and new side), ``shallow`` (the
  shallow boundary), ``worktrees/``, and any other repository file outside the
  object store, packs and rebuildable indexes;
* every annotation and attestation object (nothing links *to* them);
* runs named by the enclosing git repository's ``Tine-Run`` trailers and
  ``refs/notes/tine`` notes, when the repository lives in a git checkout.

Reachability follows the kernel's links *and* any object id that appears in an
object's bytes, so a reference carried in a blob or an attribute is kept too.
A root source, or a stored object, that cannot be read makes the plan *unsafe*:
prune then deletes nothing.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from opentine.kernel import KernelError, ObjectEnvelope, validate_links
from opentine.repository import _winretry
from opentine.repository._paths import internal_path

OID_BYTES = re.compile(rb"(?:blob|event|run|attestation|annotation):sha256:[0-9a-f]{64}")
#: Repository files never treated as roots: the object store itself and caches.
_STORE = {"objects", "packs", "indexes", "config.json", "gc.lock"}
MAX_ROOT_FILE = 16 * 1024 * 1024


class UnsafePlan(KernelError):
    """A root source could not be read; deleting anything would be a guess."""


def _scan_file(path: Path, found: set[str]) -> None:
    try:
        size = path.lstat().st_size
        if size > MAX_ROOT_FILE:
            raise UnsafePlan(f"{path.name}: root file too large to scan ({size} bytes)")
        # Windows: a ref or lock mid-replace is briefly unreadable; a denial that
        # persists past the retries still makes the plan unsafe (fail closed).
        data = _winretry.read_bytes(path, MAX_ROOT_FILE + 1)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise UnsafePlan(f"cannot read root file {path.name}: {exc}") from exc
    found.update(match.decode("ascii") for match in OID_BYTES.findall(data))


def file_roots(root: Path) -> set[str]:
    """Object ids named anywhere in the repository outside the object store."""
    found: set[str] = set()
    base = internal_path(root)
    for directory, names, files in os.walk(base, followlinks=False):
        relative = Path(directory).relative_to(base)
        if relative == Path("."):
            names[:] = [name for name in names if name not in _STORE]
            files = [name for name in files if name not in _STORE]
        for name in files:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            _scan_file(path, found)
    return found


def in_git_checkout(worktree: Path) -> bool:
    return (worktree / ".git").exists()


def git_roots(worktree: Path) -> set[str]:
    """Runs a surrounding git checkout names in trailers or ``refs/notes/tine``."""
    if not in_git_checkout(worktree):
        return set()
    from opentine._git_link import GitLinkError, git

    try:
        text = git(worktree, "log", "--all", "--notes=refs/notes/tine", "--format=%B%n%N")
    except (GitLinkError, OSError) as exc:
        raise UnsafePlan(
            f"cannot read git trailers/notes in {worktree} ({exc}); "
            "pass --no-git-links to prune without them"
        ) from exc
    return {match.decode("ascii") for match in OID_BYTES.findall(text.encode())}


def reachable(repo, roots: set[str]) -> set[str]:
    """Every stored object reachable from *roots*.

    Only a truly absent object is skipped; one that is stored but cannot be
    read raises :class:`UnsafePlan`.
    """
    seen: set[str] = set()
    stack = sorted(roots)
    while stack:
        oid = stack.pop()
        if oid in seen:
            continue
        try:
            raw = repo.raw(oid)
        except KeyError:
            continue  # not stored here: a shallow boundary, or an id in prose
        except (ValueError, OSError) as exc:
            if not repo.has(oid):
                continue  # vanished or not an object id this store can hold
            # Stored but unreadable (corrupt, or its codec is unavailable): its
            # links are unknown, so anything below it might be deleted wrongly.
            raise UnsafePlan(f"cannot read stored object {oid}: {exc}") from exc
        try:  # also checks the bytes against the id: a corrupt copy is caught
            envelope = ObjectEnvelope.decode(raw, oid)
        except (KernelError, ValueError) as exc:
            raise UnsafePlan(f"cannot read stored object {oid}: {exc}") from exc
        seen.add(oid)
        links = {match.decode("ascii") for match in OID_BYTES.findall(raw)}
        try:
            links.update(validate_links(envelope))
        except (KernelError, ValueError):
            pass
        stack.extend(link for link in links if link not in seen)
    return seen
