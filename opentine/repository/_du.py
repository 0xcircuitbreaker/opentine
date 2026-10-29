"""``tine du``: where a repository's bytes go, by kind, by run and by ref.

Sizes are apparent file sizes (``st_size``), the same on every platform; no
allocation-block assumptions. ``stored_bytes`` of a packed object is its share
of its compressed block, pro rata to its uncompressed length.
"""

from __future__ import annotations

import os
from pathlib import Path

from opentine.repository._gc_tidy import fanout_dirs, loose_entries
from opentine.repository._packs import pack_set
from opentine.repository._paths import internal_path
from opentine.repository._prune_roots import reachable
from opentine.repository._storage import canonical_size

BY = ("kind", "run", "ref")


def _tree_bytes(root: Path, name: str) -> tuple[int, int]:
    files = total = 0
    base = internal_path(root, name)
    for directory, _, names in os.walk(base, followlinks=False):
        for item in names:
            try:
                total += os.lstat(os.path.join(directory, item)).st_size
                files += 1
            except OSError:
                continue
    return files, total


def object_sizes(repo) -> dict[str, tuple[int, int, bool]]:
    """oid -> (canonical bytes, stored bytes, loose?); a loose copy wins."""
    sizes: dict[str, tuple[int, int, bool]] = {}
    packs = pack_set(repo.path)
    packs.refresh()
    for oid, (digest, number, _, length) in packs.where.items():
        _, stored_len, raw_len = packs.blocks[digest][number]
        size = packs.v3[digest][oid][3] if digest in packs.v3 else length
        sizes[oid] = (size, round(length * stored_len / raw_len) if raw_len else 0, False)
    for oid, _, info in loose_entries(repo.path):
        try:
            declared = canonical_size(repo, oid)
        except (KeyError, ValueError, OSError):
            declared = None
        sizes[oid] = (info.st_size if declared is None else declared, info.st_size, True)
    return sizes


def _group(repo, sizes, oids) -> dict:
    present = [oid for oid in oids if oid in sizes]
    return {
        "objects": len(present),
        "raw_bytes": sum(sizes[oid][0] for oid in present),
        "stored_bytes": sum(sizes[oid][1] for oid in present),
    }


def usage(repo, by: str = "kind") -> dict:
    if by not in BY:
        raise ValueError(f"--by must be one of {', '.join(BY)}")
    root = repo.path
    sizes = object_sizes(repo)
    dirs = list(fanout_dirs(root))
    empty = sum(1 for directory in dirs if not os.listdir(directory))
    loose = [oid for oid, value in sizes.items() if value[2]]
    pack_files, pack_bytes = _tree_bytes(root, "packs")
    report: dict = {
        "loose": {
            **_group(repo, sizes, loose),
            "fanout_dirs": len(dirs),
            "empty_fanout_dirs": empty,
        },
        "packed": {
            **_group(repo, sizes, [oid for oid, value in sizes.items() if not value[2]]),
            "files": pack_files,
            "file_bytes": pack_bytes,
        },
    }
    for name in ("refs", "logs", "indexes", "fanouts", "txn"):
        files, total = _tree_bytes(root, name)
        report[name] = {"files": files, "bytes": total}
    report["total_bytes"] = (
        report["loose"]["stored_bytes"]
        + pack_bytes
        + sum(report[n]["bytes"] for n in ("refs", "logs", "indexes", "fanouts", "txn"))
    )
    if by == "kind":
        kinds = sorted({oid.split(":", 1)[0] for oid in sizes})
        report["by_kind"] = {
            kind: _group(repo, sizes, [oid for oid in sizes if oid.startswith(kind + ":")])
            for kind in kinds
        }
    else:
        refs = repo.list_refs()
        rows = []
        if by == "ref":
            for name, target in sorted(refs.items()):
                rows.append(
                    {
                        "ref": name,
                        "target": target,
                        **_group(repo, sizes, reachable(repo, {target})),
                    }
                )
        else:
            names: dict[str, list[str]] = {}
            for name, target in sorted(refs.items()):
                if target.startswith("run:"):
                    names.setdefault(target, []).append(name)
            for run, labels in sorted(names.items()):
                rows.append(
                    {"run": run, "refs": labels, **_group(repo, sizes, reachable(repo, {run}))}
                )
        report[f"by_{by}"] = rows
    return report
