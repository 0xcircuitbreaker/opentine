"""``tine lineage graph|why|archive|index`` (0.59): the lineage DAG over the derived index.

Every command reads the derived index ``LINEAGE_FOLDER/index/lineage.sqlite``,
built from the signed records in the lineage folder (rebuilt when missing or
stale; ``index --rebuild`` forces it). The index is never authoritative: delete
it and the next command rebuilds an identical graph. ``why`` also runs
``tine lineage check`` over the folder, so its ``ok`` and ``findings`` are the
check's verdict on the same ancestry, never a reading of the index.
"""

from __future__ import annotations

import argparse
import hashlib
from contextlib import closing
from pathlib import Path
from typing import Any


def body(args: argparse.Namespace, folder: Path) -> dict:
    from opentine import _lineage_index as index
    from opentine import _lineage_query as query
    from opentine._lineage import read_folder

    files = read_folder(folder)
    if args.lineage_command == "index" and args.rebuild:
        index.index_path(folder).unlink(missing_ok=True)
    with closing(index.open_index(folder, refresh=not args.no_refresh, files=files)) as db:
        if args.lineage_command == "graph":
            return index.graph(db, loop=args.loop)
        if args.lineage_command == "why":
            return _why(args, folder, files, db)
        if args.lineage_command == "archive":
            return query.archive(db, loop=args.loop, signed_only=args.signed)
        out = index.graph(db)
        return {"variants": len(out["nodes"]), "edges": len(out["edges"]),
                "graph_sha256": out["graph_sha256"],
                "path": index.index_path(folder).as_posix()}  # fmt: skip


def _why(args: argparse.Namespace, folder: Path, files: dict[str, bytes], db: Any) -> dict:
    """``why`` re-derived against the folder (a poisoned index is rebuilt once), then checked."""
    from opentine import _lineage_index as index
    from opentine import _lineage_query as query
    from opentine._lineage_check import _loads, check
    from opentine._lineage_claim import rows as claim_rows

    by_oid = {"sha256:" + hashlib.sha256(raw).hexdigest(): raw
              for path, raw in files.items() if path.startswith("variants/")}  # fmt: skip

    def load(oid: str) -> dict | None:
        try:
            return claim_rows(oid, _loads(by_oid[oid]), files)
        except (KeyError, ValueError):  # an absent or unreadable record is a mismatch
            return None

    def walk(conn: Any) -> dict:
        return query.why(conn, args.variant, max_depth=args.max_depth,
                         max_nodes=args.max_nodes, load=load)  # fmt: skip

    try:
        out = walk(db)
    except query.IndexMismatch:
        index.rebuild(folder, files)
        with closing(index.open_index(folder, refresh=False)) as fresh:
            out = {**walk(fresh), "rebuilt": True}
    verdict = check(files, args.variant)
    return {**out, "ok": verdict["ok"], "findings": verdict["findings"]}


def text(args: argparse.Namespace, out: dict) -> str:
    command = args.lineage_command
    if command == "why":
        verdict = "OK" if out["ok"] else "REFUSED"
        lines = [f"{verdict} {out['variant']}: {len(out['ancestors'])} variants, "
                 f"depth {out['depth']}"]  # fmt: skip
        lines += [f"  {kind}: {', '.join(refs)}" for kind, refs in out["summary"].items()]
        lines += [f"  missing parent: {name}" for name in out["missing_parents"]]
        lines += ["  truncated: raise --max-nodes to walk further"] * out["truncated"]
        lines += [f"  {f['code']} {f['variant']}: {f['detail']}" for f in out["findings"]]
        return "\n".join(lines)
    if command == "archive":
        totals = " ".join(f"{k}={v}" for k, v in out["totals"].items())
        rows = [f"  {m['variant']} signed={m['signed']} parents={m['parents']} "
                f"children={m['children']}" for m in out["members"]]  # fmt: skip
        return "\n".join([totals, *rows])
    return f"{out['variants']} variants, {out['edges']} edges, graph {out['graph_sha256']}"


__all__ = ["body", "text"]
