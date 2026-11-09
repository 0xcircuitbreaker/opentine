"""``tine graph [PATH...]``: a code map of the repository (0.48, ``tine-graph/1``).

Lists every source file's symbols and imports and the import edges between
files of this repository (:mod:`opentine._code_graph`): tree-sitter for Python
with the optional ``graph`` extra, a regex outline otherwise. ``--symbol NAME``
keeps only the files that define NAME. Read-only and offline; the MCP server
exposes the same map as its ``code_graph`` tool.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any


def add_graph_parser(sub: Any) -> None:
    graph = sub.add_parser("graph", help="Code map: symbols, imports and import edges")
    graph.add_argument("paths", nargs="*", metavar="PATH", help="Only files under these paths")
    graph.add_argument("--repo", default=".", help="The work tree to map (default: .)")
    graph.add_argument("--symbol", metavar="NAME", help="Only files that define NAME")
    graph.add_argument("--json", action="store_true")


def code_map(root: str | Path, paths: list[str] | None = None, symbol: str | None = None) -> dict:
    """The ``tine-graph/1`` document (what the CLI and the MCP tool return)."""
    from opentine import _code_graph

    found = _code_graph.build(Path(root), paths or None)
    if symbol:
        keep = {f["path"] for f in found["files"] if any(s["name"] == symbol for s in f["symbols"])}
        found["files"] = [f for f in found["files"] if f["path"] in keep]
        found["edges"] = [e for e in found["edges"] if e["from"] in keep or e["to"] in keep]
        found["counts"] = {"files": len(found["files"]), "edges": len(found["edges"]),
                           "symbols": sum(len(f["symbols"]) for f in found["files"])}  # fmt: skip
    return found


def cmd_graph(args: argparse.Namespace) -> None:
    from opentine._cli_errors import fail
    from opentine._cli_json import emit

    root = Path(args.repo)
    root = root.parent if root.name == ".tine" else root  # the MCP server passes its store
    if not root.is_dir():
        fail(f"no such directory: {root.as_posix()}", prefix="tine graph: ")
    found = code_map(root, args.paths, args.symbol)
    if args.json:
        emit({"command": "graph", **found})
        return
    for item in found["files"]:
        names = ", ".join(s["name"] for s in item["symbols"][:8])
        more = "" if len(item["symbols"]) <= 8 else f", +{len(item['symbols']) - 8}"
        print(f"{item['path']} [{item['language']}]: {names}{more}")
    counts = found["counts"]
    print(f"{counts['files']} file(s), {counts['symbols']} symbol(s), {counts['edges']} "
          f"edge(s); backend {found['backend']}")  # fmt: skip


__all__ = ["add_graph_parser", "cmd_graph", "code_map"]
