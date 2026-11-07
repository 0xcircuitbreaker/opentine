"""``repo-search`` flags for the derived FTS5 index (0.44)."""

from __future__ import annotations

import argparse
import sys

from opentine.repository._search_index import rebuild


def add_index_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rebuild-index",
        action="store_true",
        help="Rewrite .tine/index/search.sqlite (FTS5 BM25) from the objects, then search",
    )
    parser.add_argument(
        "--no-index", action="store_true", help="Scan the objects even when an index exists"
    )


def apply_index_flags(args: argparse.Namespace, repo) -> bool:
    """Rebuild when asked; returns whether the search may use the index."""
    if getattr(args, "rebuild_index", False):
        try:
            count = rebuild(repo)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc
        print(f"indexed {count} runs", file=sys.stderr)
    return not getattr(args, "no_index", False)
