"""``repo-search`` flags: the FTS5 index (0.44), hybrid search and ``--remote`` (0.46)."""

from __future__ import annotations

import argparse
import sys
from typing import Any

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
    from opentine._cli_remote_target import add_remote_args

    add_remote_args(parser)  # --remote NAME|URL: search that remote (caps.search)
    parser.add_argument(
        "--hybrid",
        action="store_true",
        help="Fuse BM25 with a local embedding index of redacted text (reciprocal rank fusion)",
    )
    parser.add_argument(
        "--embedder", metavar="SPEC", help="With --hybrid: hash (default) or MODULE:ATTR"
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


def remote_search(args: argparse.Namespace, console) -> None:
    """``repo-search --remote``: runs whose stored record holds QUERY, newest first."""
    from opentine._cli_errors import fail
    from opentine._cli_remote_target import call, resolve, tenant_path

    try:
        base, tenant, token = resolve(args, args.remote)
        query = {"type": "run", **({"text": args.query} if args.query else {})}
        body = call(args, base, token, "POST", tenant_path(tenant, "search"), json=query)
    except Exception as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(message, prefix="tine repo-search: ")
    oids = [oid for oid in body.get("objects") or [] if isinstance(oid, str)][: args.limit]
    if getattr(args, "json", False):
        from opentine._cli_json import emit

        emit({"command": "repo-search", "repo": base + tenant_path(tenant, "")[:-1],
              "remote": args.remote, "query": args.query, "limit": args.limit,
              "count": len(oids), "truncated": bool(body.get("truncated")),
              "results": [{"run_id": oid, "status": "remote"} for oid in oids]})  # fmt: skip
        return
    for oid in oids:
        console.print(oid, highlight=False)
    if not oids:
        console.print("no matching runs on the remote")


def run_search(args: argparse.Namespace, repo, successful_only: bool) -> tuple[list, dict]:
    """``(results, extra JSON fields)`` for ``repo-search``, hybrid or not."""
    use_index = apply_index_flags(args, repo)
    filters: dict[str, Any] = dict(
        successful_only=successful_only, min_score=args.min_score, model=args.model,
        limit=args.limit, signed_only=args.signed_only,
    )  # fmt: skip
    if not getattr(args, "hybrid", False):
        if getattr(args, "embedder", None):
            raise ValueError("--embedder needs --hybrid")
        return repo.search(args.query, use_index=use_index, **filters), {}
    if not use_index:
        raise ValueError("--hybrid needs the index; drop --no-index")
    from opentine._pii_classify import load as load_classifier
    from opentine.repository._embed import load as load_embedder
    from opentine.repository._hybrid import hybrid_search

    embedder = load_embedder(args.embedder)
    try:
        found = hybrid_search(
            repo, args.query, embedder=embedder, classifier=load_classifier(), **filters
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    return found, {"hybrid": True, "embedder": embedder.name}
