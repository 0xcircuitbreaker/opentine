"""``tine query "SELECT ..."`` and ``tine query index`` (0.65): SQL over a derived index.

``tine query SQL [--verify] [--strict] [--limit N] [--max-steps N] [--refresh]``
runs one read-only statement against ``.tine/query/index.sqlite``
(:mod:`opentine._query_sql`), building the index first when it is missing. A
stale index still answers, marked ``stale`` with the reasons (``--refresh``
rebuilds it first). ``--verify`` re-checks the object behind each returned row
(:mod:`opentine._query_verify`) and exits 1 when any row ``failed``
(``--strict``: when any row is not ``verified``).

``tine query index [--rebuild] [--check] [--evals DIR]...`` reports the index
state (``--check``: compare object ids too) or rebuilds it.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-query/1"
NOTICE = "derived index, non-authoritative: rebuildable from the repository; use --verify"


def add_query_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "query", help="Read-only SQL over a derived, rebuildable index (or: query index)"
    )
    parser.add_argument("sql", metavar="SQL", help='One SELECT statement, or "index"')
    parser.add_argument("--repo", default=".", metavar="PATH", help="Repository")
    parser.add_argument("--verify", action="store_true", help="Re-check each row's object")
    parser.add_argument("--strict", action="store_true", help="With --verify: unverified fails")
    parser.add_argument("--limit", type=int, default=1000, metavar="N", help="At most N rows")
    parser.add_argument("--max-steps", type=int, default=1_000_000, metavar="N",
                        help="Stop after N thousand SQLite steps")  # fmt: skip
    parser.add_argument("--refresh", action="store_true", help="Rebuild a stale index first")
    parser.add_argument("--rebuild", action="store_true", help="index: rebuild it now")
    parser.add_argument("--check", action="store_true", help="index: also compare object ids")
    parser.add_argument("--evals", action="append", default=None, metavar="DIR",
                        help="index: an eval folder to read (repeatable; remembered)")  # fmt: skip
    parser.add_argument("--json", action="store_true", help="Print a JSON object")


def _index(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _query_build as qb
    from opentine import _query_index as qi

    store = Path(repo.path)
    rebuilt = None
    if args.rebuild or args.evals is not None:
        rebuilt = qb.build(repo, args.evals if args.evals is not None else
                           qb.remembered_dirs(store))  # fmt: skip
    state = qb.staleness(repo, exact=args.check)
    meta = qi.read_meta(qi.index_path(store)) if state["exists"] else {}
    body = {"index": qi.index_path(store).as_posix(), "authority": qi.AUTHORITY,
            "rebuilt": rebuilt is not None, **state,
            "counts": rebuilt["counts"] if rebuilt else _counts(meta),
            "evals": qb.remembered_dirs(store)}  # fmt: skip
    lines = [f"{'rebuilt' if rebuilt else 'index'} {body['index']} ({qi.AUTHORITY})"]
    lines += [f"  {name}: {n}" for name, n in sorted((body["counts"] or {}).items())]
    lines += [f"stale: {why}" for why in state["reasons"]] or ["up to date"]
    return body, lines


def _counts(meta: dict[str, str]) -> dict[str, int] | None:
    import json

    try:
        return {k: int(v) for k, v in json.loads(meta["counts"]).items()}
    except (KeyError, ValueError, AttributeError):
        return None


def _select(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _query_build as qb
    from opentine import _query_index as qi
    from opentine._query_sql import QueryError, connect_ro, run

    if args.limit < 1 or args.max_steps < 1:
        raise QueryError("query.usage", "--limit and --max-steps are positive")
    store = Path(repo.path)
    state = qb.staleness(repo)
    if not state["exists"] or (state["stale"] and args.refresh):
        qb.build(repo, qb.remembered_dirs(store))
        state = qb.staleness(repo)
    path = qi.index_path(store)
    result = run(path, args.sql, limit=args.limit, max_steps=args.max_steps)
    body: dict[str, Any] = {"authority": qi.AUTHORITY, "stale": state["stale"],
                            "stale_reasons": state["reasons"], **result,
                            "verification": None}  # fmt: skip
    if args.verify:
        from opentine._query_verify import verify_rows

        with closing(connect_ro(path)) as db:
            checks = verify_rows(repo, result["rows"], db)
        counts = {s: sum(c["status"] == s for c in checks)
                  for s in ("verified", "unverified", "failed")}  # fmt: skip
        body["verification"] = {"counts": counts, "rows": checks}
    return body, _render(body)


def _render(body: dict[str, Any]) -> list[str]:
    columns = body["columns"]
    lines = [f"-- {NOTICE}"]
    if body["stale"]:
        lines.append("-- stale: " + "; ".join(body["stale_reasons"]))
    checks = (body["verification"] or {}).get("rows")
    lines.append("\t".join(columns + (["verification"] if checks else [])))
    for i, row in enumerate(body["rows"]):
        cells = ["" if row[c] is None else str(row[c]) for c in columns]
        lines.append("\t".join(cells + ([checks[i]["status"]] if checks else [])))
    if body["truncated"]:
        lines.append(f"-- truncated at {len(body['rows'])} rows (raise --limit)")
    return lines


def cmd_query(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._query_sql import QueryError
    from opentine.repo import Repo

    verb = "index" if args.sql == "index" else "select"
    try:
        repo = Repo.open(args.repo)
        body, lines = (_index if verb == "index" else _select)(args, repo)
    except QueryError as exc:
        raise error(exc, prefix="query: ") from exc
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix="query: ") from exc
    if args.json:
        emit({"command": f"query {verb}" if verb == "index" else "query", "schema": SCHEMA,
              **body})  # fmt: skip
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    verification = body.get("verification") if verb == "select" else None
    if verification:
        counts = verification["counts"]
        if counts["failed"] or (args.strict and counts["unverified"]):
            raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"query": cmd_query}

__all__ = ["COMMANDS", "add_query_parser", "cmd_query"]
