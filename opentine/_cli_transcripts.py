"""``tine transcripts index|search|similar`` (0.74); ``cluster|label|flags`` live in
:mod:`opentine._cli_transcripts_flags`.

``index [--rebuild] [--backend SPEC] [--weights-digest D] [--step-bytes N]
[--max-bytes N] [--workers N]`` reports or rebuilds the derived transcript
index (:mod:`opentine._transcript_index`). ``search TEXT`` and ``similar RUN``
("find all trajectories like this one") return the ``-k`` nearest runs by
cosine similarity. Both build the index when it is missing; a stale index
still answers, marked ``stale`` with the reasons (``--refresh`` brings it up
to date first, reusing rows; ``index --rebuild`` embeds every run again).

The index file is writable by anything that can write the store, so nothing
in it is trusted: the backend and caps are the defaults unless given on the
command line (an adapter named in the index is never imported), rows for runs
not in the repository and vectors that are not finite unit vectors are left
out and make the index stale, and ``similar RUN`` embeds the query run from
its objects. ``index --verify`` lists rows that disagree with the objects.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-transcripts/1"
VERBS = ("index", "search", "similar", "cluster", "label", "flags")


def add_transcripts_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._cli_transcripts_flags import add_flag_verbs

    parser = subparsers.add_parser("transcripts", help="Search, cluster and flag run transcripts")
    verbs = parser.add_subparsers(dest="verb", required=True)
    for name, text in (
        ("index", "Report or rebuild the derived transcript index"),
        ("search", "Runs nearest a text"),
        ("similar", "Runs nearest a run"),
    ):
        _index_options(verbs.add_parser(name, help=text), name)
    add_flag_verbs(verbs)  # cluster, label, flags


def _index_options(parser: argparse.ArgumentParser, verb: str) -> None:
    if verb != "index":
        parser.add_argument("target", nargs="?", metavar="TEXT|RUN", help="search text or a run")
        parser.add_argument("-k", type=int, default=10, metavar="N", help="At most N hits")
        parser.add_argument("--approx", action="store_true",
                            help="LSH candidates, then exact scores")  # fmt: skip
    parser.add_argument("--repo", default=".", metavar="PATH", help="Repository")
    parser.add_argument("--refresh", action="store_true", help="Rebuild a stale index first")
    if verb == "index":
        parser.add_argument("--rebuild", action="store_true", help="Embed every run again")
        parser.add_argument("--verify", action="store_true",
                            help="List rows that disagree with the objects")  # fmt: skip
    parser.add_argument("--backend", metavar="SPEC", help="hash (default) or MODULE:ATTR")
    parser.add_argument("--weights-digest", metavar="sha256:HEX",
                        help="Refuse model weights with another digest")  # fmt: skip
    parser.add_argument("--step-bytes", type=int, metavar="N", help="Cap per input/output")
    parser.add_argument("--max-bytes", type=int, metavar="N", help="Cap per transcript")
    parser.add_argument("--workers", type=int, metavar="N", help="Worker processes")
    parser.add_argument("--json", action="store_true", help="Print a JSON object")


def _setup(args: argparse.Namespace, repo: Any) -> tuple[Any, Any, dict[str, str]]:
    from opentine import _transcript_embed as te
    from opentine import _transcript_index as ti
    from opentine._transcript_text import MAX_BYTES, STEP_BYTES, Caps

    path = ti.index_path(Path(repo.path))
    meta = ti.read_meta(path) if path.is_file() else {}
    backend = te.load(args.backend, args.weights_digest)
    caps = Caps(args.step_bytes or STEP_BYTES, args.max_bytes or MAX_BYTES)
    return backend, caps, meta


def _flag(state: dict[str, Any], why: str) -> dict[str, Any]:
    return {**state, "stale": True, "reasons": [*state["reasons"], why]}


def _index(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _transcript_embed as te
    from opentine import _transcript_index as ti

    backend, caps, _ = _setup(args, repo)
    built = None
    if args.rebuild or args.refresh:
        built = ti.build(repo, backend, caps, workers=args.workers, reuse=not args.rebuild)
    state = ti.staleness(repo, backend, caps)
    path = ti.index_path(Path(repo.path))
    disagreeing = (
        ti.verify_rows(repo, path, backend, caps) if args.verify and state["exists"] else None
    )
    if disagreeing:
        state = _flag(state, f"{len(disagreeing)} rows disagree with the objects")
    body = {"index": ti.index_path(Path(repo.path)).as_posix(), "authority": ti.AUTHORITY,
            "rebuilt": built is not None, **state, "backend": backend.description(),
            "backend_digest": te.backend_digest(backend), "caps": caps.as_dict(),
            "counts": {k: built[k] for k in ("runs", "embedded", "reused", "truncated")}
            if built else None, "disagreeing": disagreeing}  # fmt: skip
    lines = [f"{'rebuilt' if built else 'index'} {body['index']} ({ti.AUTHORITY})",
             f"  backend {body['backend']['name']} {body['backend_digest']}"]  # fmt: skip
    lines += [f"  {k}: {v}" for k, v in sorted((body["counts"] or {}).items())]
    lines += [f"stale: {why}" for why in state["reasons"]] or ["up to date"]
    return body, lines


def _find(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    import hashlib

    from opentine import _transcript_embed as te
    from opentine import _transcript_index as ti
    from opentine._transcript_text import transcript

    if not args.target:
        raise ValueError(f"{args.verb} needs {'TEXT' if args.verb == 'search' else 'a RUN'}")
    if args.k < 1:
        raise ValueError("-k is positive")
    backend, caps, _ = _setup(args, repo)
    state = ti.staleness(repo, backend, caps)
    if not state["exists"] or (state["stale"] and args.refresh):
        ti.build(repo, backend, caps, workers=args.workers)
        state = ti.staleness(repo, backend, caps)
    if "the embedding backend differs (backend digest)" in state["reasons"]:
        raise ValueError("the index was built with another backend; rebuild it or pass --backend")
    index, info, rejected = ti.load(ti.index_path(Path(repo.path)), ti.run_oids(repo),
                                    backend.dim)  # fmt: skip
    if rejected:
        state = _flag(state, f"{rejected} rows left out (unknown run or invalid vector)")
    exclude = None
    if args.verb == "search":
        vector = backend.embed([args.target])[0]
        query = {"text_sha256": hashlib.sha256(args.target.encode("utf-8")).hexdigest()}
    else:
        from opentine.repository.ops import resolve_target

        try:
            run = resolve_target(repo, args.target)
        except KeyError:
            raise KeyError(f"cannot resolve {args.target}: no such ref or object") from None
        if not run.startswith("run:"):
            raise ValueError(f"{args.target} is not a run")
        exclude, query = run, {"run": run}
        vector = backend.embed([transcript(repo, run, caps).text])[0]
    found = index.search(vector, args.k, exclude=exclude, approx=args.approx)
    hits = [{**h, **info[h["run"]]} for h in found["hits"]]
    body = {"authority": ti.AUTHORITY, "stale": state["stale"], "stale_reasons": state["reasons"],
            "backend_digest": te.backend_digest(backend), "query": query, "k": args.k,
            "method": found["method"], "candidates": found["candidates"],
            "indexed": len(index), "hits": hits}  # fmt: skip
    lines = ["-- derived index, non-authoritative: rebuildable from the repository"]
    lines += ["-- stale: " + "; ".join(state["reasons"])] if state["stale"] else []
    lines += [f"{h['score']:.4f}\t{h['run']}\t{h['steps']} steps" for h in hits]
    return body, lines


def cmd_transcripts(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._cli_transcripts_flags import HANDLERS
    from opentine.repo import Repo

    handler = HANDLERS.get(args.verb) or (_index if args.verb == "index" else _find)
    try:
        flagless = args.verb == "cluster" and args.corpus
        repo = None if flagless else Repo.open(args.repo)
        body, lines = handler(args, repo)
    except (OSError, ValueError, KeyError, PermissionError) as exc:
        raise error(exc, prefix=f"transcripts {args.verb}: ") from exc
    if args.json:
        emit({"command": f"transcripts {args.verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"transcripts": cmd_transcripts}

__all__ = ["COMMANDS", "SCHEMA", "add_transcripts_parser", "cmd_transcripts"]
