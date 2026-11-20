"""``tine transcripts index|search|similar`` (0.74, release 0.73.0).

``index [--rebuild] [--backend SPEC] [--weights-digest D] [--step-bytes N]
[--max-bytes N] [--workers N]`` reports or rebuilds the derived transcript
index (:mod:`opentine._transcript_index`). ``search TEXT`` and ``similar RUN``
("find all trajectories like this one") return the ``-k`` nearest runs by
cosine similarity. Both build the index when it is missing; a stale index
still answers, marked ``stale`` with the reasons (``--refresh`` rebuilds it
first). The backend and caps come from the index unless given; a model
backend is reloaded only when its weights still match the recorded digest.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-transcripts/1"
VERBS = ("index", "search", "similar")


def add_transcripts_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "transcripts", help="Embedding search over run transcripts (derived index)"
    )
    parser.add_argument("verb", choices=VERBS)
    parser.add_argument("target", nargs="?", metavar="TEXT|RUN", help="search text or a run")
    parser.add_argument("--repo", default=".", metavar="PATH", help="Repository")
    parser.add_argument("-k", type=int, default=10, metavar="N", help="At most N hits")
    parser.add_argument("--approx", action="store_true", help="LSH candidates, then exact scores")
    parser.add_argument("--refresh", action="store_true", help="Rebuild a stale index first")
    parser.add_argument("--rebuild", action="store_true", help="index: rebuild it now")
    parser.add_argument("--backend", metavar="SPEC", help="hash (default) or MODULE:ATTR")
    parser.add_argument("--weights-digest", metavar="sha256:HEX",
                        help="Refuse model weights with another digest")  # fmt: skip
    parser.add_argument("--step-bytes", type=int, metavar="N", help="Cap per input/output")
    parser.add_argument("--max-bytes", type=int, metavar="N", help="Cap per transcript")
    parser.add_argument("--workers", type=int, metavar="N", help="index: worker processes")
    parser.add_argument("--json", action="store_true", help="Print a JSON object")


def _setup(args: argparse.Namespace, repo: Any) -> tuple[Any, Any, dict[str, str]]:
    from opentine import _transcript_embed as te
    from opentine import _transcript_index as ti
    from opentine._transcript_text import Caps

    path = ti.index_path(Path(repo.path))
    meta = ti.read_meta(path) if path.is_file() else {}
    recorded = json.loads(meta.get("backend", "{}"))
    caps = json.loads(meta.get("caps", "{}"))
    spec, pin = args.backend, args.weights_digest
    if spec is None and recorded.get("adapter"):
        spec, pin = recorded["adapter"], pin or recorded.get("weights_digest")
    backend = te.load(spec, pin)
    caps = Caps(args.step_bytes or caps.get("step_bytes", 2048),
                args.max_bytes or caps.get("max_bytes", 32768))  # fmt: skip
    return backend, caps, meta


def _index(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _transcript_embed as te
    from opentine import _transcript_index as ti

    backend, caps, _ = _setup(args, repo)
    built = ti.build(repo, backend, caps, workers=args.workers) if args.rebuild else None
    state = ti.staleness(repo, backend, caps)
    body = {"index": ti.index_path(Path(repo.path)).as_posix(), "authority": ti.AUTHORITY,
            "rebuilt": built is not None, **state, "backend": backend.description(),
            "backend_digest": te.backend_digest(backend), "caps": caps.as_dict(),
            "counts": {k: built[k] for k in ("runs", "embedded", "reused", "truncated")}
            if built else None}  # fmt: skip
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
    index, info = ti.load(ti.index_path(Path(repo.path)))
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
        if run in index.runs:
            vector = index.vectors[index.runs.index(run)]
        else:
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
    from opentine.repo import Repo

    try:
        repo = Repo.open(args.repo)
        body, lines = (_index if args.verb == "index" else _find)(args, repo)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"transcripts {args.verb}: ") from exc
    if args.json:
        emit({"command": f"transcripts {args.verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"transcripts": cmd_transcripts}

__all__ = ["COMMANDS", "SCHEMA", "add_transcripts_parser", "cmd_transcripts"]
