"""``tine transcripts cluster|label|flags`` (0.74): transcript analysis at corpus scale.

``cluster [--corpus FILE.jsonl]... [--k N] [--seed S]`` clusters the
repository's runs (or a JSONL corpus) with seeded k-means over the
``opentine.tfidf-hash/1`` embedding (:mod:`opentine._transcript_cluster`).
``label LABEL (--run RUN... | --cluster ID | --like RUN --top N) --key KEY``
signs and holds a behaviour flag (:mod:`opentine._transcript_flags`) with a
pinned scorer or curator key. ``flags [--label L] [--run RUN] [--like RUN]``
lists flags with their verification and, with ``--like``, the runs most like
one run. See docs/TRANSCRIPT_FLAGS.md.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-transcripts/1"


def add_transcripts_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("transcripts", help="Cluster, label and flag transcripts")
    verbs = parser.add_subparsers(dest="transcripts_command", required=True)
    cluster = verbs.add_parser("cluster", help="Seeded clustering of runs or a JSONL corpus")
    cluster.add_argument("--corpus", action="append", default=[], metavar="FILE.jsonl",
                         help="Analyse {id, text} lines, not the runs")  # fmt: skip
    label = verbs.add_parser("label", help="Sign and hold a behaviour flag")
    label.add_argument("label", metavar="LABEL", help="reward-hacking, test-deletion, ...")
    label.add_argument("--run", action="append", default=[], metavar="RUN", help="Evidence run")
    label.add_argument("--cluster", metavar="ID", help="The cluster (tc-...) it was found in")
    label.add_argument("--note", default="", metavar="TEXT", help="What the labeller saw")
    label.add_argument("--key", required=True, metavar="KEY", help="A scorer or curator key")
    label.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    flags = verbs.add_parser("flags", help="Behaviour flags and runs like a run")
    flags.add_argument("--label", metavar="LABEL", help="Only this label")
    flags.add_argument("--run", metavar="RUN", help="Only flags naming this run")
    for verb in (cluster, label):
        verb.add_argument("--k", type=int, metavar="N", help="Clusters (default sqrt(n/2))")
        verb.add_argument("--seed", type=int, default=0, metavar="S", help="Seed (default 0)")
    for verb in (label, flags):
        verb.add_argument("--like", metavar="RUN", help="Also take the runs most like this one")
        verb.add_argument("--top", type=int, default=50, metavar="N", help="With --like (50)")
    for verb in (cluster, label, flags):
        verb.add_argument("--backend", metavar="MODULE:ATTR",
                          help="A pinned local model with a weights_digest")  # fmt: skip
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _space(args: argparse.Namespace, repo: Any) -> tuple[Any, dict[str, Any]]:
    from opentine import _transcript_corpus as corpus
    from opentine._transcript_embed import Space, load_model

    if getattr(args, "corpus", None):
        texts, _ = corpus.from_files(args.corpus)
        source = "files"
    else:
        texts, source = corpus.from_repo(repo), "repo"
    space = Space(texts, model=load_model(args.backend))
    return space, {"source": source, "count": len(space.ids), "digest": space.corpus_digest}


def _run(repo: Any, value: str) -> str:
    from opentine.repository.ops import resolve_target

    try:
        return resolve_target(repo, value)
    except KeyError:
        raise KeyError(f"cannot resolve {value}: no such ref or run") from None


def _cluster(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine._transcript_cluster import kmeans
    from opentine._transcript_flags import flags

    space, source = _space(args, repo)
    found = kmeans(space, args.k, args.seed)
    labelled: dict[str, list[str]] = {}
    for row in flags(repo) if repo is not None else []:
        if row["verification"] == "verified":
            for run in row["evidence"] or []:
                labelled.setdefault(run, []).append(row["label"])
    for c in found["clusters"]:
        counts: dict[str, int] = {}
        for run in c["members"]:
            for name in set(labelled.get(run, [])):
                counts[name] = counts.get(name, 0) + 1
        c["flags"] = dict(sorted(counts.items()))
    lines = [
        f"{c['id']} {c['size']} run(s), exemplar {c['exemplar']}"
        + (f", flagged {c['flags']}" if c["flags"] else "")
        for c in found["clusters"]
    ]
    return {"backend": space.backend(), "corpus": source, **found}, lines or ["no transcripts"]


def _label(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _transcript_flags as tf
    from opentine._key_hygiene import ed25519_private
    from opentine._promote import _now
    from opentine._transcript_cluster import kmeans, similar

    evidence = [_run(repo, r) for r in args.run]
    backend = None
    if args.cluster or args.like:
        space, _ = _space(args, repo)
        backend = {k: v for k, v in space.backend().items() if k != "dim"}
        if args.cluster:
            match = [c for c in kmeans(space, args.k, args.seed)["clusters"]
                     if c["id"] == args.cluster]  # fmt: skip
            if not match:
                raise ValueError(f"no cluster {args.cluster} at this seed and k")
            outside = [r for r in evidence if r not in match[0]["members"]]
            if outside:
                raise ValueError(f"{outside[0]} is not a member of {args.cluster}")
            evidence = evidence or match[0]["members"]
        if args.like:
            like = _run(repo, args.like)
            evidence += [like, *(r["run"] for r in similar(space, [like], args.top))]
    if not evidence:
        raise ValueError("label needs evidence: --run, --cluster or --like")
    claim = {"label": args.label, "evidence": evidence, "cluster": args.cluster,
             "backend": backend, "note": args.note, "labelled_at": args.at or _now()}  # fmt: skip
    oid = tf.record(repo, claim, ed25519_private(args.key))
    count = len(set(evidence))
    return {"record": oid, "label": args.label, "evidence": sorted(set(evidence))}, [
        f"flagged {args.label} on {count} run(s): {oid}"]  # fmt: skip


def _flags(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine._transcript_flags import flags

    run = _run(repo, args.run) if args.run else None
    rows = flags(repo, label=args.label, run=run)
    lines = [f"{r['label']} {r['verification']} {len(r['evidence'] or [])} run(s) {r['record']}"
             for r in rows] or ["no transcript flags"]  # fmt: skip
    body: dict[str, Any] = {"flags": rows}
    if args.like:
        from opentine._transcript_cluster import similar

        space, _ = _space(args, repo)
        body["like"] = _run(repo, args.like)
        body["backend"] = space.backend()
        body["similar"] = similar(space, [body["like"]], args.top)
        lines += [f"like {r['run']} {r['score']}" for r in body["similar"]]
    return body, lines


def cmd_transcripts(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine.repo import Repo

    verb = args.transcripts_command
    handler = {"cluster": _cluster, "label": _label, "flags": _flags}[verb]
    try:
        repo = None if verb == "cluster" and args.corpus else Repo.open(args.repo)
        body, lines = handler(args, repo)
    except (OSError, ValueError, KeyError, PermissionError) as exc:
        raise error(exc, prefix=f"transcripts {verb}: ") from exc
    if args.json:
        emit({"command": f"transcripts {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"transcripts": cmd_transcripts}

__all__ = ["COMMANDS", "SCHEMA", "add_transcripts_parser", "cmd_transcripts"]
