"""Argparse wiring for the v3 repository subcommands, kept free of handlers."""

from __future__ import annotations

import argparse


def add_repo_parsers(subparsers: argparse._SubParsersAction) -> None:
    init = subparsers.add_parser("init", help="Initialize a v3 .tine repository")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--bare", action="store_true")

    fsck = subparsers.add_parser("fsck", help="Verify every object, ref, and causal link")
    fsck.add_argument("--repo", default=".")
    fsck.add_argument("--shallow", action="store_true", help="Skip linked-object checks")

    log = subparsers.add_parser("repo-log", help="Show the v3 event ancestry")
    log.add_argument("ref", nargs="?", default="heads/main")
    log.add_argument("--repo", default=".")
    log.add_argument("--limit", type=int)

    show = subparsers.add_parser("repo-show", help="Render a v3 run from a ref or run oid")
    show.add_argument("ref", help="A ref name such as heads/main, or a run:sha256:… oid")
    show.add_argument("--repo", default=".")

    context = subparsers.add_parser("context", help="Show only an event's causal ancestors")
    context.add_argument("event_id", help="An event:sha256:… oid")
    context.add_argument("--repo", default=".")
    # 8 is the MCP context_slice default; the two surfaces must agree, because an
    # operator reproducing what an agent saw types this command.
    context.add_argument("--depth", type=int, default=8)

    diff = subparsers.add_parser("repo-diff", help="Semantically diff two v3 runs")
    for side in ("left", "right"):
        diff.add_argument(side, help="A ref name such as heads/main, or a run:sha256:… oid")
    diff.add_argument("--repo", default=".")
    diff.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit 1 when the runs differ and 0 when they are identical, like git diff",
    )

    search = subparsers.add_parser(
        "repo-search",
        help="Search completed v3 runs (scans up to 100,000 objects; bound output with --limit)",
    )
    search.add_argument("query", nargs="?", default="", help="Text matched against run content")
    search.add_argument("--repo", default=".")
    # successful_only=True and limit=20 are the MCP search_runs defaults, mirrored
    # exactly: an operator reproducing what an agent searched must get its result set.
    search.add_argument(
        "--limit", type=int, default=20, help="Maximum runs returned, 1-1000 (default 20)"
    )
    search.add_argument("--min-score", type=float, help="Keep runs scoring at least this")
    search.add_argument("--model", help="Keep runs whose model ids contain this substring")
    search.add_argument(
        "--include-unsuccessful",
        action="store_true",
        help="Also return non-completed runs (the default is completed runs only)",
    )

    # --json is purely additive on the read verbs: without it each renders as before.
    for readable in (log, show, context, diff, search):
        readable.add_argument(
            "--json", action="store_true", help="Emit a machine-readable JSON object instead"
        )

    _add_write_parsers(subparsers)
    _add_porcelain_parsers(subparsers)

    inspect = subparsers.add_parser("object", help="Inspect a verified v3 object")
    inspect.add_argument("object_id")
    inspect.add_argument("--repo", default=".")
    inspect.add_argument("--resolve-blobs", action="store_true")

    pack = subparsers.add_parser("pack", help="Write a deterministic object pack")
    pack.add_argument("--repo", default=".")
    pack.add_argument("--output", required=True)
    pack.add_argument("object_ids", nargs="*")

    migration = subparsers.add_parser(
        "migrate-v3", help="Import a v2 .tine artifact into a v3 repository"
    )
    migration.add_argument("source")
    migration.add_argument("--repo", default=".")
    migration.add_argument("--ref", default="heads/main")
    migration.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Import even if the v2 source fails integrity or signature verification",
    )

    fetch = subparsers.add_parser("fetch", help="Fetch a verified pack from a remote")
    _remote_args(fetch)
    fetch.add_argument("--ref", default="heads/main")
    fetch.add_argument("--depth", type=int)
    fetch.add_argument("--repo", default=".")

    push = subparsers.add_parser("push", help="Push a pack and CAS-update a remote ref")
    _remote_args(push)
    push.add_argument("--ref", default="heads/main")
    push.add_argument("--remote-ref")
    push.add_argument("--repo", default=".")

    clone_parser = subparsers.add_parser("clone", help="Clone a remote v3 repository")
    _remote_args(clone_parser)
    clone_parser.add_argument("path")
    clone_parser.add_argument("--ref", default="heads/main")
    clone_parser.add_argument("--depth", type=int)


def _add_write_parsers(subparsers: argparse._SubParsersAction) -> None:
    """The three mutating verbs. Each takes a ref *or* a run oid as its target.

    ``promote`` deliberately has no ``--force``: ``--expected-old`` is the only way
    to move an existing promotion, so replacing a release gate always states which
    value is being replaced.
    """
    target = "A ref name such as heads/main, or a run:sha256:… oid"

    attest = subparsers.add_parser("attest", help="Attach a signed-by-label claim to a run")
    attest.add_argument("target", help=target)
    attest.add_argument("--signer", required=True, help="Self-asserted signer label")
    claim = attest.add_mutually_exclusive_group(required=True)
    claim.add_argument("--claim", help="The claim as a JSON object")
    claim.add_argument("--claim-file", help="Read the JSON object claim from this file")
    attest.add_argument(
        "--evidence",
        action="append",
        metavar="OID",
        help="An existing object id supporting the claim; repeatable",
    )

    evaluate = subparsers.add_parser("evaluate", help="Attach immutable evaluation scores to a run")
    evaluate.add_argument("target", help=target)
    evaluate.add_argument("--evaluator", required=True, help="Self-asserted evaluator label")
    evaluate.add_argument(
        "--score",
        action="append",
        required=True,
        metavar="NAME=VALUE",
        help="One finite numeric score; repeatable",
    )

    promote = subparsers.add_parser("promote", help="CAS-update a promotions/<name> release gate")
    promote.add_argument("target", help=target)
    promote.add_argument("--name", required=True, help="The promotions/<name> to point at the run")
    promote.add_argument(
        "--expected-old",
        help="The oid promotions/<name> currently holds; required to move an existing promotion",
    )

    for writable in (attest, evaluate, promote):
        writable.add_argument("--repo", default=".")
        # Emitted only after the write succeeds; a refusal stays human text + exit 1.
        writable.add_argument(
            "--json", action="store_true", help="Emit a machine-readable JSON object instead"
        )


def _add_porcelain_parsers(subparsers: argparse._SubParsersAction) -> None:
    """The two lineage verbs, prefixed because ``fork``/``resume`` are legacy v2.

    ``--ref`` is required on both and has **no default**. The MCP tools confine a
    fork's ref to ``experiments/*`` because a fork's ref update is an
    unconditional overwrite driven by untrusted run content; the CLI is an
    operator surface and is deliberately not confined, so the safety here is that
    the destination is always stated rather than inherited from a default.
    """
    target = "A ref name such as heads/main, or a run:sha256:… oid"

    fork = subparsers.add_parser(
        "repo-fork", help="Fork a v3 run from an event onto a ref (v3 twin of tine fork)"
    )
    fork.add_argument("target", help=target)
    fork.add_argument("--from-event", required=True, metavar="OID", help="An event:sha256:… oid")
    fork.add_argument("--model", help="Override the model of the forked run")
    fork.add_argument("--prompt", help="Override the prompt of the forked run")
    fork.add_argument("--policy", help="Override the policy manifest, as a JSON object")

    resume = subparsers.add_parser(
        "repo-resume", help="Resume a v3 run at its last verified tip (v3 twin of tine resume)"
    )
    resume.add_argument("target", help=target)

    for lineage in (fork, resume):
        lineage.add_argument("--repo", default=".")
        lineage.add_argument(
            "--ref", required=True, help="The ref to point at the new run; required, no default"
        )
        # Emitted only after the write succeeds; a refusal stays human text + exit 1.
        lineage.add_argument(
            "--json", action="store_true", help="Emit a machine-readable JSON object instead"
        )


def _remote_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("remote")
    parser.add_argument("--tenant")
    parser.add_argument("--token")
    parser.add_argument("--allow-insecure", action="store_true")
