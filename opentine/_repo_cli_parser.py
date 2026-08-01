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

    # --json is purely additive on the read verbs: without it each renders as before.
    for readable in (log, show, context):
        readable.add_argument(
            "--json", action="store_true", help="Emit a machine-readable JSON object instead"
        )

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


def _remote_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("remote")
    parser.add_argument("--tenant")
    parser.add_argument("--token")
    parser.add_argument("--allow-insecure", action="store_true")
