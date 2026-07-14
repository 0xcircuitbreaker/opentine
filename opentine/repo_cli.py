"""CLI commands for v3 repositories, packs, migration, and remotes."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from opentine.repo import Repo
from opentine.repository.client import clone
from opentine.repository.store import _atomic_bytes


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


def cmd_repo(args: argparse.Namespace, console) -> None:
    command = args.command
    if command == "init":
        repo = Repo.init(args.path, bare=args.bare)
        console.print(f"Initialized OpenTine repository in {repo.path}")
        return
    if command == "clone":
        repo = clone(
            args.remote,
            args.path,
            tenant=args.tenant,
            token=args.token,
            ref=args.ref,
            depth=args.depth,
            allow_insecure=args.allow_insecure,
        )
        console.print(f"Cloned into {repo.path}")
        return
    repo = Repo.open(args.repo)
    if command == "fsck":
        result = repo.fsck(deep=not args.shallow)
        print(json.dumps(asdict(result), indent=2))
        if not result.ok:
            raise SystemExit(1)
    elif command == "repo-log":
        for entry in repo.log(args.ref, limit=args.limit):
            console.print(f"{entry.oid} {entry.payload.get('kind', entry.object_type)}")
    elif command == "object":
        inspected = repo.inspect(args.object_id, resolve_blobs=args.resolve_blobs)
        print(json.dumps(inspected, indent=2))
    elif command == "pack":
        data = repo.pack(args.object_ids or None)
        _atomic_bytes(Path(args.output), data)
        console.print(f"Wrote {len(data)} bytes to {args.output}")
    elif command == "migrate-v3":
        result = repo.migrate_v2(args.source, ref=args.ref, strict=not args.allow_unverified)
        print(json.dumps(asdict(result), indent=2))
    elif command == "fetch":
        result = repo.fetch(
            args.remote,
            tenant=args.tenant,
            token=args.token,
            ref=args.ref,
            depth=args.depth,
            allow_insecure=args.allow_insecure,
        )
        print(json.dumps(asdict(result), indent=2))
    elif command == "push":
        result = repo.push(
            args.remote,
            tenant=args.tenant,
            token=args.token,
            ref=args.ref,
            remote_ref=args.remote_ref,
            allow_insecure=args.allow_insecure,
        )
        print(json.dumps(asdict(result), indent=2))
