"""One handler per v3 repository subcommand, moved verbatim out of repo_cli.

The five ``print(json.dumps(..., indent=2))`` sites below are the documented
machine-readable surface of ``fsck``, ``object``, ``migrate-v3``, ``fetch``, and
``push``: bare stdout, two-space indent, no Rich markup. Their exact bytes are
pinned by tests/test_repo_cli_routing.py — changing them is a breaking change.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from opentine._cli_common import _terminal
from opentine.repo import Repo
from opentine.repository.store import _atomic_bytes


def cmd_init(args: argparse.Namespace, console) -> None:
    repo = Repo.init(args.path, bare=args.bare)
    console.print(f"Initialized OpenTine repository in {_terminal(repo.path)}")


def cmd_clone(args: argparse.Namespace, console) -> None:
    # ``clone`` is resolved through opentine.repo_cli at call time so the long-standing
    # patch site (tests monkeypatch opentine.repo_cli.clone) keeps biting after the split.
    from opentine import repo_cli

    repo = repo_cli.clone(
        args.remote,
        args.path,
        tenant=args.tenant,
        token=args.token,
        ref=args.ref,
        depth=args.depth,
        allow_insecure=args.allow_insecure,
    )
    console.print(f"Cloned into {_terminal(repo.path)}")


def cmd_fsck(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    result = repo.fsck(deep=not args.shallow)
    print(json.dumps(asdict(result), indent=2))
    if not result.ok:
        raise SystemExit(1)


def cmd_repo_log(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    for entry in repo.log(args.ref, limit=args.limit):
        kind = (
            entry.payload.get("kind", entry.object_type)
            if isinstance(entry.payload, dict)
            else entry.object_type
        )
        console.print(f"{_terminal(entry.oid)} {_terminal(kind)}")


def cmd_object(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    inspected = repo.inspect(args.object_id, resolve_blobs=args.resolve_blobs)
    print(json.dumps(inspected, indent=2))


def cmd_pack(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    data = repo.pack(args.object_ids or None)
    _atomic_bytes(Path(args.output), data)
    console.print(f"Wrote {len(data)} bytes to {_terminal(args.output)}")


def cmd_migrate_v3(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    result = repo.migrate_v2(args.source, ref=args.ref, strict=not args.allow_unverified)
    print(json.dumps(asdict(result), indent=2))


def cmd_fetch(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    result = repo.fetch(
        args.remote,
        tenant=args.tenant,
        token=args.token,
        ref=args.ref,
        depth=args.depth,
        allow_insecure=args.allow_insecure,
    )
    print(json.dumps(asdict(result), indent=2))


def cmd_push(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    result = repo.push(
        args.remote,
        tenant=args.tenant,
        token=args.token,
        ref=args.ref,
        remote_ref=args.remote_ref,
        allow_insecure=args.allow_insecure,
    )
    print(json.dumps(asdict(result), indent=2))
