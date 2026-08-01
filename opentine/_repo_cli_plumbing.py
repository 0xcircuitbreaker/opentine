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
from opentine._repo_cli_json import emit_context, emit_repo_log, emit_repo_show
from opentine._repo_cli_render import render_context, render_log, render_repo_show
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
    entries = repo.log(args.ref, limit=args.limit)
    if getattr(args, "json", False):
        emit_repo_log(repo.path, args.ref, entries)
        return
    render_log(console, entries)


def cmd_repo_show(args: argparse.Namespace, console) -> None:
    # load_run resolves a ref or a run oid itself, and refuses a run whose events a
    # shallow fetch cut away; that refusal reaches the operator through cmd_repo's
    # envelope as "tine repo-show: … deepen the fetch", never as a traceback.
    repo = Repo.open(args.repo)
    try:
        run = repo.load_run(args.ref)
    except KeyError as exc:
        # load_run signals "not here" with KeyError(<the id it could not find>), so
        # the bare envelope printed "tine repo-show: heads/nope" and nothing else.
        missing = exc.args[0] if exc.args else args.ref
        raise KeyError(f"cannot load {missing}: no such ref or object in {args.repo}") from None
    oid = str(getattr(run, "_v3_run_id", "") or "")
    if getattr(args, "json", False):
        emit_repo_show(repo.path, args.ref, run, oid)
        return
    render_repo_show(console, run, oid)


def cmd_context(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    entries = repo.context_slice(args.event_id, depth=args.depth)
    if getattr(args, "json", False):
        emit_context(repo.path, args.event_id, args.depth, entries)
        return
    render_context(console, args.event_id, entries)


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
