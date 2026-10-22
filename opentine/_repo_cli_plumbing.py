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
from opentine._cli_git_sync import (
    configured_remotes,
    emit_all,
    fetch_one,
    push_hook,
    resolve_remote,
)
from opentine._repo_cli_json import (
    emit_context,
    emit_repo_diff,
    emit_repo_log,
    emit_repo_search,
    emit_repo_show,
)
from opentine._repo_cli_migrate import migration_keys
from opentine._repo_cli_query_render import render_diff, render_search
from opentine._repo_cli_render import render_context, render_log, render_repo_show
from opentine._repo_cli_token import MAX_TOKEN_FILE_BYTES, _token  # noqa: F401
from opentine.repo import Repo

# The engine's own ref-or-oid resolver, imported rather than re-implemented: the
# ids ``repo-diff --json`` reports must be the objects semantic_diff compared.
from opentine.repository.ops import resolve_target
from opentine.repository.store import _atomic_bytes


#: A bearer token file is one line; anything larger is not a token.
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
        token=_token(args),
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


def _resolve_run(repo: Repo, value: str) -> str:
    """Resolve one side of a diff, naming what could not be found.

    ``resolve_target`` signals "not here" with ``KeyError(<the name>)``, which the
    repo error envelope would print as ``tine repo-diff: heads/nope`` and nothing else.
    """
    try:
        return resolve_target(repo, value)
    except KeyError:
        message = f"cannot resolve {value}: no such ref or object in {repo.path}"
        raise KeyError(message) from None


def cmd_repo_diff(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    # Resolved here, then diffed by oid: semantic_diff resolves its own arguments,
    # so passing the oids removes any chance the ids reported disagree with the
    # objects compared, and a ref moving mid-command cannot split the two reads.
    left_id, right_id = _resolve_run(repo, args.left), _resolve_run(repo, args.right)
    diff = repo.diff(left_id, right_id)
    # git-diff semantics: identical means no event-level divergence. Summary
    # numbers are derived from those events, so they cannot differ on their own.
    identical = not (diff.only_left or diff.only_right or diff.changed)
    if getattr(args, "json", False):
        emit_repo_diff(repo.path, args.left, args.right, left_id, right_id, diff, identical)
    else:
        render_diff(console, left_id, right_id, diff)
    # Only --exit-code may make a successful diff non-zero, and only ever with 1:
    # argparse owns 2 for a usage error, so a caller can tell the two apart.
    if getattr(args, "exit_code", False) and not identical:
        raise SystemExit(1)


def cmd_repo_search(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    successful_only = not args.include_unsuccessful
    results = repo.search(
        args.query,
        successful_only=successful_only,
        min_score=args.min_score,
        model=args.model,
        limit=args.limit,
        signed_only=args.signed_only,
    )
    if getattr(args, "json", False):
        emit_repo_search(
            repo.path,
            args.query,
            results,
            successful_only=successful_only,
            limit=args.limit,
            min_score=args.min_score,
            model=args.model,
            signed_only=args.signed_only,
        )
        return
    render_search(console, args.query, results)


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
    keys = migration_keys(args)  # the source's signature, when a key flag asks for it
    result = repo.migrate_v2(args.source, ref=args.ref, strict=not args.allow_unverified, **keys)
    print(json.dumps(asdict(result), indent=2))


def cmd_fetch(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    # A configured remote name resolves to its URL; --all fetches every one.
    names = configured_remotes(repo) if getattr(args, "all", False) else [args.remote]
    if not names:
        raise ValueError("no remotes configured (see `tine remote add`)")
    if getattr(args, "all", False):
        emit_all([fetch_one(repo, args, name, _token)[1] for name in names])
        return
    result = fetch_one(repo, args, names[0], _token)[1]
    print(json.dumps(asdict(result), indent=2))


def cmd_push(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    tracking = resolve_remote(repo, args)
    # --all pushes every heads/* ref under its own name; otherwise the one --ref.
    refs = (
        sorted(name for name in repo.list_refs() if name.startswith("heads/"))
        if getattr(args, "all", False)
        else [args.ref]
    )
    results = []
    for ref in refs:
        push_hook(repo, tracking, ref)
        result = repo.push(
            args.remote,
            tenant=args.tenant,
            token=_token(args),
            ref=ref,
            remote_ref=None if getattr(args, "all", False) else args.remote_ref,
            allow_insecure=args.allow_insecure,
            force=getattr(args, "force", False),
        )
        results.append(result)
    if getattr(args, "all", False):
        emit_all(results)
        return
    print(json.dumps(asdict(result), indent=2))
