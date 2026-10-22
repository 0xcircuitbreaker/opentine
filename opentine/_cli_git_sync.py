"""Named remotes for fetch/push, ``--all``, ``tine pull``, and the transfer hooks.

``tine remote add origin https://…`` stores the URL (and, optionally, a tenant
and a token *file path*) in the repository's porcelain settings, so ``tine fetch
origin`` and ``tine push origin`` work like git. A literal URL still works as
before. Remote-tracking refs land under ``remotes/<name>/…`` -- the configured
name, or ``origin`` for a bare URL, as before.

``tine pull`` is fetch plus a **fast-forward only** update of the local ref: the
local run must be the remote run or one of the runs it was forked from (its
``forked_from`` chain). Anything else is divergence, and pull refuses rather
than overwrite history -- the operator resolves it with ``tine reset``.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine import _hooks
from opentine import _porcelain_config as porcelain
from opentine._cli_common import _terminal
from opentine._cli_json import emit
from opentine._repo_cli_render import _short_oid
from opentine._repo_cli_token import _token
from opentine.repo import Repo
from opentine.repository._refs import normalize_ref

MAX_ANCESTRY = 10_000


def resolve_remote(repo: Repo, args: argparse.Namespace, name: str | None = None) -> str:
    """Point *args* at the URL a remote name stands for; returns the tracking name."""
    value = name if name is not None else args.remote
    if not value:
        raise ValueError("name a remote (or a URL), or pass --all")
    if "://" in value:
        args.remote = value
        return "origin"
    entry = porcelain.remote(repo.path, value)
    if entry is None:
        raise KeyError(f"no such remote: {value} (see `tine remote ls`)")
    args.remote = entry["url"]
    if not getattr(args, "tenant", None) and entry.get("tenant"):
        args.tenant = entry["tenant"]
    if not getattr(args, "token", None) and not getattr(args, "token_file", None):
        args.token_file = entry.get("token_file")
    return value


def configured_remotes(repo: Repo) -> list[str]:
    return sorted(porcelain.load(repo.path)["remotes"])


def is_ancestor(repo: Repo, older: str, newer: str) -> bool:
    """Whether run *older* is *newer* or on *newer*'s ``forked_from`` chain."""
    current: str | None = newer
    for _ in range(MAX_ANCESTRY):
        if current is None:
            return False
        if current == older:
            return True
        if not repo.has(current):
            return False
        payload: dict[str, Any] = repo.get(current).payload()
        parent = payload.get("forked_from")
        current = parent if isinstance(parent, str) else None
    return False


def fetch_one(repo: Repo, args: argparse.Namespace, name: str | None, token) -> tuple[str, Any]:
    tracking = resolve_remote(repo, args, name)
    result = repo.fetch(
        args.remote,
        tenant=args.tenant,
        token=token(args),
        ref=args.ref,
        depth=getattr(args, "depth", None),
        allow_insecure=args.allow_insecure,
        adopt_annotations=getattr(args, "adopt_annotations", False),
        remote_name=tracking,
    )
    hook = _hooks.run_hook(
        repo.path,
        "post-fetch",
        {"OPENTINE_REMOTE": tracking, "OPENTINE_REF": args.ref},
    )
    if hook.ran and not hook.ok:
        print(f"tine: post-fetch hook failed: {hook.output.strip()[-300:]}")
    return tracking, result


def emit_all(results: list[Any]) -> None:
    """``--all``: one JSON array of the per-remote (or per-ref) transfer results."""
    import json
    from dataclasses import asdict

    print(json.dumps([asdict(result) for result in results], indent=2))


def push_hook(repo: Repo, tracking: str, ref: str) -> None:
    oid = repo.read_ref(ref) or ""
    _hooks.require(
        repo.path,
        "pre-push",
        {"OPENTINE_REMOTE": tracking, "OPENTINE_REF": ref, "OPENTINE_OID": oid},
    )


def cmd_pull(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    tracking, _ = fetch_one(repo, args, args.remote or "origin", _token)
    ref = normalize_ref(args.ref)
    tracking_ref = f"remotes/{tracking}/{ref.removeprefix('heads/')}"
    remote_oid = repo.read_ref(tracking_ref)
    if remote_oid is None:
        raise KeyError(f"fetch did not produce {tracking_ref}")
    local = repo.read_ref(ref)
    if local == remote_oid:
        state = "up-to-date"
    elif local is None or is_ancestor(repo, local, remote_oid):
        repo.update_ref(ref, remote_oid, expected_old=local, actor=f"pull {tracking}")
        state = "fast-forward"
    else:
        raise ValueError(
            f"{ref} and {tracking_ref} have diverged; pull only fast-forwards. "
            f"Inspect with `tine log --graph --all`, then `tine reset {ref} <run>`"
        )
    if getattr(args, "json", False):
        emit(
            {
                "command": "pull",
                "ref": ref,
                "remote": tracking,
                "state": state,
                "run_id": remote_oid,
            }
        )
        return
    console.print(f"{_terminal(ref)}: {state} -> {_short_oid(remote_oid)}")


__all__ = [
    "cmd_pull",
    "configured_remotes",
    "emit_all",
    "fetch_one",
    "is_ancestor",
    "push_hook",
    "resolve_remote",
]
