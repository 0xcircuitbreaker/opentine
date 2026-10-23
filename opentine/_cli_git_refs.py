"""Git-style ref verbs over a v3 repository: remote, branch, tag, reflog, reset, config.

Every verb here is porcelain over what the store already does: refs move only by
compare-and-swap (``Repo.update_ref``), deletions take the ref's lock and leave a
reflog row (``_ref_delete``), and signed tags are ``tine-attest/1`` attestations
whose claim names the tag, verified by the same code as ``tine repo-verify``.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine import _porcelain_config as porcelain
from opentine._cli_common import _terminal
from opentine._cli_json import emit
from opentine._ref_delete import delete_ref
from opentine._repo_cli_keys import verification_keys, verification_pins
from opentine._repo_cli_render import _short_oid
from opentine._repo_cli_verify import _row
from opentine._repo_cli_write import _attest, _run_oid
from opentine.repo import Repo
from opentine.repository._reflog import read_reflog
from opentine.repository._refs import normalize_ref

PROTECTED_BRANCHES = frozenset({"heads/main"})


def _json(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "json", False))


# -- remote ---------------------------------------------------------------------


def cmd_remote(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    settings = porcelain.load(repo.path)
    remotes = settings["remotes"]
    action = args.remote_action or "ls"
    if action == "add":
        name = porcelain.check_remote_name(args.name)
        if name in remotes:
            raise ValueError(f"remote {name!r} already exists; `tine remote rm {name}` first")
        entry: dict[str, Any] = {"url": porcelain.check_url(args.url)}
        if args.tenant:
            entry["tenant"] = args.tenant
        if args.token_file:
            # Only the *path* is stored; the token is read at use time.
            entry["token_file"] = args.token_file
        remotes[name] = entry
    elif action in ("rm", "remove"):
        if remotes.pop(args.name, None) is None:
            raise KeyError(f"no such remote: {args.name}")
    elif action == "rename":
        new = porcelain.check_remote_name(args.new_name)
        if args.name not in remotes:
            raise KeyError(f"no such remote: {args.name}")
        if new in remotes:
            raise ValueError(f"remote {new!r} already exists")
        remotes[new] = remotes.pop(args.name)
    else:
        if _json(args):
            emit({"command": "remote", "repo": str(repo.path), "remotes": remotes})
            return
        for name, entry in sorted(remotes.items()):
            console.print(f"{_terminal(name)}\t{_terminal(entry['url'])}", highlight=False)
        return
    porcelain.save(repo.path, settings)
    console.print(f"remote {action}: {_terminal(args.name)}")


# -- branch -----------------------------------------------------------------------


def _branch_ref(name: str) -> str:
    name = name.removeprefix("refs/")
    return normalize_ref(
        name if "/" in name and name.split("/", 1)[0] in _SPACES else f"heads/{name}"
    )


_SPACES = frozenset({"heads", "experiments"})


def cmd_branch(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    refs = repo.list_refs()
    if args.delete:
        ref = _branch_ref(args.delete)
        if ref in PROTECTED_BRANCHES and not args.force:
            raise ValueError(f"refusing to delete {ref} without --force")
        current = refs.get(ref)
        if current is None:
            raise KeyError(f"no such branch: {ref}")
        delete_ref(repo.path, ref, current, actor="branch -d")
        console.print(f"Deleted {_terminal(ref)} (was {_short_oid(current)})")
        return
    if args.name:
        ref = _branch_ref(args.name)
        target = _run_oid(repo, args.start or "heads/main")
        current = refs.get(ref)
        if current is not None and not args.force:
            raise ValueError(f"{ref} already exists; use --force to move it")
        repo.update_ref(ref, target, expected_old=current, actor="branch")
        console.print(
            f"{'Moved' if current else 'Created'} {_terminal(ref)} -> {_short_oid(target)}"
        )
        return
    spaces = ("heads/", "experiments/", "remotes/") if args.all else ("heads/",)
    shown = {name: oid for name, oid in sorted(refs.items()) if name.startswith(spaces)}
    if _json(args):
        emit({"command": "branch", "repo": str(repo.path), "branches": shown})
        return
    for name, oid in shown.items():
        console.print(f"{_terminal(name)}\t{_short_oid(oid)}", highlight=False)


# -- tags ---------------------------------------------------------------------------


def cmd_tag_v3(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    refs = repo.list_refs()
    if args.delete:
        ref = normalize_ref(f"tags/{args.delete}")
        if ref not in refs:
            raise KeyError(f"no such tag: {args.delete}")
        delete_ref(repo.path, ref, refs[ref], actor="tag -d")
        console.print(f"Deleted tag {_terminal(args.delete)}")
        return
    if not args.name or args.list:
        tags = {name[5:]: oid for name, oid in sorted(refs.items()) if name.startswith("tags/")}
        if _json(args):
            emit({"command": "tag", "repo": str(repo.path), "tags": tags})
            return
        for name, oid in tags.items():
            console.print(f"{_terminal(name)}\t{_short_oid(oid)}", highlight=False)
        return
    ref = normalize_ref(f"tags/{args.name}")
    target = _run_oid(repo, args.target or "heads/main")
    current = refs.get(ref)
    if current is not None and not args.force:
        raise ValueError(f"tag {args.name} already exists; use --force to move it")
    attestation = None
    if args.sign:
        claim = {"kind": "tag", "tag": args.name, "run": target}
        if args.message:
            claim["message"] = args.message
        _, attestation, block = _attest(repo, args, target, claim, args.signer or "tag")
        if block is None:
            raise ValueError("-s needs a signing key (--key-file/--ed25519-key-file/--key-env)")
    repo.update_ref(ref, target, expected_old=current, actor="tag")
    if _json(args):
        emit({"command": "tag", "tag": args.name, "run_id": target, "attestation_id": attestation})
        return
    signed = " (signed)" if attestation else ""
    console.print(f"Tagged {_short_oid(target)} as {_terminal(args.name)}{signed}")


def cmd_verify_tag(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    target = repo.read_ref(normalize_ref(f"tags/{args.name}"))
    if target is None:
        raise KeyError(f"no such tag: {args.name}")
    keys, pins = verification_keys(args), verification_pins(args)
    rows = []
    for oid in repo.attestations_for(target):
        claim = repo.get(oid).payload().get("claim")
        if isinstance(claim, dict) and claim.get("kind") == "tag" and claim.get("tag") == args.name:
            if claim.get("run") == target:
                rows.append(_row(repo, oid, keys, pins))
    ok = any(row["ok"] for row in rows)
    if _json(args):
        emit({"command": "verify-tag", "tag": args.name, "run_id": target, "ok": ok, "rows": rows})
    else:
        for row in rows:
            console.print(f"{_terminal(row['state'])} {_short_oid(row['attestation_id'])}")
        console.print(f"tag {_terminal(args.name)}: {'verified' if ok else 'NOT verified'}")
    if not ok:
        raise SystemExit(1)


# -- reflog / reset / config -----------------------------------------------------------


def cmd_reflog(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    ref = normalize_ref(args.ref)
    rows = read_reflog(repo.path, ref, limit=args.limit)
    if _json(args):
        emit({"command": "reflog", "ref": ref, "entries": rows})
        return
    for index, row in enumerate(rows):
        new = _short_oid(row["new"]) if row.get("new") else "(deleted)"
        actor = _terminal(row.get("actor", ""))
        console.print(f"{ref}@{{{index}}} {new} {actor}", highlight=False)


def cmd_reset(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    ref = normalize_ref(args.ref)
    target = _run_oid(repo, args.target)
    expected = args.expect if args.expect is not None else repo.read_ref(ref)
    repo.update_ref(ref, target, expected_old=expected, actor="reset")
    console.print(f"{_terminal(ref)} -> {_short_oid(target)}")


def cmd_config(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    if args.trust:
        console.print(
            f"trusted {_terminal(porcelain.FILE_NAME)} ({porcelain.trust(repo.path)[:12]})"
        )
        return
    settings = porcelain.load(repo.path)
    config = settings["config"]
    if args.list or not args.key:
        trusted = porcelain.trusted(repo.path)
        if _json(args):
            emit({"command": "config", "config": config, "trusted": trusted})
            return
        for key, value in sorted(config.items()):
            console.print(f"{_terminal(key)}={_terminal(value)}", highlight=False)
        if config and not trusted:
            console.print("[yellow]untrusted[/]: alias.* and hooks.* are ignored")
        return
    key = porcelain.check_key(args.key)
    if args.unset:
        config.pop(key, None)
    elif args.value is None:
        if key not in config:
            raise SystemExit(1)
        console.print(_terminal(config[key]), highlight=False)
        return
    else:
        config[key] = args.value
    porcelain.save(repo.path, settings)


__all__ = [
    "cmd_branch",
    "cmd_config",
    "cmd_reflog",
    "cmd_remote",
    "cmd_reset",
    "cmd_tag_v3",
    "cmd_verify_tag",
]
