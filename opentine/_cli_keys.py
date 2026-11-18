"""``tine keys lint`` (0.58): key separation for self-improving agent loops.

``keys lint [--policy FILE] [--optimizer-key KEY]... [--strict]`` checks the
key-role policy (``.tine/key-roles.toml``, :mod:`opentine._key_roles`): exit 1
on a ``fail:`` finding (the optimizer key also holds a scorer, dataset,
verdict or approver key; a malformed policy); ``advisory:`` findings never
block unless ``--strict`` (owner decision D12). It reports ``roles: pinned``
when the roles come from an owner-signed trust bundle (0.59,
:mod:`opentine._key_roles_pin`), else ``roles: unpinned`` (or ``absent``).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error


def add_keys_parser(subparsers: argparse._SubParsersAction) -> None:
    keys = subparsers.add_parser("keys", help="Key-role checks for self-improving agent loops")
    verbs = keys.add_subparsers(dest="keys_command", required=True)
    lint = verbs.add_parser("lint", help="Refuse an optimizer key that holds evaluation keys")
    lint.add_argument("--repo", default=".", metavar="PATH", help="v3 repository")
    lint.add_argument("--policy", metavar="FILE", help="Key-role policy (.tine/key-roles.toml)")
    lint.add_argument("--optimizer-key", action="append", default=[], metavar="KEY",
                      help="Also check this candidate signing key")  # fmt: skip
    lint.add_argument("--strict", action="store_true", help="Advisory findings block too")
    lint.add_argument("--json", action="store_true", help="Machine-readable output")


def _policy(args: argparse.Namespace) -> tuple[Path, dict | None, str]:
    from opentine import _key_roles
    from opentine._key_roles_pin import BUNDLE_NAME, resolve
    from opentine.repo import Repo

    if args.policy:
        path = Path(args.policy)
        roles = _key_roles.load(path)
        if roles is None:
            raise FileNotFoundError(f"no key-role policy at {args.policy}")
        return path, roles, "unpinned"
    store = Repo.open(args.repo).path
    found = resolve(store)
    name = BUNDLE_NAME if found["status"] == "pinned" else _key_roles.FILE_NAME
    return store / name, found["roles"], found["status"]


def cmd_keys(args: argparse.Namespace) -> None:
    from opentine import _key_roles

    pinning = "absent"
    try:
        path, roles, pinning = _policy(args)
        findings = _key_roles.lint(roles or {}, args.optimizer_key)
    except _key_roles.KeyRoleError as exc:
        path, roles = Path(args.policy or _key_roles.FILE_NAME), None
        findings = [{"level": "fail", "code": "fail:key-roles.malformed", "role": None,
                     "key": None, "message": str(exc)}]  # fmt: skip
    except (OSError, ValueError) as exc:
        raise error(exc, prefix="keys lint: ") from exc
    if roles is None and not findings[0]["code"].endswith("malformed"):
        findings.insert(0, {"level": "advisory", "code": "advisory:key-roles.no-policy",
                            "role": None, "key": None,
                            "message": f"no key-role policy ({path.name})"})  # fmt: skip
    blocking = _key_roles.blocking(findings, strict=args.strict)
    if args.json:
        body = {"command": "keys lint", "schema": "tine-cli-keys-lint/1", "ok": not blocking,
                "policy": path.as_posix() if roles is not None else None, "strict": args.strict,
                "roles": roles or {}, "findings": findings, "blocking": len(blocking),
                "pinning": pinning}  # fmt: skip
        sys.stdout.write(json.dumps(body, sort_keys=True) + "\n")
    else:
        for row in findings:
            console.print(_terminal(f"{row['code']}: {row['message']}"), markup=False)
        console.print(f"roles: {pinning}", markup=False)
        console.print("key separation: " + ("refused" if blocking else "ok"), markup=False)
    if blocking:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"keys": cmd_keys}

__all__ = ["COMMANDS", "add_keys_parser", "cmd_keys"]
