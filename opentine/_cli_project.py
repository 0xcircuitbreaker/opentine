"""``tine project init|link|show|history|verify|push`` (0.46.1, SPEC 4.16).

A project binds this run repository to the code repositories it is linked to
through a signed, hash-chained ``opentine.project`` manifest kept under the
``project/manifest`` ref. ``init`` writes the first version and ``link`` the
next one with a code slot set (``--role primary`` replaces the primary;
``secondary`` adds or replaces the secondary). Both sign with an owner's
Ed25519 key (``--ed25519-key-file``); no server ever signs a manifest. A
private project (``--visibility private``) names each upstream by a salted
commitment, and the URL and salt stay in ``.tine/project-locators.json``.

``show``, ``history`` and ``verify`` read this repository, or a remote's
``caps.project`` with ``--remote`` (whose ``tine remote add --project ID`` pin
must match). ``verify`` checks the whole chain and exits 4 when it fails.
``push`` sends the versions a remote lacks (:mod:`opentine._cli_project_remote`).
"""

from __future__ import annotations

import argparse
import os
from typing import Any

from opentine._cli_errors import VERIFICATION_FAILED, fail
from opentine._cli_json import emit
from opentine._cli_remote_target import add_remote_args

ACTIONS = ("init", "link", "show", "history", "verify", "push")


def _slot_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--forge", required=True, choices=("github", "gitlab", "forgejo", "git",
                                                           "entire"))  # fmt: skip
    parser.add_argument("--url", required=True, help="Clone URL (https://, ssh:// or git@)")
    parser.add_argument("--forge-repo-id", help="The forge's own repository id, where it has one")
    parser.add_argument("--default-branch", default="main")
    parser.add_argument("--upstream-visibility", choices=("public", "private"))
    parser.add_argument("--ed25519-key-file", required=True, metavar="PATH",
                        help="An owner's Ed25519 key; it signs the new version")  # fmt: skip
    parser.add_argument("--key-id", help="Key id recorded in the signature")


def add_project_parser(sub: Any) -> None:
    project = sub.add_parser(
        "project", help="Link this run repository to its code (opentine.project)"
    )
    actions = project.add_subparsers(dest="project_action", required=True)
    init = actions.add_parser("init", help="Write the first, signed project manifest")
    init.add_argument("project_id", help="[a-z0-9][a-z0-9._-]{0,63}")
    init.add_argument("--tenant", required=True)
    init.add_argument("--visibility", choices=("public", "private"), default="public")
    init.add_argument("--owner", action="append", default=[], metavar="HEX",
                      help="A further owner's Ed25519 public key (repeatable)")  # fmt: skip
    init.add_argument("--forked-from", metavar="PROJECT_ID")
    _slot_args(init)
    link = actions.add_parser("link", help="Sign a new version with a code slot set")
    link.add_argument("--role", choices=("primary", "secondary"), default="primary")
    _slot_args(link)
    for name, text in (
        ("show", "The current manifest"),
        ("history", "Every version, oldest first"),
        ("verify", "Check every version's signature and chain link"),
    ):
        reader = actions.add_parser(name, help=text)
        add_remote_args(reader)
        reader.add_argument("--owner-key", metavar="HEX", help="verify: pin the first owner")
    push = actions.add_parser("push", help="Send the versions a remote lacks (caps.project)")
    add_remote_args(push)
    for parser in (init, link, push, *(actions.choices[n] for n in ("show", "history", "verify"))):
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true")


def _public_hex(key: Any) -> str:
    return key.public_key().public_bytes_raw().hex()


def _slot(args: argparse.Namespace, repo: Any, visibility: str, role: str) -> dict[str, Any]:
    from opentine import _project
    from opentine.repository import _project_ref

    upstream = args.upstream_visibility or visibility
    locator: dict[str, str] = {"url": args.url}
    if visibility == "private":
        salt = os.urandom(32)
        locator = {"commitment": _project.commitment(args.url, salt)}
        _project_ref.remember(repo, locator["commitment"], args.url, salt)
    return {"role": role, "forge": args.forge, "forge_repo_id": args.forge_repo_id,
            "upstream_visibility": upstream, "locator": locator,
            "default_branch": args.default_branch}  # fmt: skip


def _write(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _project
    from opentine._signing_keys import ed25519_private_from_file
    from opentine.repository import Repo, _project_ref

    repo = Repo.open(args.repo)
    key = ed25519_private_from_file(args.ed25519_key_file)
    current = _project_ref.read(repo)
    if args.project_action == "init":
        if current is not None:
            raise ValueError("this repository already has a project: use `tine project link`")
        owners = [_public_hex(key), *[o for o in args.owner if o != _public_hex(key)]]
        slot = _slot(args, repo, args.visibility, "primary")
        record = _project.build(
            args.project_id,
            args.tenant,
            owners=owners,
            slots=[slot],
            visibility=args.visibility,
            forked_from=args.forked_from,
        )
    else:
        if current is None:
            raise KeyError("no project here: `tine project init` first")
        slot = _slot(args, repo, current["visibility"], args.role)
        kept = [s for s in current["slots"] if s["role"] != args.role]
        slots = sorted([*kept, slot], key=lambda s: s["role"] != "primary")
        record = _project.build(current["project_id"], current["tenant"], owners=current["owners"],
                                slots=slots, visibility=current["visibility"], previous=current,
                                forked_from=current["forked_from"])  # fmt: skip
    signed = _project.sign(record, key, key_id=args.key_id)
    oid = _project_ref.write(repo, signed)
    return {"project": _summary(signed), "digest": oid, "manifest": signed}


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    return {name: record[name] for name in ("project_id", "tenant", "seq", "visibility")}


def _read(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.remote:
        from opentine._cli_project_remote import remote_history

        return remote_history(args)
    from opentine.repository import Repo, _project_ref

    versions = _project_ref.history(Repo.open(args.repo))
    if not versions:
        raise KeyError("no project here: `tine project init` first")
    return versions


def _lines(versions: list[dict[str, Any]]) -> str:
    from opentine import _project

    rows = []
    for record in versions:
        where = ", ".join(f"{s['role']} {s['forge']} {s['locator'].get('url', 'commitment')}"
                          for s in record["slots"])  # fmt: skip
        rows.append(f"{record['seq']}\t{_project.digest(record)}\t{record['visibility']}\t{where}")
    return "\n".join(rows)


def _act(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    from opentine import _project

    action = args.project_action
    if action in ("init", "link"):
        body = _write(args)
        return (
            body,
            f"project {body['project']['project_id']} v{body['project']['seq']}: {body['digest']}",
        )
    if action == "push":
        from opentine._cli_project_remote import push

        body = push(args)
        return body, f"pushed {body['sent']} project version(s); remote head {body['head']}"
    versions = _read(args)
    if action == "show":
        head = versions[-1]
        body = {"project": _summary(head), "digest": _project.digest(head), "manifest": head}
        return body, _lines([head])
    if action == "history":
        return {"versions": versions, "total": len(versions)}, _lines(versions)
    result = _project.chain(versions, owner_key=args.owner_key)
    return {"result": result}, f"verified {result['versions']} version(s) ({result['state']})"


def cmd_project(args: argparse.Namespace) -> None:
    from opentine._signed_record import RecordError

    try:
        body, text = _act(args)
    except RecordError as exc:
        fail(f"{exc.code}: {exc}", VERIFICATION_FAILED, prefix="tine project: ")
    except (KeyError, OSError, ValueError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(str(message), prefix="tine project: ")
    if args.json:
        emit({"command": "project", "action": args.project_action, "ok": True, **body})
    else:
        print(text)


__all__ = ["ACTIONS", "add_project_parser", "cmd_project"]
