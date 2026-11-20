"""``tine organism tag|untag|approve|status|gate`` (0.72): model-organism custody.

``tag ARTIFACT --reason R [--name N]... --key KEY`` signs and holds a tag
(a ``policy`` or ``curator`` key of the owner-pinned roles); ARTIFACT is
``sha256:HEX`` or a file, hashed locally and never stored. ``untag ARTIFACT
--key KEY`` releases its live tags once each tag's oversight item
(``organism:ATTESTATION``) is approved k-of-n. ``approve ARTIFACT --run RUN
--why W --key KEY`` lets one run load it (a pinned ``approver`` key).
``status [ARTIFACT]`` lists tags, approvals and the access log. ``gate`` is the
agent hook (:mod:`opentine._organism_gate`). See docs/MODEL_ORGANISMS.md.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-organism/1"


def add_organism_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("organism", help="Model-organism tags, approvals and access")
    verbs = parser.add_subparsers(dest="organism_command", required=True)
    tag = verbs.add_parser("tag", help="Sign and hold a model-organism tag on an artifact")
    tag.add_argument("--reason", required=True, metavar="TEXT", help="Why it is tagged")
    tag.add_argument("--name", action="append", default=[], metavar="NAME",
                     help="A path or file name the artifact is loaded by (repeatable)")  # fmt: skip
    untag = verbs.add_parser("untag", help="Release the tags (needs k-of-n oversight approval)")
    approve = verbs.add_parser("approve", help="Approve one run loading a tagged artifact")
    approve.add_argument("--run", required=True, metavar="RUN", help="The requesting run")
    approve.add_argument("--why", required=True, metavar="TEXT", help="Why it may load it")
    status = verbs.add_parser("status", help="Tags, approvals and the access log")
    status.add_argument("artifact", nargs="?", metavar="ARTIFACT", help="sha256:HEX or a file")
    for verb in (tag, untag, approve):
        verb.add_argument("artifact", metavar="ARTIFACT", help="sha256:HEX or a file")
        verb.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    gate = verbs.add_parser("gate", help="Agent hook: refuse loading a tagged artifact")
    gate.add_argument("--agent", metavar="NAME", help="claude-code, codex, gemini or generic")
    gate.add_argument("--run", metavar="RUN", help="The requesting run (default: the session)")
    gate.add_argument("--fail-closed", action="store_true",
                      help="Refuse when the hook payload cannot be read")  # fmt: skip
    for verb in (tag, untag, approve, status, gate):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
    for verb in (tag, untag, approve, status):
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _key(path: str) -> Any:
    from opentine._key_hygiene import ed25519_private

    return ed25519_private(path)


def _write(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _organism

    artifact = _organism.digest_of(args.artifact)
    verb, key = args.organism_command, _key(args.key)
    if verb == "tag":
        names = list(args.name)
        if artifact != args.artifact.strip().lower():
            from pathlib import Path

            names.append(Path(args.artifact).as_posix())
        oid = _organism.tag(repo, artifact, key, names=names, reason=args.reason)
    elif verb == "approve":
        oid = _organism.approve(repo, artifact, args.run, key, why=args.why)
    else:
        oid = _organism.untag(repo, artifact, key)
    return {"artifact": artifact, "record": oid}, [f"{verb} {artifact}: {oid}"]


def _status(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _organism
    from opentine._organism_registry import accesses, approvals, registry

    known = registry(repo)
    wanted = [_organism.digest_of(args.artifact)] if args.artifact else sorted(known)
    rows, lines = [], []
    for artifact in wanted:
        entry = known.get(artifact) or {"tagged": False, "live": [], "names": [], "tags": [],
                                        "untags": []}  # fmt: skip
        row = {
            "artifact": artifact,
            "tagged": entry["tagged"],
            "live": entry["live"],
            "names": entry["names"],
            "tags": entry["tags"],
            "untags": entry["untags"],
            "approvals": approvals(repo, artifact),
            "accesses": accesses(repo, artifact),
        }
        rows.append(row)
        refused = sum(a["outcome"] == "refused" for a in row["accesses"])
        lines.append(f"{artifact} {'tagged' if row['tagged'] else 'untagged'}: "
                     f"{len(row['approvals'])} approval(s), {len(row['accesses'])} access(es), "
                     f"{refused} refused")  # fmt: skip
    return {"artifacts": rows}, lines or ["no model organisms tagged"]


def cmd_organism(args: argparse.Namespace) -> None:
    verb = args.organism_command
    if verb == "gate":
        from opentine._organism_gate import run

        raise SystemExit(run(args))
    from opentine._cli_json import emit
    from opentine.repo import Repo

    handler = _status if verb == "status" else _write
    try:
        body, lines = handler(args, Repo.open(args.repo))
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"organism {verb}: ") from exc
    if args.json:
        emit({"command": f"organism {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"organism": cmd_organism}

__all__ = ["COMMANDS", "SCHEMA", "add_organism_parser", "cmd_organism"]
