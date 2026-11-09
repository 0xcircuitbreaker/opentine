"""``tine memory add|list|recall|trust`` (0.47, SPEC 4.20).

Team memory: signed notes that sync with the run repository and that MCP
``recall`` returns to an agent. ``add`` signs a note (Ed25519, ``--key``) and
stores it under ``memory/<scope>/<hex>``; it refuses text a secret detector
fires on, because a signed note is never redacted afterwards. ``trust`` adds a
public key to the team file ``.tine/memory-team.json``; ``list`` and ``recall``
show only notes that verify under the team and are not superseded (with no
team file, ``list --any-signer`` shows every note that verifies on its own key).
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from opentine._cli_errors import VERIFICATION_FAILED, fail
from opentine._cli_json import emit
from opentine._cli_remote_target import add_remote_args

TEAM_FILE = "memory-team.json"
ACTIONS = ("add", "list", "recall", "trust", "sync")
MAX_RECALL = 50


def add_memory_parser(sub: Any) -> None:
    memory = sub.add_parser("memory", help="Signed team memory notes (opentine.memory)")
    actions = memory.add_subparsers(dest="memory_action", required=True)
    add = actions.add_parser("add", help="Sign and store a memory note")
    add.add_argument("topic", help="[a-z0-9][a-z0-9._-]{0,63}")
    add.add_argument("text")
    add.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    add.add_argument("--scope", default="team", help="The team or repository it belongs to")
    add.add_argument("--tag", action="append", default=[], help="A tag (repeatable)")
    add.add_argument("--subject", metavar="OID", help="The run or blob the note is about")
    add.add_argument("--supersedes", metavar="DIGEST", help="The note this one replaces")
    add.add_argument("--author", help="Who wrote it (default: the key's fingerprint)")
    add.add_argument("--created-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    listing = actions.add_parser("list", help="Notes that verify under the team")
    listing.add_argument("--scope")
    listing.add_argument("--any-signer", action="store_true",
                         help="Without a team file, show notes on their embedded keys")  # fmt: skip
    recall = actions.add_parser("recall", help="Notes whose topic, tags or text hold every word")
    recall.add_argument("query")
    recall.add_argument("--limit", type=int, default=10)
    trust = actions.add_parser("trust", help="Add an Ed25519 public key to the team file")
    trust.add_argument("pubkey", metavar="PUB", help="A public key file or 64 hex")
    add_remote_args(actions.add_parser("sync", help="Send and fetch notes (team-signed only)"))
    for parser in actions.choices.values():
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true")


def team(repo: Any) -> list[str]:
    """The hex public keys of ``.tine/memory-team.json`` (empty without one)."""
    from opentine.repository._paths import internal_path

    try:
        value = json.loads(internal_path(repo.path, TEAM_FILE).read_bytes())
    except FileNotFoundError:
        return []
    keys = value.get("keys") if isinstance(value, dict) else None
    if not isinstance(keys, list) or not all(
        isinstance(k, str) and len(k) == 64 and not k.strip("0123456789abcdef") for k in keys
    ):
        raise ValueError(f"{TEAM_FILE} is malformed")
    return sorted(set(keys))


def _row(entry: dict[str, Any]) -> dict[str, Any]:
    record, check = entry["record"], entry["check"]
    return {**check, "text": record["text"], "author": record["author"],
            "created_at": record["created_at"]}  # fmt: skip


def recall_notes(repo: Any, query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Team notes whose topic, tags or text contain every word of *query*."""
    from opentine.repository import _registry_refs as refs

    keys = team(repo)
    if not keys or not isinstance(query, str):
        return []
    words = [word.casefold() for word in query.split() if word]
    found = []
    for entry in refs.notes(repo, team=keys):
        record = entry["record"]
        hay = " ".join([record["topic"], *record["tags"], record["text"]]).casefold()
        if words and all(word in hay for word in words):
            found.append(_row(entry))
    found.sort(key=lambda row: row["created_at"], reverse=True)
    return found[: max(1, min(limit, MAX_RECALL))]


def _add(args: argparse.Namespace, repo: Any) -> dict[str, Any]:
    from opentine import _memory
    from opentine._signing_keys import ed25519_private_from_file
    from opentine._signing_pins import key_fingerprint
    from opentine.redaction import redact_text
    from opentine.repository import _registry_refs as refs

    if redact_text(args.text) != args.text:
        raise ValueError("the note holds what looks like a secret; a signed note is never redacted")
    key = ed25519_private_from_file(args.key)
    public = key.public_key().public_bytes_raw()
    record = _memory.build(args.scope, args.topic, args.text,
                           author=args.author or key_fingerprint(public), tags=args.tag,
                           subject=args.subject, supersedes=args.supersedes,
                           created_at=args.created_at)  # fmt: skip
    signed = _memory.sign(record, key)
    refs.add_note(repo, signed)
    return {"note": _memory.check(signed), "record": signed}


def _trust(args: argparse.Namespace, repo: Any) -> dict[str, Any]:
    from opentine._canon import atomic_write_text
    from opentine._signing_keys import ed25519_public_from_file
    from opentine.repository._paths import internal_path

    raw = args.pubkey
    if len(raw) == 64 and all(c in "0123456789abcdef" for c in raw):
        hex_key = raw
    else:
        hex_key = ed25519_public_from_file(raw).public_bytes_raw().hex()
    keys = sorted({*team(repo), hex_key})
    path = internal_path(repo.path, TEAM_FILE)
    atomic_write_text(path, json.dumps({"keys": keys}, indent=2) + "\n")
    return {"team": keys}


def remote_sync(args: Any, prefix: str) -> dict[str, Any]:
    """``tine memory|prompt sync``: one round each way with a remote."""
    from opentine._cli_memory import team
    from opentine._cli_remote_target import resolve
    from opentine.repository import Repo
    from opentine.repository._registry_sync import sync

    repo = Repo.open(args.repo)
    base, tenant, token = resolve(args, args.remote)
    return sync(repo, base, tenant=tenant, token=token, team=team(repo), prefixes=(prefix,),
                allow_insecure=args.allow_insecure, timeout=args.timeout)  # fmt: skip


def _act(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    from opentine.repository import Repo
    from opentine.repository import _registry_refs as refs

    repo = Repo.open(args.repo)
    action = args.memory_action
    if action == "add":
        body = _add(args, repo)
        return (
            body,
            f"memory {body['note']['scope']}/{body['note']['topic']}: {body['note']['digest']}",
        )
    if action == "sync":
        body = remote_sync(args, "memory/")
        return body, f"sent {len(body['sent'])}, received {len(body['received'])} note(s)"
    if action == "trust":
        body = _trust(args, repo)
        return body, f"team: {len(body['team'])} key(s)"
    if action == "recall":
        rows = recall_notes(repo, args.query, args.limit)
    else:
        keys = team(repo)
        if not keys and not args.any_signer:
            rows = []
        else:
            rows = [_row(entry) for entry in refs.notes(repo, team=keys, scope=args.scope)]
    text = "\n".join(f"{r['scope']}/{r['topic']}\t{r['text']}" for r in rows)
    return {"notes": rows, "team": len(team(repo))}, text or "no notes"


def cmd_memory(args: argparse.Namespace) -> None:
    from opentine._signed_record import RecordError

    try:
        body, text = _act(args)
    except RecordError as exc:
        fail(f"{exc.code}: {exc}", VERIFICATION_FAILED, prefix="tine memory: ")
    except (KeyError, OSError, ValueError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(str(message), prefix="tine memory: ")
    if args.json:
        emit({"command": "memory", "action": args.memory_action, "ok": True, **body})
    else:
        print(text)


__all__ = ["ACTIONS", "TEAM_FILE", "add_memory_parser", "cmd_memory", "recall_notes",
           "remote_sync", "team"]  # fmt: skip
