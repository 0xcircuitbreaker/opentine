"""``tine merge-history snapshot|plan|apply|verify`` (0.69, F2): merge run histories.

``tine merge`` merges two runs; ``merge-history`` merges what parallel loops
hold around them: refs, labels (promotions), lineage records and holds
(:mod:`opentine._history_merge`). ``snapshot`` prints this repository's
``opentine-history-snapshot/1``; ``plan`` merges it with a base and another
side's snapshot and lists conflicts; ``apply`` lands a conflict-free merge as
ref updates (or merge-queue entries) plus a signed, held
``opentine.history-merge/1`` attestation; ``verify`` re-runs a recorded merge
from its three snapshots and checks the record. ``plan``, ``apply`` and
``verify`` exit 1 on a conflict or a record that does not verify. ``--json``
output follows ``tine-cli-merge-history-1`` (docs/MERGE.md).
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-merge-history/1"
VERBS = ("snapshot", "plan", "apply", "verify")


def add_merge_history_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "merge-history", help="Three-way merge of refs, labels, lineage and holds"
    )
    verbs = parser.add_subparsers(dest="merge_history_command", required=True)
    snap = verbs.add_parser("snapshot", help="Print this repository's history snapshot")
    plan = verbs.add_parser("plan", help="Merge a base and another side into this repository")
    apply = verbs.add_parser("apply", help="Land a conflict-free merge with a signed record")
    for verb in (plan, apply):
        verb.add_argument("--base", required=True, metavar="FILE", help="Base snapshot")
        verb.add_argument("--theirs", required=True, metavar="FILE", help="Other side's snapshot")
    apply.add_argument("--key", required=True, metavar="KEY", help="Ed25519 signing key")
    apply.add_argument("--target", metavar="REF", help="The ref the merge is about")
    apply.add_argument("--subject", metavar="RUN", help="The run the record targets")
    apply.add_argument("--theirs-state", metavar="DIR", help="Other side's .tine/promotion")
    apply.add_argument("--theirs-lineage", metavar="DIR", help="Other side's lineage folder")
    apply.add_argument("--at", metavar="TIME", help="Record time (default now, UTC)")
    ver = verbs.add_parser("verify", help="Re-run a recorded merge and check its record")
    ver.add_argument("record", metavar="RECORD", help="Record file or attestation oid")
    for name in ("base", "ours", "theirs"):
        ver.add_argument(f"--{name}", required=True, metavar="FILE", help=f"{name} snapshot")
    ver.add_argument("--public-key", metavar="HEX", help="Expected Ed25519 public key")
    for verb in (snap, plan, apply, ver):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")
    for verb in (snap, plan, apply):
        verb.add_argument("--state", metavar="DIR", help="Label states (default .tine/promotion)")
        verb.add_argument("--lineage", metavar="DIR", help="Lineage folder (.tine/lineage)")


def _load(path: str) -> Any:
    return json.loads(Path(path).read_bytes().decode("utf-8"))


def _dirs(args: argparse.Namespace) -> dict[str, Path]:
    from opentine._lineage import FOLDER
    from opentine._promote import STATE

    root = Path(args.repo)
    return {"state": Path(args.state) if args.state else root / STATE,
            "lineage": Path(args.lineage) if args.lineage else root / FOLDER}  # fmt: skip


def _lines(body: dict[str, Any]) -> list[str]:
    return [f"conflict ({c['kind']}): {c['key']}" for c in body.get("conflicts", [])]


def _run(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine import _history_merge_repo as hmr
    from opentine.repo import Repo

    verb = args.merge_history_command
    if verb == "verify":
        return _verify(args)
    repo = Repo.open(args.repo)
    if verb == "snapshot":
        snap = hmr.snapshot(repo, **_dirs(args))
        from opentine._history_merge import digest

        return {"ok": True, "digest": digest(snap), "snapshot": snap}, [json.dumps(snap)]
    base, theirs = _load(args.base), _load(args.theirs)
    if verb == "plan":
        found = hmr.plan(repo, base, theirs, **_dirs(args))
        body = {"ok": not found["conflicts"], **found}
        return body, [*_lines(body), f"merged {found['digests']['merged']}"]
    from opentine._audit_game import now
    from opentine._key_hygiene import ed25519_private

    found = hmr.apply(repo, ed25519_private(args.key), base, theirs, **_dirs(args),
                      subject=args.subject, target=args.target, at=args.at or now(),
                      theirs_state=Path(args.theirs_state) if args.theirs_state else None,
                      theirs_lineage=Path(args.theirs_lineage) if args.theirs_lineage
                      else None)  # fmt: skip
    body = {"ok": found["applied"], **found}
    if not found["applied"]:
        return body, [*_lines(body), "not applied: resolve the conflicts first"]
    return body, [f"merged {found['digests']['merged']}: record {found['record']}",
                  f"refs moved {len(found['refs_moved'])}, queued {len(found['queued'])}, "
                  f"labels {len(found['labels_moved'])}, "
                  f"lineage {len(found['lineage_added'])}"]  # fmt: skip


def _verify(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine._history_merge_record import check
    from opentine._key_roles_pin import pinned
    from opentine.repo import Repo

    try:
        repo = Repo.open(args.repo)
    except (OSError, ValueError):
        repo = None
    if Path(args.record).is_file():
        record = _load(args.record)
    elif repo is not None:
        record = repo.get(args.record).payload()
    else:
        raise ValueError(f"no record file or repository object {args.record}")
    key = bytes.fromhex(args.public_key) if args.public_key else None
    body = check(record, _load(args.base), _load(args.ours), _load(args.theirs), key)
    # Who may sign a merge that moves labels: a pinned policy key, never the optimizer's.
    roles = pinned(repo.path if repo is not None else None)
    trusted = None
    if roles is not None:
        signer = record.get("signer")
        trusted = signer in roles.get("policy", []) and signer not in roles.get("optimizer", [])
    body = {
        **body,
        "ok": body["ok"] and trusted is not False,
        "signers": "unpinned" if roles is None else "pinned",
        "signer_trusted": trusted,
    }
    state = "ok" if body["ok"] else "does not verify"
    return body, [
        f"history merge {body['merged']}: {state} (signature {body['signature']}, "
        f"merged {body['merged_matches']}, conflicts {body['conflicts_match']}, "
        f"signers {body['signers']})"
    ]


def cmd_merge_history(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit

    verb = args.merge_history_command
    try:
        body, lines = _run(args)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"merge-history {verb}: ") from exc
    if args.json:
        emit({"command": f"merge-history {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if not body["ok"]:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"merge-history": cmd_merge_history}

__all__ = ["COMMANDS", "VERBS", "add_merge_history_parser", "cmd_merge_history"]
