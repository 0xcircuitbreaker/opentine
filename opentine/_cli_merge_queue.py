"""``tine merge-queue init|add|claim|heartbeat|land|work|show|approve|verify`` (0.47).

A merge queue (:mod:`opentine.coord._merge_queue`) owns one target ref. ``add``
queues a run; a worker ``claim``s the queue's lease (printing its fencing
token) and ``land``s the first entry with that token, which checks the gates,
merges, signs an ``opentine.merge`` attestation with ``--ed25519-key-file`` and
commits all of it in one compare-and-swap. ``work`` repeats claim and land
until the queue is empty. ``approve`` writes a signed ``opentine.merge-approval``
for a gate; ``verify`` checks an attestation or approval offline (exit 4 when
it fails). ``--json`` output follows ``tine-cli-merge-queue-1``.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from opentine._cli_errors import VERIFICATION_FAILED, fail
from opentine._cli_json import emit

ACTIONS = ("init", "add", "claim", "heartbeat", "land", "work", "show", "approve", "verify")


def _key_args(parser: argparse.ArgumentParser, required: bool) -> None:
    parser.add_argument("--ed25519-key-file", required=required, metavar="PATH",
                        help="Ed25519 key that signs the record")  # fmt: skip


def add_merge_queue_parser(sub: Any) -> None:
    queue = sub.add_parser("merge-queue", help="Land runs onto a ref through gated, fenced merges")
    actions = queue.add_subparsers(dest="queue_action", required=True)

    def action(name: str, text: str) -> argparse.ArgumentParser:
        parser = actions.add_parser(name, help=text)
        parser.add_argument("queue", metavar="QUEUE", help="[a-z0-9][a-z0-9._-]{0,63}")
        return parser

    init = action("init", "Create a queue owning a target ref")
    init.add_argument("--target", required=True, help="The ref the queue lands on")
    init.add_argument("--gates", metavar="FILE", help="An opentine-merge-gates/1 policy")
    add = action("add", "Queue a run")
    add.add_argument("run", metavar="RUN")
    add.add_argument("--by", default="cli", help="Who queued it")
    claim = action("claim", "Take the queue's lease")
    beat = action("heartbeat", "Extend the lease")
    land = action("land", "Land the first entry under the lease")
    work = action("work", "Claim and land until the queue is empty")
    for parser in (claim, beat, land, work):
        parser.add_argument("--holder", required=True)
        parser.add_argument("--ttl", type=float, default=60.0, help="Lease seconds")
    for parser in (beat, land):
        parser.add_argument("--fencing", type=int, required=True)
    for parser in (land, work):
        parser.add_argument("--evidence", metavar="FILE", help="{vsa, evals, approvals} JSON")
        _key_args(parser, True)
    work.add_argument("--max", type=int, default=0, help="Stop after this many entries")
    action("show", "The queue's current value")
    approve = actions.add_parser("approve", help="Sign an opentine.merge-approval")
    approve.add_argument("run", metavar="RUN")
    approve.add_argument("--target", required=True)
    approve.add_argument("--approver", required=True)
    approve.add_argument("--reject", action="store_true")
    _key_args(approve, True)
    verify = actions.add_parser("verify", help="Check a merge attestation or approval offline")
    verify.add_argument("file", metavar="FILE", help="A record file, or an attestation oid")
    verify.add_argument("--public-key", metavar="HEX", help="The trusted signer key")
    verify.add_argument("--run", action="store_true", help="Also check the merged run here")
    for parser in actions.choices.values():
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true")


def _load(path: str | None) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def _key(args: argparse.Namespace) -> Any:
    from opentine._signing_keys import ed25519_private_from_file

    return ed25519_private_from_file(args.ed25519_key_file)


def _work(repo: Any, args: argparse.Namespace) -> dict[str, Any]:
    from opentine.coord import _merge_queue as q
    from opentine.coord._tasks import LeaseError

    key, evidence, rows = _key(args), _load(args.evidence), []
    while not args.max or len(rows) < args.max:
        try:
            value = q.claim(repo, args.queue, args.holder, args.ttl)
        except LeaseError as exc:
            if exc.code == "empty":
                break
            if exc.code not in ("held", "contended"):
                raise
            time.sleep(0.02)
            continue
        try:
            rows.append(q.land(repo, args.queue, args.holder, value["fencing"],
                               evidence=evidence, key=key))  # fmt: skip
        except LeaseError as exc:
            if exc.code != "stale":
                raise
    return {"results": rows, "total": len(rows)}


def _verify(repo: Any, args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _merge_record

    if args.file.startswith("blob:"):
        record = json.loads(repo.get(args.file).body)
    else:
        record = _load(args.file)
    key = bytes.fromhex(args.public_key) if args.public_key else None
    if isinstance(record, dict) and record.get("kind") == _merge_record.APPROVAL_KIND:
        return {"result": _merge_record.check_approval(record, public_key=key)}
    run = repo.get(record["run"]).payload() if args.run and isinstance(record, dict) else None
    return {"result": _merge_record.check(record, public_key=key, run=run)}


def _act(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _merge_record
    from opentine.coord import _merge_queue as q
    from opentine.repository import Repo

    action = args.queue_action
    if action == "approve":
        record = _merge_record.build_approval(args.run, args.target, args.approver,
                                              "reject" if args.reject else "approve")  # fmt: skip
        return {"record": _merge_record.sign_approval(record, _key(args), algorithm="ed25519",
                                                      key_id=args.approver)}  # fmt: skip
    repo = Repo.open(args.repo)
    if action == "verify":
        return _verify(repo, args)
    if action == "init":
        return {"queue": q.init(repo, args.queue, args.target, _load(args.gates))}
    if action == "add":
        return {"queue": q.enqueue(repo, args.queue, args.run, args.by)}
    if action == "claim":
        return {"queue": q.claim(repo, args.queue, args.holder, args.ttl)}
    if action == "heartbeat":
        return {"queue": q.heartbeat(repo, args.queue, args.holder, args.fencing, args.ttl)}
    if action == "land":
        return {"result": q.land(repo, args.queue, args.holder, args.fencing,
                                 evidence=_load(args.evidence), key=_key(args))}  # fmt: skip
    if action == "work":
        return _work(repo, args)
    return {"queue": q.get(repo, args.queue)}


def _text(action: str, body: dict[str, Any]) -> str:
    if "queue" in body:
        value = body["queue"]
        return (f"{value['queue']} -> {value['target']}: head {value['head']}, "
                f"{len(value['entries'])} queued, holder {value['holder']} "
                f"(fencing {value['fencing']})")  # fmt: skip
    if action == "work":
        return f"{body['total']} entr{'y' if body['total'] == 1 else 'ies'} processed"
    if "record" in body:
        return json.dumps(body["record"], sort_keys=True)
    result = body["result"]
    return " ".join(f"{k}={v}" for k, v in result.items() if not isinstance(v, list | dict))


def cmd_merge_queue(args: argparse.Namespace) -> None:
    from opentine._merge import MergeError
    from opentine._merge_gates import GateError
    from opentine._signed_record import RecordError
    from opentine.coord._tasks import LeaseError

    try:
        body = _act(args)
    except RecordError as exc:
        fail(f"{exc.code}: {exc}", VERIFICATION_FAILED, prefix="tine merge-queue: ")
    except (LeaseError, MergeError) as exc:
        fail(f"{exc.code}: {exc}", prefix="tine merge-queue: ")
    except (GateError, KeyError, OSError, ValueError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(str(message), prefix="tine merge-queue: ")
    if args.json:
        emit({"command": "merge-queue", "action": args.queue_action, "ok": True, **body})
    else:
        print(_text(args.queue_action, body))


__all__ = ["ACTIONS", "add_merge_queue_parser", "cmd_merge_queue"]
