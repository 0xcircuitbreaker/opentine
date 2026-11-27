"""``tine oversight policy|sign-policy|request|approve|reject|queue|fatigue`` (0.64).

``policy`` reports whether ``.tine/oversight.toml`` is pinned
(:mod:`opentine._oversight_policy`); ``sign-policy --key`` writes
``.tine/oversight.sig.json`` with a policy-role key; ``request``, ``approve``
and ``reject ITEM --key`` write one signed, held decision annotation
(:mod:`opentine._oversight`); ``queue`` lists every routed item and its k-of-n
tally (:mod:`opentine._oversight_queue`), ``--from-objects`` rebuilding it from
the annotation objects alone; ``tine ui --repo`` serves the same body.
``fatigue`` is the advisory approver-fatigue report
(:mod:`opentine._oversight_fatigue`); it always exits 0. An approve or reject signed
by an optimizer, monitor or scorer key is refused before anything is written.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-oversight/1"
DECIDE = ("request", "approve", "reject")


def add_oversight_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("oversight", help="Oversight queue: k-of-n signed approvals")
    verbs = parser.add_subparsers(dest="oversight_command", required=True)
    policy = verbs.add_parser("policy", help="Is .tine/oversight.toml pinned?")
    sign = verbs.add_parser("sign-policy", help="Sign .tine/oversight.toml (a policy-role key)")
    sign.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    rows = []
    for verb in DECIDE:
        row = verbs.add_parser(verb, help=f"Sign and hold a {verb} decision on ITEM")
        row.add_argument(
            "item",
            metavar="ITEM",
            help="promotion:LABEL:RUN, monitor:|integrity:|containment:ATTESTATION, "
            "budget:ANNOTATION",
        )
        row.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
        row.add_argument("--human", help="The person deciding (keys of one person count once)")
        row.add_argument("--note", default="", help="Why (recorded, signed)")
        row.add_argument("--state", metavar="DIR",
                         help="Label state (default REPO/.tine/promotion)")  # fmt: skip
        if verb != "request":
            row.add_argument("--viewed", action="append", default=[], metavar="OID",
                             help="Evidence reviewed before deciding (repeatable)")  # fmt: skip
            row.add_argument("--viewed-at", metavar="TIME",
                             help="When the evidence was opened (default: --at)")  # fmt: skip
        rows.append(row)
    rows[0].add_argument("--evals", metavar="DIR", help="The candidate's eval folder (routing)")
    show = verbs.add_parser("queue", help="List routed items and their approvals")
    show.add_argument("--from-objects", action="store_true",
                      help="Rebuild from the annotation objects alone")  # fmt: skip
    show.add_argument("--only", choices=("pending", "approved", "rejected", "unrouted"),
                      help="Print only items in this state (text output)")  # fmt: skip
    tired = verbs.add_parser("fatigue", help="Advisory approver-fatigue report (exits 0)")
    tired.add_argument("--min-review-seconds", type=int, default=30, metavar="N",
                       help="Approval under N s after viewing: rubber stamp")  # fmt: skip
    for verb in (policy, sign, *rows, show, tired):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _policy(repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _oversight_policy

    state = _oversight_policy.load(repo.path)
    policy = state["policy"]
    body = {"status": state["status"], "why": state["why"], "floors": state["floors"],
            "sha256": policy["sha256"] if policy else None,
            "tiers": [{"tier": n, "k": t["k"], "n": len(t["approvers"])}
                      for n, t in (policy or {}).get("tiers", {}).items()],
            "routes": (policy or {}).get("routes", [])}  # fmt: skip
    lines = [f"oversight policy: {state['status']}" + (f" ({state['why']})" if state["why"]
                                                        else "")]  # fmt: skip
    lines += [f"  tier {t['tier']}: {t['k']} of {t['n']}" for t in body["tiers"]]
    return {"policy": body}, lines


def _bind(args: argparse.Namespace, repo: Any, item: str) -> dict[str, Any] | None:
    from opentine import _oversight, _oversight_policy
    from opentine._promote import STATE, read_state

    info = _oversight.parse_item(item)
    if info["source"] != "promotion":
        return None
    state = Path(args.state) if args.state else repo.path.parent / STATE
    record = read_state(state, info["label"])
    bind = {"label": info["label"], "candidate": info["candidate"],
            "previous": record["current"], "sequence": len(record["history"])}  # fmt: skip
    evals = getattr(args, "evals", None)
    if evals:
        bind["metrics"] = _oversight_policy.eval_metrics(Path(evals))
    return bind


def _decide(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _oversight, _oversight_policy
    from opentine._key_hygiene import ed25519_private
    from opentine._signing_pins import key_fingerprint

    verb = args.oversight_command
    key = ed25519_private(args.key)
    who = key_fingerprint(key.public_key().public_bytes_raw())
    held, _ = _oversight_policy.roles(repo.path)
    if verb != "request" and who in _oversight_policy.banned(held):
        raise ValueError(f"oversight.key-separation: {who} holds an optimizer, monitor or "
                         "scorer role and may not approve or reject")  # fmt: skip
    viewed = None
    if getattr(args, "viewed", None):
        seen = args.viewed_at or args.at or _oversight.now()
        viewed = {"evidence": sorted(set(args.viewed)), "at": seen}
    oid = _oversight.decide(repo, args.item, verb, key, bind=_bind(args, repo, args.item),
                            human=args.human, note=args.note, at=args.at,
                            viewed=viewed)  # fmt: skip
    row = {"decision": oid, "item": args.item, "action": verb, "signer": who}
    return {"decisions": [row]}, [f"{verb} {args.item}: {oid}"]


def _body(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _oversight, _oversight_policy, _oversight_queue

    verb = args.oversight_command
    if verb == "policy":
        return _policy(repo)
    if verb == "sign-policy":
        from opentine._key_hygiene import ed25519_private

        data = (repo.path / _oversight_policy.FILE_NAME).read_bytes()
        _oversight_policy.parse(data)
        doc = _oversight_policy.sign(ed25519_private(args.key), data, args.at or _oversight.now())
        path = repo.path / _oversight_policy.PIN_NAME
        path.write_bytes((json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        from opentine._integrity_defaults import pin  # 0.85: the policy is a default pin

        pin(Path(repo.path).parent, Path(repo.path) / _oversight_policy.FILE_NAME, "oversight")
        body, lines = _policy(repo)
        return body, [f"signed {path.as_posix()}", *lines]
    if verb in DECIDE:
        return _decide(args, repo)
    body = _oversight_queue.queue(repo, from_objects=getattr(args, "from_objects", False))
    if verb == "fatigue":
        return _fatigue(args, body)
    c = body["counts"]
    lines = [f"oversight policy: {body['policy']['status']}; {c['pending']} pending, "
             f"{c['approved']} approved, {c['rejected']} rejected ({body['digest']})"]  # fmt: skip
    for item in body["items"]:
        if args.only and item["state"] != args.only:
            continue
        got = ", ".join(f"{t['tier']} {t['approvals']}/{t['k']}" for t in item["tiers"])
        lines.append(f"{item['state']:9} {item['item']} {got}".rstrip())
    return body, lines if body["items"] else [*lines, "no items in the queue"]


def _fatigue(args: argparse.Namespace, body: dict[str, Any]) -> tuple[dict, list[str]]:
    from opentine._oversight_fatigue import parse_time, report

    if args.min_review_seconds < 0:
        raise ValueError("--min-review-seconds is not negative")
    when = parse_time(args.at) if args.at else datetime.now(UTC)
    if when is None:
        raise ValueError(f"--at {args.at!r} is not an ISO 8601 time")
    out = report(body, now=lambda: when, min_review_seconds=args.min_review_seconds)
    rate = out["rubber_stamp_rate"]
    lines = [f"advisory: {out['approvals']} approval(s), {out['rubber_stamps']} rubber "
             "stamp(s)" + (f" ({rate:.0%})" if rate is not None else "")
             + f"; median time to decision {out['median_seconds_to_decision']} s"]  # fmt: skip
    lines += [f"  {r['signer']}: {r['approvals']} approved, {r['rejections']} rejected, "
              f"{r['rubber_stamps']} rubber stamp(s)" for r in out["approvers"]]  # fmt: skip
    return out, lines


def cmd_oversight(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._oversight_policy import OversightError
    from opentine.repo import Repo

    try:
        repo = Repo.open(args.repo)
        body, lines = _body(args, repo)
    except (OSError, ValueError, KeyError, OversightError) as exc:
        raise error(exc, prefix="oversight: ") from exc
    if args.json:
        emit({"command": f"oversight {args.oversight_command}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"oversight": cmd_oversight}

__all__ = ["COMMANDS", "add_oversight_parser", "cmd_oversight"]
