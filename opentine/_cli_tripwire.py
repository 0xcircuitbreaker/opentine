"""``tine tripwire add|remove|list|check|trips`` (0.91): the signed tripwire registry.

* ``add ID --metric M --threshold X [--op >=] [--scope S] [--action flag|stop]
  [--decoy sha256:...]... [--replace] --key K`` signs the next registry version
  with the tripwire added (or, with ``--replace``, edited);
* ``remove ID --key K`` signs the next version without it. Both need a pinned
  ``policy`` key that is not an ``optimizer`` key;
* ``list`` shows the registry in force and every finding about its versions;
* ``check [--key K] [--now-ms MS]`` evaluates every tripwire; with ``--key``
  it signs and holds the trips (and a ``stop`` action's stop token). It exits
  1 when a tripwire trips or the registry has a finding;
* ``trips`` lists the held trips.

See :mod:`opentine._tripwire_registry` and :mod:`opentine._tripwire_check`;
``--json`` prints ``tine-cli-tripwire/1``.
"""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from typing import Any

SCHEMA = "tine-cli-tripwire/1"
VERBS = ("add", "remove", "list", "check", "trips")


def add_tripwire_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._tripwire_registry import ACTIONS, OPS

    parser = subparsers.add_parser("tripwire", help="A signed registry of tripwires, checked "
                                   "over monitor, ingest and budget signals")  # fmt: skip
    verbs = parser.add_subparsers(dest="tripwire_command", required=True)
    add = verbs.add_parser("add", help="Sign a registry version with this tripwire")
    add.add_argument("id", metavar="ID")
    add.add_argument("--metric", required=True, help="suspicion.flags, decoy.touches, ...")
    add.add_argument("--threshold", required=True, type=float)
    add.add_argument("--op", choices=OPS, default=">=")
    add.add_argument("--scope", default="*", help="*, agent:ID, session:ID, stream:NAME, ...")
    add.add_argument("--action", choices=ACTIONS, default="flag")
    add.add_argument("--decoy", action="append", default=[], metavar="DIGEST",
                     help="decoy.touches: the sha256: digest of a decoy (repeatable)")  # fmt: skip
    add.add_argument("--replace", action="store_true", help="Edit an existing tripwire")
    remove = verbs.add_parser("remove", help="Sign a registry version without this tripwire")
    remove.add_argument("id", metavar="ID")
    lst = verbs.add_parser("list", help="The registry in force and its findings")
    check = verbs.add_parser("check", help="Evaluate every tripwire (exit 1 on a trip)")
    check.add_argument("--now-ms", type=int, help="Evaluation time (default now)")
    trips = verbs.add_parser("trips", help="The held trips")
    for verb in (add, remove, check):
        verb.add_argument("--key", required=verb is not check, metavar="KEY",
                          help="Signing key (check: records trips)")  # fmt: skip
    for verb in (add, remove, lst, check, trips):
        verb.add_argument("--repo", default=".")
        verb.add_argument("--json", action="store_true", help="Emit a JSON object instead")


def _edit(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str], bool]:
    from opentine import _tripwire_registry as reg
    from opentine._key_hygiene import ed25519_private

    state = reg.current(repo)
    wires = [w for w in state["tripwires"] if w["id"] != args.id]
    there = len(wires) != len(state["tripwires"])
    if args.tripwire_command == "remove" and not there:
        raise KeyError(f"no tripwire {args.id} is registered")
    if args.tripwire_command == "add":
        if there and not args.replace:
            raise ValueError(f"tripwire {args.id} is registered: --replace edits it")
        wires.append(reg.wire({"id": args.id, "metric": args.metric, "op": args.op,
                               "threshold": args.threshold, "scope": args.scope,
                               "action": args.action, "decoys": args.decoy}))  # fmt: skip
    out = reg.write(repo, wires, ed25519_private(args.key))
    claim = out["claim"]
    return ({"record": out["record"], "serial": claim["serial"], "tripwires": claim["tripwires"]},
            [f"registry serial {claim['serial']}: {out['record']}"], True)  # fmt: skip


def _list(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str], bool]:
    from opentine import _tripwire_registry as reg

    state = reg.current(repo)
    body = {k: state[k] for k in ("status", "head", "serial", "tripwires", "findings")}
    body["required"] = state["rule"]["required"]
    lines = [f"registry {state['status']} (serial {state['serial']})"]
    lines += [f"  {w['id']}: {w['metric']} {w['op']} {w['threshold']} {w['scope']} -> "
              f"{w['action']}" for w in state["tripwires"]]  # fmt: skip
    lines += [f"{f['code']}: {f['message']}" for f in state["findings"]]
    return body, lines, not state["findings"]


def _check(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str], bool]:
    from opentine import _tripwire_check as tc
    from opentine._key_hygiene import ed25519_private

    now_ms = args.now_ms if args.now_ms is not None else int(time.time() * 1000)
    result = tc.evaluate(repo, now_ms=now_ms)
    written = tc.record(repo, result, ed25519_private(args.key),
                        now=now_ms / 1000) if args.key else []  # fmt: skip
    lines = [
        f"{r['id']}: {r['metric']} = {r['value']} "
        + (f"TRIPPED -> {r['action']}" if r["tripped"] else "ok")
        for r in result["tripwires"]
    ]
    lines += [f"{f['code']}: {f['message']}" for f in result["findings"]]
    lines += [f"recorded {w['record']} ({w['tripwire']}, {w['action']})" for w in written]
    return {**result, "recorded": written}, lines, result["ok"]


def _trips(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str], bool]:
    from opentine import _tripwire_check as tc

    rows = [{"record": t["oid"], "signer": t["signer"], "counted": t["counted"],
             "claim": t["claim"]} for t in tc.trips(repo)]  # fmt: skip
    lines = [f"{r['record']} {(r['claim'] or {}).get('reason')}"
             + ("" if r["counted"] else " (not counted)") for r in rows]  # fmt: skip
    return {"trips": rows}, lines or ["no trips"], True


HANDLERS = {"add": _edit, "remove": _edit, "list": _list, "check": _check, "trips": _trips}


def cmd_tripwire(args: argparse.Namespace) -> None:
    from opentine._cli_common import _terminal, console
    from opentine._cli_errors import error
    from opentine._cli_json import emit
    from opentine._tripwire_registry import TripwireError
    from opentine.repo import Repo

    verb = args.tripwire_command
    try:
        body, lines, ok = HANDLERS[verb](args, Repo.open(args.repo))
    except TripwireError as exc:
        raise error(exc, 1, prefix=f"tripwire {verb}: ") from exc
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"tripwire {verb}: ") from exc
    if args.json:
        emit({"command": f"tripwire {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False, highlight=False)
    if not ok:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"tripwire": cmd_tripwire}

__all__ = ["COMMANDS", "SCHEMA", "VERBS", "add_tripwire_parser", "cmd_tripwire"]
