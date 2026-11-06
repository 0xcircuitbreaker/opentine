"""``tine fleet up|status|stop|cost``: run a declared fleet of agents.

``tine fleet up fleet.toml --trust`` reviews-then-trusts the manifest's exact
bytes and runs its members (``--dry-run`` lists them, running nothing);
``status [ID]`` shows a fleet's members (every fleet without ID; with
``--repo PATH``, the repository's ``tine fan-out`` records instead); ``stop ID``
asks the running ``up`` to kill every member's process tree; ``cost ID`` sums
the members' reported costs. ``cost --repo PATH RUN`` instead totals a fleet
recorded by ``tine import --fleet`` (each shared step counted once). ``--dir``
is the state directory (default ``.tine_fleet``, beside the manifest for ``up``).
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from collections.abc import Callable
from pathlib import Path

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_errors import error


def add_fleet_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("fleet", help="Run a declared fleet of agents (fleet.toml)")
    parser.add_argument("action", choices=("up", "status", "stop", "cost"))
    parser.add_argument("target", nargs="?", help="fleet.toml (up), a fleet ID, or a RUN")
    parser.add_argument("--trust", action="store_true", help="Trust this manifest's exact bytes")
    parser.add_argument("--dry-run", action="store_true", help="up: list members, run nothing")
    parser.add_argument("--dir", metavar="DIR", help="Fleet state directory")
    parser.add_argument("--repo", metavar="PATH", help="cost: an imported fleet; status: fan-outs")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")


def _fail(message: object) -> SystemExit:
    return error(message, prefix="fleet: ")


def _up(args: argparse.Namespace) -> int:
    from opentine.fleet import _manifest, _runner

    if not args.target:
        raise _fail("up needs a fleet.toml")
    path = Path(args.target)
    if args.dry_run:
        with open(path, "rb") as handle:
            fleet = _manifest.parse(handle.read(_manifest.MAX_BYTES + 1), path)
        rows = []
        for row in _runner.plan(fleet):
            agent = next(a for a in fleet.agents if a.name == row["vary"]["agent"])
            rows.append({"key": row["key"], "agent": agent.name, "role": agent.role,
                         "argv": list(agent.argv)})  # fmt: skip
        if args.json:
            out = {"command": "fleet up", "dry_run": True, "fleet": fleet.name, "members": rows}
            sys.stdout.write(json.dumps(out) + "\n")
        for row in [] if args.json else rows:
            console.print(f"  [{row['key']}] {row['agent']} ({row['role']}): {row['argv']}",
                          markup=False)  # fmt: skip
        return 0
    fleet = _manifest.load(path, trust_now=args.trust)
    state = _runner.create(fleet)
    if not args.json:
        count = len(state.data["members"])
        console.print(f"[{BRAND}]# Fleet[/] {fleet.name} id {state.id} ({count} "
                      f"members, {fleet.layout}); stop with: tine fleet stop {state.id} --dir "
                      f"{_terminal(state.directory)}")  # fmt: skip
        return _runner.run(fleet, state)
    code = _runner.run(fleet, state, out=io.StringIO())  # progress lines would corrupt JSON
    out = {"command": "fleet up", "dry_run": False, "fleet": fleet.name, "id": state.id,
           "exit_code": code, "members": state.data["members"]}  # fmt: skip
    sys.stdout.write(json.dumps(out) + "\n")
    return code


def _directory(args: argparse.Namespace) -> Path:
    from opentine.fleet._runner import STATE_DIR

    return Path(args.dir or STATE_DIR)


def _status(args: argparse.Namespace) -> int:
    from opentine.parallel._state import State

    kind, directory = "fleet", _directory(args)
    if args.repo:  # `status --repo PATH`: the repository's `tine fan-out` records
        from opentine.repo import Repo

        kind, directory = "fan-out", Repo.open(args.repo).path / "fanouts"
    ids = [args.target] if args.target else sorted(p.stem for p in directory.glob("*.json"))
    rows = []
    for fleet_id in ids:
        state = State.load(directory, fleet_id)
        if state.data["source"].get("kind") != kind:
            continue
        rows.append({"id": fleet_id, "name": state.data["source"].get("name"),
                     "members": state.data["members"]})  # fmt: skip
    if args.json:
        noun = "fanout" if args.repo else "fleet"
        out = {"command": f"{noun} status", f"{noun}s": rows}
        sys.stdout.write(json.dumps(out) + "\n")
        return 0
    for row in rows:
        console.print(f"[{BRAND}]{row['id']}[/] {_terminal(row['name'])}")
        for member in row["members"]:
            cost = f" ${_terminal(member['cost'])}" if member["cost"] is not None else ""
            agent, status = _terminal(member["vary"]["agent"]), _terminal(member["status"])
            console.print(f"  [{_terminal(member['key'])}] {agent:<20} "
                          f"{status:<8}{cost}", markup=False)  # fmt: skip
    return 0


def _cost(args: argparse.Namespace) -> int:
    if args.repo:
        from opentine._import_fleet import fleet_cost
        from opentine.repo import Repo

        repo = Repo.open(args.repo)
        try:
            run_id = repo.read_ref(args.target or "") or args.target
        except ValueError:
            run_id = args.target
        run = repo.load_run(run_id)
        manifest = run.metadata.get("opentine.fleet") if isinstance(run.metadata, dict) else None
        if not isinstance(manifest, dict) or "members" not in manifest:
            raise _fail("that run is not the root of an imported fleet")
        total, unknown, fleet_id = fleet_cost(repo, manifest), 0, manifest["root"]
    else:
        from opentine.fleet._runner import cost
        from opentine.parallel._state import State

        state = State.load(_directory(args), args.target or "")
        (total, unknown), fleet_id = cost(state), state.id
    if args.json:
        out = {"command": "fleet cost", "fleet": fleet_id, "cost_usd": str(total),
               "unknown_members": unknown}  # fmt: skip
        sys.stdout.write(json.dumps(out) + "\n")
    else:
        note = f" ({unknown} member(s) reported no cost)" if unknown else ""
        console.print(f"fleet {_terminal(fleet_id)}: ${_terminal(total)}{note}")
    return 0


def cmd_fleet(args: argparse.Namespace) -> None:
    try:
        if args.action == "up":
            raise SystemExit(_up(args))
        if args.action == "status":
            raise SystemExit(_status(args))
        if args.action == "cost":
            raise SystemExit(_cost(args))
        from opentine.fleet._runner import request_stop

        path = request_stop(_directory(args), args.target or "")
        console.print(f"stop requested: {_terminal(path)}")
    except (OSError, ValueError) as exc:
        raise _fail(exc) from exc


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"fleet": cmd_fleet}

__all__ = ["COMMANDS", "add_fleet_parser", "cmd_fleet"]
