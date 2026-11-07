"""``tine fleet resume|logs|send`` (0.43), beside ``up|status|stop|cost``.

* ``resume fleet.toml --id ID [--trust]`` runs the members of fleet ``ID`` that
  did not finish (``ok``/``failed``), from the same trusted manifest: the
  recorded manifest digest must match, so a different manifest cannot reuse
  the record.
* ``logs ID [--member KEY]`` prints each member's captured output.
* ``send ID --member M --message TEXT --repo PATH`` queues a steer message in
  the member's ``opentine-coord/1`` mailbox; its hook delivers it at the next
  turn end and records it as a step (:mod:`opentine._hook_mailbox`). ``M`` is
  the member's key (``0``) or name (``coder-0``).
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

from opentine._cli_common import _terminal, console

MAX_LOG_BYTES = 4 * 1024 * 1024


def _state(directory: Path, fleet_id: str):
    from opentine.parallel._state import State

    state = State.load(directory, fleet_id)
    if state.data["source"].get("kind") != "fleet":
        raise ValueError(f"{fleet_id} is not a fleet")
    return state


def resume(args: argparse.Namespace) -> int:
    from opentine.fleet import _manifest, _runner

    if not args.target or not args.id:
        raise ValueError("resume needs a fleet.toml and --id ID")
    fleet = _manifest.load(Path(args.target), trust_now=args.trust)
    state = _state(Path(args.dir) if args.dir else _runner.state_dir(fleet.root), args.id)
    if state.data["command_digest"] != fleet.digest:
        raise ValueError(f"this manifest is not the one fleet {args.id} was started from")
    if not args.json:
        return _runner.run(fleet, state)
    code = _runner.run(fleet, state, out=io.StringIO())
    out = {"command": "fleet resume", "fleet": fleet.name, "id": state.id, "exit_code": code,
           "members": state.data["members"]}  # fmt: skip
    sys.stdout.write(json.dumps(out) + "\n")
    return code


def _read_log(path: Path) -> str | None:
    try:
        with open(path, "rb") as handle:
            return handle.read(MAX_LOG_BYTES).decode("utf-8", errors="replace")
    except FileNotFoundError:
        return None


def logs(args: argparse.Namespace, directory: Path) -> int:
    state = _state(directory, args.target or "")
    keys = [m["key"] for m in state.data["members"]]
    if args.member is not None and args.member not in keys:
        raise ValueError(f"fleet {state.id} has no member {args.member}")
    rows = {key: _read_log(directory / state.id / f"{key}.log")
            for key in keys if args.member in (None, key)}  # fmt: skip
    if args.json:
        sys.stdout.write(json.dumps({"command": "fleet logs", "id": state.id, "logs": rows}) + "\n")
        return 0
    for key, text in rows.items():
        console.print(f"==> member {key} <==", markup=False)
        console.print(_terminal(text if text is not None else "(no output yet)"), markup=False)
    return 0


def _member_name(directory: Path, fleet_id: str, member: str) -> str:
    if not member.isdigit():
        return member
    try:
        state = _state(directory, fleet_id)
    except (OSError, ValueError):
        return member
    for entry in state.data["members"]:
        if entry["key"] == member:
            return f"{entry['vary']['agent']}-{member}"
    raise ValueError(f"fleet {fleet_id} has no member {member}")


def send(args: argparse.Namespace, directory: Path) -> int:
    from opentine.coord._mailbox import ref_name
    from opentine.coord._mailbox import send as queue
    from opentine.repo import Repo

    if not args.target or not args.member or not args.message or not args.repo:
        raise ValueError("send needs ID, --member, --message and --repo")
    member = _member_name(directory, args.target, args.member)
    message = queue(Repo.open(args.repo), args.target, member, args.message)
    mailbox = ref_name(args.target, member)
    if args.json:
        out = {"command": "fleet send", "id": args.target, "mailbox": mailbox, "message": message}
        sys.stdout.write(json.dumps(out) + "\n")
    else:
        console.print(f"queued message {message['id']} in {_terminal(mailbox)}", markup=False)
    return 0


__all__ = ["logs", "resume", "send"]
