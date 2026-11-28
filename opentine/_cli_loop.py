"""``tine loop stop|status`` (0.58): the kill switch for self-improving agent loops.

``loop stop LOOP --ed25519-key-file KEY [--reason T] [--run RUN]`` writes the
signed stop (:mod:`opentine.coord._loop_stop`): every generation of LOOP is then
refused a coord lease (``tine task claim`` and ``heartbeat`` exit 1 with code
``stopped``). ``loop status LOOP`` reports the stop and whether its signature
verifies.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable

from opentine._cli_common import _terminal, console
from opentine._cli_errors import USAGE, error


def add_loop_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._cli_stop import add_stop_parser

    add_stop_parser(subparsers)  # 0.91: tine stop, the fleet-wide stop
    loop = subparsers.add_parser("loop", help="Stop a self-improving agent loop (signed)")
    actions = loop.add_subparsers(dest="loop_command", required=True)
    stop = actions.add_parser("stop", help="Write a signed stop; generations' leases are refused")
    status = actions.add_parser("status", help="Whether a loop is stopped, and by whom")
    for parser in (stop, status):
        parser.add_argument("loop", help="Loop id (lowercase [a-z0-9._-])")
        parser.add_argument("--repo", default=".", metavar="PATH", help="v3 repository")
        parser.add_argument("--json", action="store_true", help="Machine-readable output")
    stop.add_argument("--ed25519-key-file", metavar="FILE", help="The operator's Ed25519 key")
    stop.add_argument("--reason", default="", help="Why the loop is stopped")
    stop.add_argument("--run", metavar="RUN", help="The run that prompted the stop")


def _stop(args: argparse.Namespace, repo) -> dict:
    from opentine._key_hygiene import ed25519_private
    from opentine.coord import _loop_stop

    if not args.ed25519_key_file:
        raise error("loop stop needs --ed25519-key-file: a stop is signed with an Ed25519 key",
                    USAGE, prefix="loop: ")  # fmt: skip
    key = ed25519_private(args.ed25519_key_file)
    _loop_stop.stop(repo, args.loop, key, reason=args.reason, run=args.run)
    return _loop_stop.loop_state(repo, args.loop)


def cmd_loop(args: argparse.Namespace) -> None:
    from opentine.coord import _loop_stop
    from opentine.repo import Repo

    try:
        repo = Repo.open(args.repo)
        if args.loop_command == "stop":
            state = _stop(args, repo)
        else:
            state = _loop_stop.loop_state(repo, args.loop)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix="loop: ") from exc
    if args.json:
        body = {"command": f"loop {args.loop_command}", "schema": "tine-cli-loop/1",
                "loop": state}  # fmt: skip
        sys.stdout.write(json.dumps(body, sort_keys=True) + "\n")
        return
    line = f"{state['loop']}: {state['status']}"
    if state["status"] == "stopped":
        line += f" by {state['signer']} ({state['verification']}) stop={state['stop']}"
    console.print(_terminal(line), markup=False)


from opentine._cli_stop import COMMANDS as _STOP_COMMANDS  # noqa: E402 - after cmd_loop

COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"loop": cmd_loop, **_STOP_COMMANDS}

__all__ = ["COMMANDS", "add_loop_parser", "cmd_loop"]
