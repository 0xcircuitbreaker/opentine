"""``tine timestamp data RUN`` and ``tine timestamp attach RUN TOKEN.tsr`` (0.31.0).

``data`` writes the exact bytes an RFC 3161 token for RUN must cover (the run's
digest string, no newline) so a query can be built offline::

    tine timestamp data run.tine > bound.txt
    openssl ts -query -data bound.txt -sha256 -cert -out q.tsq

Sending ``q.tsq`` to a TSA is the user's job; opentine never contacts one.
``attach`` checks that the response parses and that its messageImprint covers
the run's current digest, then stores it beside the run
(``_timestamp_sidecar``). It does not judge trust: ``tine verify RUN --offline
--tsa-roots FILE.pem`` does.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any

from opentine._cli_common import _find_run, _terminal, console

MAX_TOKEN = 256 * 1024


def add_timestamp_parser(sub: Any) -> None:
    stamp = sub.add_parser("timestamp", help="Attach an RFC 3161 timestamp token to a run")
    actions = stamp.add_subparsers(dest="timestamp_command", required=True)
    data = actions.add_parser("data", help="Print the bytes a timestamp token must cover")
    data.add_argument("run_id", metavar="RUN")
    attach = actions.add_parser("attach", help="Store a TSA response beside the run")
    attach.add_argument("run_id", metavar="RUN")
    attach.add_argument("token", metavar="TOKEN.tsr", help="DER TimeStampResp or token")


def _fail(message: str) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(1)


def _bound(run_id: str) -> tuple[Path, str]:
    from opentine._timestamp_sidecar import bound_string
    from opentine.core import Run

    path = _find_run(run_id)
    if path is None or not Path(path).is_file():
        _fail(f"Run not found: {run_id}")
    result = Run.verify_integrity(path)
    bound = bound_string(result)
    if bound is None:
        _fail(f"{path}: integrity check failed ({result.reason}); refusing to timestamp it")
    return Path(path), bound


def cmd_timestamp(args: argparse.Namespace) -> None:
    from opentine import _timestamp_sidecar as sidecar
    from opentine._tsp import HASHES, parse

    path, bound = _bound(args.run_id)
    if args.timestamp_command == "data":
        sys.stdout.write(bound)
        sys.stdout.flush()
        return
    try:
        with open(args.token, "rb") as handle:
            raw = handle.read(MAX_TOKEN + 1)
    except OSError as exc:
        _fail(f"cannot read {args.token}: {exc}")
    if len(raw) > MAX_TOKEN:
        _fail(f"{args.token} exceeds {MAX_TOKEN} bytes")
    try:
        token = parse(raw)
    except ValueError as exc:
        _fail(f"{args.token} is not an RFC 3161 timestamp token: {exc}")
    if token.hash_oid not in HASHES:
        _fail(f"unsupported imprint hash {token.hash_oid}")
    if hashlib.new(token.hash_name, bound.encode("utf-8")).digest() != token.imprint:
        _fail(f"the token does not cover this run's digest {bound}; see `tine timestamp data`")
    try:
        added = sidecar.attach(path, bound, raw)
    except (OSError, ValueError) as exc:
        _fail(f"cannot store the token: {exc}")
    where = _terminal(str(sidecar.sidecar_path(path)))
    if added:
        console.print(f"[green]attached[/] timestamp {token.gen_time.isoformat()} -> {where}")
    else:
        console.print(f"already attached -> {where}")


COMMANDS = {"timestamp": cmd_timestamp}

__all__ = ["COMMANDS", "add_timestamp_parser", "cmd_timestamp"]
