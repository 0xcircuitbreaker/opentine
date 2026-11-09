"""``tine watch [REMOTE|REPO]``: tail a remote's event stream or a repository's op log (0.45.1).

A URL or a configured remote name reads ``GET /v1/tenants/<t>/events`` (SSE)
and reconnects with ``Last-Event-ID`` when the server closes the stream; a
``reset`` from the server (events were missed) is printed so a script can
re-list refs. Anything else is a local repository whose op log is polled every
``--interval`` seconds; each new op is an ``op.logged`` event. ``--json``
writes one ``tine-watch/1`` object per line (JSON Lines).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_share import SHARE_COMMANDS, add_share_parsers

MAX_LINE = 1 << 20


def add_watch_parser(sub: argparse._SubParsersAction) -> None:
    add_share_parsers(sub)  # 0.46: tine share create|revoke|list, tine open
    watch = sub.add_parser("watch", help="Tail a remote's events (SSE) or a repository's op log")
    watch.add_argument("target", nargs="?", help="Remote URL or name, or a repository path")
    watch.add_argument("--repo", default=".", help="Repository whose remotes name TARGET")
    watch.add_argument("--tenant")
    watch.add_argument("--token", help=argparse.SUPPRESS)
    watch.add_argument("--token-file")
    watch.add_argument("--allow-insecure", action="store_true")
    watch.add_argument("--interval", type=float, default=2.0, help="Op-log poll seconds")
    watch.add_argument("--from-start", action="store_true", help="Print ops already logged")
    watch.add_argument("--once", action="store_true", help="One stream or one poll, then exit")
    watch.add_argument("--max-events", type=int, help="Exit after this many events")
    watch.add_argument("--timeout", type=float, default=60.0, help="Per-request seconds")
    watch.add_argument("--json", action="store_true", help="One tine-watch/1 object per line")


def parse_sse(lines: Iterator[str]) -> Iterator[dict[str, Any]]:
    """``{"event", "id", "data"}`` per dispatched SSE frame (comments skipped)."""
    frame: dict[str, Any] = {"data": []}
    for line in lines:
        if len(line) > MAX_LINE:
            raise ValueError("event stream line is too long")
        if not line:
            if frame["data"] or frame.get("event"):
                yield {**frame, "data": "\n".join(frame["data"])}
            frame = {"data": []}
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if field == "data":
            frame["data"].append(value)
        elif field in {"event", "id"}:
            frame[field] = value


def _remote_frames(args, base: str, tenant: str, token, last: str | None):
    from opentine.repository._http import client

    headers = {"Accept": "text/event-stream", **({"Last-Event-ID": last} if last else {})}
    path = f"/v1/tenants/{quote(tenant, safe='')}/events"
    with client(base, token, allow_insecure=args.allow_insecure, timeout=args.timeout) as http:
        with http.stream("GET", path, headers=headers) as response:
            if response.status_code != 200:
                raise ValueError(f"event stream refused: HTTP {response.status_code}")
            yield from parse_sse(response.iter_lines())


def _emit(args, event: dict[str, Any] | None) -> None:
    if args.json:
        from opentine._cli_json import serialize

        body = {"event": event} if event is not None else {"reset": True}
        print(serialize({"command": "watch", "schema": "tine-watch/1", **body}, indent=None))
    elif event is None:
        console.print(f"[{BRAND}]# reset[/]: events were missed; re-list refs")
    else:
        data = event["data"]
        what = data.get("name") or data.get("command") or data.get("size") or data.get("total")
        when, kind = _terminal(str(event.get("time"))), _terminal(str(event.get("kind")))
        console.print(f"{when} [{BRAND}]{kind}[/] {_terminal(str(what))}")
    sys.stdout.flush()


def _watch_remote(args, base: str, tenant: str, token) -> None:
    import httpx

    seen, last, failures = 0, None, 0
    while True:
        try:
            for frame in _remote_frames(args, base, tenant, token, last):
                failures = 0
                if frame.get("event") == "reset":
                    _emit(args, None)
                    continue
                event = json.loads(frame["data"])
                if not isinstance(event, dict) or not isinstance(event.get("data"), dict):
                    raise ValueError("event stream sent a malformed event")
                last = frame.get("id") or last
                _emit(args, event)
                seen += 1
                if args.max_events and seen >= args.max_events:
                    return
        except (OSError, ValueError, httpx.HTTPError) as exc:
            failures += 1
            if args.once or failures > 5:
                raise
            print(f"tine watch: {_terminal(exc)}; reconnecting", file=sys.stderr)
            time.sleep(min(30.0, 2.0**failures))
        if args.once:
            return


def _op_event(op: dict[str, Any]) -> dict[str, Any]:
    stamp = int(op["time_ns"]) / 1e9
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))
    return {"data": op, "format": "tine-event/1", "id": op["id"], "kind": "op.logged",
            "tenant": None, "time": when}  # fmt: skip


def _watch_local(args, path: str) -> None:
    from opentine._cli_du import _repo
    from opentine.repository._oplog import read_ops

    repo = _repo(path)
    shown = 0 if args.from_start else len(read_ops(repo.path))
    seen = 0
    while True:
        ops = read_ops(repo.path)
        for op in ops[shown:]:
            _emit(args, _op_event(op))
            seen += 1
            if args.max_events and seen >= args.max_events:
                return
        shown = len(ops)
        if args.once:
            return
        time.sleep(args.interval)


def cmd_watch(args: argparse.Namespace) -> None:
    import httpx

    from opentine import _porcelain_config as porcelain
    from opentine._cli_errors import fail
    from opentine._repo_cli_token import _token
    from opentine.repository._http import split_remote

    if args.interval <= 0 or args.timeout <= 0 or (args.max_events or 1) < 1:
        fail("--interval, --timeout and --max-events must be positive", prefix="tine watch: ")
    target = args.target
    try:
        if target and "://" not in target:
            from opentine._cli_du import _repo

            try:
                entry = porcelain.remote(_repo(args.repo).path, target)
            except (KeyError, OSError, ValueError):
                entry = None
            if entry is not None:
                target = entry["url"]
                args.tenant = args.tenant or entry.get("tenant")
                if not args.token and not args.token_file:
                    args.token_file = entry.get("token_file")
        if target and "://" in target:
            base, tenant = split_remote(target, args.tenant)
            _watch_remote(args, base, tenant, _token(args))
        else:
            _watch_local(args, target or args.repo)
    except KeyboardInterrupt:
        return
    except (KeyError, OSError, ValueError, httpx.HTTPError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(message, prefix="tine watch: ")


WATCH_COMMANDS = {"watch": cmd_watch, **SHARE_COMMANDS}  # 0.46: share-link, open

__all__ = ["WATCH_COMMANDS", "add_watch_parser", "cmd_watch", "parse_sse"]
