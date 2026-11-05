"""``--json`` on every leaf command (0.36, A3).

Commands with their own JSON payload keep it unchanged; when one fails without
writing JSON, its human text goes to stderr and stdout gets the
``{"error": {...}}`` object of ``opentine._cli_errors``. Every other leaf parser
gets a ``--json`` that wraps the command's human output in one object::

    {"command": "fsck", "exit_code": 0, "output": "..."}

and, when the command fails, the ``{"error": {...}}`` object of
``opentine._cli_errors`` plus the output captured before it. Only Python-level
stdout is captured: a child process that writes to the terminal directly (an
agent under ``tine record``) still does. ``output.format = json`` does not turn
this wrapper on: those commands stay exactly what they were unless ``--json``
is typed.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from collections.abc import Callable

from opentine import _cli_errors

FALLBACK_DEST = "json_fallback"
#: v3 plumbing verbs whose output is always bare JSON: ``--json`` is a no-op on them.
BARE_JSON_VERBS = ("fsck", "object", "migrate-v3", "fetch", "push")


def add_json_fallback(parser: argparse.ArgumentParser, seen: set[int] | None = None) -> None:
    """Give every leaf parser without ``--json`` the wrapping one."""
    seen = set() if seen is None else seen
    if id(parser) in seen:
        return
    seen.add(id(parser))
    children = [
        child
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
        for child in action.choices.values()
    ]
    for child in children:
        add_json_fallback(child, seen)
    if children or "--json" in parser._option_string_actions:
        return
    if parser.prog.split()[1:] in ([verb] for verb in BARE_JSON_VERBS):
        parser.add_argument("--json", action="store_true", help="Accepted; output is always JSON")
        return
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit {command, exit_code, output} JSON (errors as {error: {code, message}})",
    )
    parser.set_defaults(**{FALLBACK_DEST: True})


def _name(args: argparse.Namespace) -> str:
    action = getattr(args, "action", None)
    return " ".join(w for w in (args.command, action if isinstance(action, str) else None) if w)


def _exit_code(exc: SystemExit) -> int:
    if exc.code is None:
        return 0
    return exc.code if isinstance(exc.code, int) else 1


class _Tee(io.StringIO):
    """Pass stderr through while keeping a copy for the JSON error's message."""

    def __init__(self, target) -> None:
        super().__init__()
        self.target = target

    def write(self, text: str) -> int:
        self.target.write(text)
        return super().write(text)

    def flush(self) -> None:
        self.target.flush()


def _is_json(text: str) -> bool:
    lines = [line for line in text.splitlines() if line.strip()]
    try:  # one (possibly indented) document, or JSON lines
        return json.loads(text) is not None
    except ValueError:
        pass
    try:
        return bool(lines) and all(json.loads(line) is not None for line in lines)
    except ValueError:
        return False


def _last_line(*texts: str) -> str:
    """The last paragraph of the first non-empty text, its wrapped lines rejoined."""
    for text in texts:
        blocks = [b for b in text.replace("\r\n", "\n").split("\n\n") if b.strip()]
        if blocks:
            return " ".join(line.strip() for line in blocks[-1].splitlines() if line.strip())
    return "command failed"


def run_with_json(args: argparse.Namespace, run: Callable[[], None]) -> None:
    """Run one command; under ``--json`` stdout carries only JSON, errors included.

    A command's own JSON passes through unchanged (on failure too: a verdict is
    still a verdict). Human text a failing JSON command printed goes to stderr
    instead, and the error object takes its place; a fallback ``--json`` command
    has its whole output wrapped.
    """
    _cli_errors.set_json_mode(False)  # the error object is written once, below
    if not getattr(args, "json", False):
        run()
        return
    fallback = getattr(args, FALLBACK_DEST, False)
    out, err, code, exited = io.StringIO(), _Tee(sys.stderr), 0, False
    _cli_errors.last_error["message"] = None
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            run()
    except SystemExit as exc:
        code, exited = _exit_code(exc), True
        if code and isinstance(exc.code, str):
            _cli_errors.last_error["message"] = exc.code
            print(f"tine: {exc.code}", file=sys.stderr)
    except Exception:
        sys.stderr.write(out.getvalue())
        _cli_errors.set_json_mode(True)  # guarded_dispatch reports it as JSON
        raise
    text = out.getvalue()
    message = _cli_errors.last_error["message"] or _last_line(err.getvalue(), text)
    if fallback:
        payload: dict = {"command": _name(args), "exit_code": code, "output": text}
        if code:
            payload.update(_cli_errors.error_payload(message, code))
        sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    elif not code or _is_json(text):
        sys.stdout.write(text)
    else:
        sys.stderr.write(text)
        sys.stdout.write(json.dumps(_cli_errors.error_payload(message, code), sort_keys=True))
        sys.stdout.write("\n")
    if code or exited:  # a handler's own `raise SystemExit(0)` stays an exit
        raise SystemExit(code)


def dispatch(args: argparse.Namespace, run: Callable[[], None]) -> None:
    """``guarded_dispatch`` with this invocation's ``--json`` error contract."""
    from opentine._cli_guard import guarded_dispatch

    try:
        guarded_dispatch(lambda: run_with_json(args, run))
    finally:
        _cli_errors.set_json_mode(False)


def parse_reporting_usage(argv: list[str], parse: Callable) -> tuple:
    """``parse(argv)``; a usage error (exit 2) under ``--json`` also emits JSON."""
    if "--json" not in argv:
        return parse(argv)
    captured = io.StringIO()
    try:
        with contextlib.redirect_stderr(captured):
            return parse(argv)
    except SystemExit as exc:
        if exc.code == _cli_errors.USAGE:
            lines = [line for line in captured.getvalue().splitlines() if line.strip()]
            message = lines[-1] if lines else "usage error"
            payload = _cli_errors.error_payload(message, _cli_errors.USAGE)
            sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
        raise
    finally:
        sys.stderr.write(captured.getvalue())


__all__ = [
    "FALLBACK_DEST",
    "add_json_fallback",
    "dispatch",
    "parse_reporting_usage",
    "run_with_json",
]
