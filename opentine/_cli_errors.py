"""One way for a ``tine`` command to fail: a stderr line, and JSON under ``--json``.

0.36 (A1/A2) replaces the per-module ``_fail`` helpers, which printed the error
on stdout -- where a script parsing ``--json`` output read it as a corrupt
payload. A refusal now writes one human line to stderr and, when the invocation
asked for ``--json``, one ``{"error": {"code": ..., "message": ...}}`` object on
stdout, then exits with a documented status (docs/CLI.md "Exit codes"):

==  ===================  ==================================================
0   ok
1   error                any other failure
2   usage                bad flags or arguments (argparse, refused combos)
3   not_found            a run, ref or object that does not exist
4   verification_failed  a signature, digest or verdict did not hold
5   budget_exhausted     a budget or limit stopped the work
6   trust_required       needs a trust decision or is unsupported here
==  ===================  ==================================================
"""

from __future__ import annotations

import json
import sys
from typing import NoReturn

from rich.console import Console

OK, ERROR, USAGE, NOT_FOUND, VERIFICATION_FAILED, BUDGET_EXHAUSTED, TRUST_REQUIRED = range(7)
CODES = {
    ERROR: "error",
    USAGE: "usage",
    NOT_FOUND: "not_found",
    VERIFICATION_FAILED: "verification_failed",
    BUDGET_EXHAUSTED: "budget_exhausted",
    TRUST_REQUIRED: "trust_required",
}

_state = {"json": False}
#: The last error reported, for a caller that renders it later (the --json fallback).
last_error: dict[str, str | None] = {"message": None}


def set_json_mode(enabled: bool) -> bool:
    """Whether errors are also emitted as JSON on stdout; returns the old mode."""
    previous, _state["json"] = _state["json"], bool(enabled)
    return previous


def json_mode() -> bool:
    return _state["json"]


def error_payload(message: object, code: int = ERROR) -> dict:
    """The ``--json`` error object; ``code`` is the exit status's documented name."""
    from opentine._cli_text import plain_text

    name = CODES.get(code, "error")
    return {"error": {"code": name, "exit_code": code, "message": plain_text(message)}}


def report(message: object, code: int = ERROR, *, prefix: str = "") -> None:
    """Write *message* to stderr, and its JSON form to stdout under ``--json``."""
    from opentine._cli_common import _terminal

    text = f"{prefix}{message}"
    last_error["message"] = text
    Console(stderr=True, emoji=False).print(f"[red]{_terminal(text)}[/]")
    if json_mode():
        sys.stdout.write(json.dumps(error_payload(text, code), sort_keys=True) + "\n")
        sys.stdout.flush()


def error(message: object, code: int = ERROR, *, prefix: str = "") -> SystemExit:
    """Report *message* and return the ``SystemExit`` the caller raises."""
    report(message, code, prefix=prefix)
    return SystemExit(code)


def fail(
    message: object, code: int = ERROR, *, prefix: str = "", cause: BaseException | None = None
) -> NoReturn:
    """Report *message* and exit with *code*."""
    raise error(message, code, prefix=prefix) from cause


__all__ = [
    "CODES",
    "USAGE",
    "error",
    "error_payload",
    "fail",
    "json_mode",
    "report",
    "set_json_mode",
]
