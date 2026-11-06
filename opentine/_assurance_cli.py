"""The CLI face of assurance tiers: ``tine proxy keygen`` and ``tine verify`` flags.

* ``tine proxy keygen [--force] [--json]`` makes the proxy key (``_assurance``).
* ``tine verify RUN --min-assurance T0..T3`` exits 4 (verification_failed) when
  the *verified* tier is below the floor; ``--proxy-pubkey FILE`` trusts another
  proxy key; ``--tsa-roots`` (also outside ``--offline`` with a floor) lets a
  timestamp token count toward T3.
* ``tine verify RUN --compare-capture OTHER`` prints the divergence report
  between a proxy capture and an imported transcript (``_capture_diverge``).
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine._assurance import TIERS, assess, line, rank
from opentine._cli_errors import NOT_FOUND, TRUST_REQUIRED, VERIFICATION_FAILED, fail


def add_proxy_parser(sub: Any) -> None:
    proxy = sub.add_parser("proxy", help="Manage the proxy witness key (assurance tier T2)")
    verbs = proxy.add_subparsers(dest="proxy_command")
    keygen = verbs.add_parser("keygen", help="Create the Ed25519 key proxies sign runs with")
    keygen.add_argument("--force", action="store_true", help="Replace an existing proxy key")
    keygen.add_argument("--json", action="store_true", help="Print a JSON object")


def cmd_proxy(args: argparse.Namespace) -> None:
    from opentine import _assurance
    from opentine._cli_common import _terminal, console
    from opentine._cli_json import emit
    from opentine.signing import SignatureError

    if getattr(args, "proxy_command", None) != "keygen":
        fail("name a proxy command: tine proxy keygen", 2)
    try:
        public, fingerprint = _assurance.keygen(force=args.force)
    except FileExistsError as exc:
        fail(exc, prefix="proxy keygen: ")
    except (OSError, SignatureError, ValueError) as exc:
        fail(exc, TRUST_REQUIRED if isinstance(exc, SignatureError) else 1, prefix="proxy keygen: ")
    if getattr(args, "json", False):
        emit({"command": "proxy keygen", "public_key": str(public), "fingerprint": fingerprint})
        return
    console.print(f"Wrote the proxy key; public half {_terminal(public)}")
    console.print(f"fingerprint {fingerprint}")


def add_assurance_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--min-assurance",
        choices=TIERS,
        metavar="TIER",
        help="Fail (exit 4) unless the verified assurance tier is at least TIER (T0..T3)",
    )
    parser.add_argument(
        "--proxy-pubkey",
        action="append",
        metavar="FILE",
        help="Also trust this proxy public key as a T2 witness (repeatable)",
    )
    parser.add_argument(
        "--compare-capture",
        metavar="OTHER",
        help="Report step-by-step divergence between RUN and OTHER (proxy vs import)",
    )


def assurance_for(args: argparse.Namespace, path: Any, *, show: bool = False) -> dict[str, Any]:
    """The run's assurance object; printed as one line on the human path."""
    from opentine.signing import SignatureError

    try:
        found = assess(path, args)
    except (OSError, SignatureError, ValueError) as exc:
        fail(f"cannot assess assurance: {exc}", 1)
    if show:
        from opentine._cli_common import console

        console.print(line(found))
    return found


def floor_failed(args: argparse.Namespace, assurance: dict[str, Any]) -> bool:
    floor = getattr(args, "min_assurance", None)
    return bool(floor) and rank(assurance["verified"]) < rank(floor)


def enforce_floor(args: argparse.Namespace, assurance: dict[str, Any]) -> None:
    """Exit 4 when the verified tier is below ``--min-assurance``."""
    if not floor_failed(args, assurance):
        return
    message = (
        f"assurance {assurance['verified']} is below --min-assurance {args.min_assurance} "
        f"(claimed {assurance['claimed']})"
    )
    if getattr(args, "json", False):  # the report already went to stdout
        from opentine._cli_errors import report, set_json_mode

        previous = set_json_mode(False)  # one JSON object on stdout, the reason on stderr
        report(message, VERIFICATION_FAILED)
        set_json_mode(previous)
        raise SystemExit(VERIFICATION_FAILED)
    fail(message, VERIFICATION_FAILED)


def cmd_compare_capture(args: argparse.Namespace) -> None:
    from opentine import _capture_diverge
    from opentine._cli_common import _find_run, console

    paths = [_find_run(args.run_id), _find_run(args.compare_capture)]
    for given, found in zip((args.run_id, args.compare_capture), paths, strict=True):
        if not found:
            fail(f"run not found: {given}", NOT_FOUND)
    try:
        result = _capture_diverge.compare(paths[0], paths[1], args)
    except (OSError, RecursionError, ValueError) as exc:
        fail(f"cannot compare captures: {exc}", 1)
    if getattr(args, "json", False):
        from opentine._cli_json import emit

        emit(result)
    else:
        for text in _capture_diverge.render(result):
            console.print(text)
    if not result["consistent"]:
        raise SystemExit(VERIFICATION_FAILED)


__all__ = [
    "add_assurance_verify_args",
    "add_proxy_parser",
    "assurance_for",
    "cmd_compare_capture",
    "cmd_proxy",
    "enforce_floor",
    "floor_failed",
]
