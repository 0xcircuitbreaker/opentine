"""``log`` and ``show`` front the read-only verbs: ``tine log --search Q`` is ``tine search Q``.

0.17 folds ``ls``, ``search``, ``cost`` and ``price`` into the two everyday
inspect verbs without moving them:

* ``tine log --search QUERY`` -> ``tine search QUERY`` (``--json``/``--repo``/``--legacy`` kept);
* ``tine log --legacy`` or ``tine log`` with an ``ls`` filter -> ``tine ls`` (``log``
  reads the v3 repository and ``ls`` the legacy runs index, so the plain ``log``
  output is unchanged and ``--legacy`` selects the other listing);
* ``tine show RUN --cost`` -> ``tine cost RUN``;
* ``tine show RUN --price [--at DATE]`` -> ``tine price RUN [--at DATE]``.

Like the noun groups, the fold is an argv rewrite before the real parse, so the
new spelling is parsed by the old verb's parser and reaches the same handler with
the same Namespace. The folded flags are declared on ``log``/``show`` too, so they
show in ``--help`` and the invocation is first parsed whole: a flag the target verb
does not take is a usage error (exit 2), never silently dropped.
"""

from __future__ import annotations

import argparse

# The `ls` filters, as (dest, flag); declared on `log` with the same types as on `ls`.
_FILTERS = (
    ("tag", "--tag"),
    ("model", "--model"),
    ("status", "--status"),
    ("cost_min", "--cost-min"),
    ("cost_max", "--cost-max"),
    ("since", "--since"),
    ("until", "--until"),
    ("grep", "--grep"),
)
# `log`-only options and the flag that spells each, for conflict messages.
_LOG_ONLY = (
    ("ref", "REF"),
    ("graph", "--graph"),
    ("all", "--all"),
    ("oneline", "--oneline"),
    ("commit", "--commit"),
    ("pr", "--pr"),
)


def add_fold_args(sub: argparse._SubParsersAction) -> None:
    """The folded flags on ``log`` and ``show``; they only ever reach an argv rewrite."""
    log = sub.choices["log"]
    log.add_argument("--search", metavar="QUERY", help="Search runs (what `tine search` does)")
    log.add_argument(
        "--legacy", action="store_true", help="List legacy .tine runs (what `tine ls` does)"
    )
    for dest, flag in _FILTERS:
        repeat = dest in {"tag", "grep"}
        kind = float if dest.startswith("cost") else str
        log.add_argument(
            flag,
            dest=dest,
            action="append" if repeat else "store",
            default=[] if repeat else None,
            type=kind,
            help=f"Filter legacy runs, as `tine ls {flag}` (implies --legacy)",
        )
    show = sub.choices["show"]
    show.add_argument("--cost", action="store_true", help="Recorded cost (what `tine cost` does)")
    show.add_argument(
        "--price", action="store_true", help="Re-price from the catalog (what `tine price` does)"
    )
    show.add_argument("--at", metavar="DATE", help="With --price: the catalog effective on DATE")


def rewrite(parser: argparse.ArgumentParser, argv: list[str]) -> list[str]:
    """The old-verb argv a folded ``log``/``show`` spelling stands for; else *argv*."""
    if not argv or argv[0] not in {"log", "show"}:
        return argv
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    verb = sub.choices[argv[0]]
    args = parser.parse_args(argv)
    if argv[0] == "log":
        return _log(verb, args, argv)
    return _show(verb, args, argv)


def _given(argv: list[str], flag: str) -> bool:
    return any(token == flag or token.startswith(f"{flag}=") for token in argv)


def _refuse(verb: argparse.ArgumentParser, mode: str, args, names) -> None:
    for dest, flag in names:
        if getattr(args, dest) not in (None, False, []):
            verb.error(f"{flag} cannot be combined with {mode}")


def _log(verb, args, argv: list[str]) -> list[str]:
    json = ["--json"] if args.json else []
    if args.search is not None:
        _refuse(verb, "--search", args, (*_LOG_ONLY, ("limit", "--limit"), *_FILTERS))
        repo = ["--repo", args.repo] if _given(argv, "--repo") else []
        legacy = ["--legacy"] if args.legacy else []
        return ["search", args.search, *json, *repo, *legacy]
    if not (args.legacy or any(getattr(args, dest) not in (None, []) for dest, _ in _FILTERS)):
        return argv
    mode = "--legacy or an ls filter"
    _refuse(verb, mode, args, _LOG_ONLY)
    if _given(argv, "--repo"):
        verb.error(f"--repo cannot be combined with {mode}")
    out = ["ls"]
    for dest, flag in _FILTERS:
        value = getattr(args, dest)
        for item in value if isinstance(value, list) else [value]:
            out += (
                [flag, repr(item) if isinstance(item, float) else item] if item is not None else []
            )
    limit = ["--limit", str(args.limit)] if args.limit is not None else []
    return [*out, *limit, *json]


def _show(verb, args, argv: list[str]) -> list[str]:
    if args.cost and args.price:
        verb.error("--cost cannot be combined with --price")
    if args.at is not None and not args.price:
        verb.error("--at requires --price")
    if not (args.cost or args.price):
        return argv
    mode = "--cost" if args.cost else "--price"
    _refuse(verb, mode, args, (("legacy", "--legacy"), ("repo", "--repo")))
    json = ["--json"] if args.json else []
    at = ["--at", args.at] if args.at is not None else []
    return [mode[2:], args.run_id, *at, *json]


__all__ = ["add_fold_args", "rewrite"]
