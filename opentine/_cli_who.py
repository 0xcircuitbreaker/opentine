"""``tine who``, ``tine actions``, ``tine touched`` and ``tine audit``.

Which agents did what: every command reads the action index (see
:mod:`opentine._actions_db`), which it brings up to date first. Without
``--repo`` they cover the legacy runs directory; with ``--repo PATH`` the runs
a v3 repository's refs point at.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine import _cli_who_trust as who_trust
from opentine._actions import extract_actions
from opentine._actions_db import ActionIndex, SyncReport
from opentine._actions_policy import evaluate, load_policy
from opentine._actions_query import (
    GROUP_KEYS,
    ActionQuery,
    ActionQueryError,
    find,
    group,
    parse_time,
    redacted_misses,
)
from opentine._actions_source import open_repo, open_runs_dir
from opentine._cli_actions_sign import require_signed, sign_or_verify
from opentine._cli_agent import cmd_agent
from opentine._cli_common import _find_run, _runs_dir, _terminal, console
from opentine._cli_who_parser import _FILTERS, add_actions_parsers
from opentine._cli_who_render import emit_or_print, print_audit, render_actions, render_groups


def _fail(message: str) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(2)


def _open(args: argparse.Namespace, *, fresh: bool = False) -> tuple[ActionIndex, SyncReport]:
    try:
        if args.repo:
            from opentine.repository import Repo

            return open_repo(Repo.open(args.repo), fresh=fresh)
        return open_runs_dir(_runs_dir(), fresh=fresh)
    except (OSError, ValueError) as exc:
        _fail(f"Cannot index actions: {exc}")
        raise  # unreachable


def _query(args: argparse.Namespace) -> ActionQuery:
    query = ActionQuery(cmd=list(getattr(args, "cmd", []) or []))
    for flag, _ in _FILTERS:
        name = flag[2:]
        value = getattr(args, name, None)
        if value:
            setattr(query, name, parse_time(value) if name in ("since", "until") else value)
    query.errors = bool(getattr(args, "errors", False))
    return query


def _group_keys(text: str) -> list[str]:
    keys = [key.strip() for key in text.split(",") if key.strip()]
    if not keys or any(key not in GROUP_KEYS for key in keys):
        _fail(f"--by takes a comma list of: {', '.join(GROUP_KEYS)}")
    return keys


def _coverage(index: ActionIndex, query: ActionQuery) -> dict[str, int]:
    return {**index.coverage(), "redacted_unmatched": redacted_misses(index, query)}


def _matched(args: argparse.Namespace, query: ActionQuery) -> tuple[list, dict, dict]:
    """Matching actions (re-checked, see ``_cli_who_trust``), coverage, trust states."""
    index, report = _open(args)
    with index:
        try:
            trust = who_trust.resolver(args, index)
            who_trust.apply_refs(args, query, index, trust)
        except (OSError, ValueError) as exc:
            _fail(str(exc))
        matched = find(index, query)
        coverage = _coverage(index, query)
        verified_only = bool(getattr(args, "verified_only", False))
        matched = who_trust.screen(
            matched, trust, verified_only=verified_only, by_ref=bool(query.agent_refs)
        )
        states = who_trust.states(matched, trust)
    return matched, coverage, states


def cmd_who(args: argparse.Namespace) -> None:
    try:
        query = _query(args)
        keys = _group_keys(args.by)
    except ActionQueryError as exc:
        _fail(str(exc))
        return
    matched, coverage, states = _matched(args, query)
    limit = args.limit if args.limit and args.limit > 0 else None
    if args.list:
        emit_or_print(
            args,
            "who",
            {
                "actions": [{**a.to_dict(), "trust": states[a.run_id]} for a in matched[:limit]],
                "matched": len(matched),
                "coverage": coverage,
            },
            lambda: render_actions("Matching actions", matched[:limit], coverage, trust=states),
        )
        return
    groups = group(matched, keys, program=query.program, trust=states)[:limit]
    emit_or_print(
        args,
        "who",
        {"by": keys, "groups": groups, "matched": len(matched), "coverage": coverage},
        lambda: render_groups(keys, groups, len(matched), coverage),
    )


def cmd_touched(args: argparse.Namespace) -> None:
    try:
        query = ActionQuery(path=args.path, writes=True)
        if args.since:
            query.since = parse_time(args.since)
        keys = _group_keys(args.by)
    except ActionQueryError as exc:
        _fail(str(exc))
        return
    matched, coverage, states = _matched(args, query)
    groups = group(matched, keys, trust=states)
    emit_or_print(
        args,
        "touched",
        {
            "by": keys,
            "groups": groups,
            "matched": len(matched),
            "path": args.path,
            "coverage": coverage,
        },
        lambda: render_groups(keys, groups, len(matched), coverage),
    )


def _load_run(args: argparse.Namespace) -> Any:
    from opentine.graph import Run

    if args.repo:
        from opentine.repository import Repo

        return Repo.open(args.repo).load_run(args.run_id)
    path = _find_run(args.run_id)
    if path is None:
        _fail(f"Run not found: {args.run_id}")
    return Run.load(path)


def cmd_actions(args: argparse.Namespace) -> None:
    try:
        run = _load_run(args)
    except (KeyError, OSError, ValueError) as exc:
        _fail(f"Cannot load run: {exc}")
        return
    if args.sign or args.verify:
        sign_or_verify(args, run)
        return
    actions, truncated = extract_actions(run)
    if args.verb:
        actions = [action for action in actions if args.verb in action.verbs]
    resolver = who_trust.resolver(args)
    resolver.adopt(run)
    trust = resolver.trust(run.id).state
    emit_or_print(
        args,
        "actions",
        {
            "run_id": run.id,
            "actions": [a.to_dict() for a in actions],
            "truncated": truncated,
            "trust": trust,
        },
        lambda: render_actions(f"Actions in {run.id} ({trust})", actions, None, timeline=True),
    )


def cmd_audit(args: argparse.Namespace) -> None:
    try:
        rules = load_policy(args.policy)
    except ActionQueryError as exc:
        _fail(str(exc))
        return
    # Re-derived from the runs every time: a verdict must never rest on an
    # index file this process did not build (one can arrive with a cloned tree).
    index, report = _open(args, fresh=True)
    with index:
        violations = evaluate(index, rules)
        coverage = index.coverage()
        # A command whose text redaction swallowed may hide the program a rule
        # targets: that is unchecked coverage, not a pass.
        coverage["redacted_commands"] = index.count(
            "WHERE redacted = 1 AND (verbs LIKE '%,exec,%' OR verbs LIKE '%,other,%')"
        )
        trust = require_signed(args, index)
    partial = any(
        coverage[key] for key in ("unreadable_runs", "truncated_runs", "redacted_commands")
    )
    denied = [v for v in violations if v.rule.level == "deny"]
    rows = [
        {
            "rule": v.rule.id,
            "level": v.rule.level,
            "message": v.rule.message,
            "action": v.action.to_dict(),
        }
        for v in violations
    ]
    failed = bool(denied) or (args.strict and bool(violations))
    failed = failed or (partial and not args.allow_partial) or bool(trust["unverified"])
    emit_or_print(
        args,
        "audit",
        {
            "violations": rows,
            "rules": len(rules),
            "ok": not failed,
            "partial": partial,
            "coverage": coverage,
            "signatures": trust,
        },
        lambda: print_audit(violations, len(rules), coverage, trust),
    )
    if failed:
        raise SystemExit(1)


COMMANDS = {
    "agent": cmd_agent,
    "who": cmd_who,
    "actions": cmd_actions,
    "touched": cmd_touched,
    "audit": cmd_audit,
}

__all__ = ["COMMANDS", "add_actions_parsers", "cmd_actions", "cmd_audit", "cmd_touched", "cmd_who"]
