"""``tine bisect``: start / good / bad / skip / run / log / reset."""

from __future__ import annotations

import argparse
import math
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

from opentine._bisect import (
    BisectError,
    BisectState,
    exit_verdict,
    lineage,
    load,
    save,
    score_verdict,
    start,
)
from opentine._cli_common import _runs_dir, _terminal, console
from opentine._cli_who_render import emit_or_print
from opentine._git_link_runs import RunCatalog, open_catalog
from opentine.repository._search_scores import MAX_UNSIGNED_SCORE, _signed

MAX_RUN_ROUNDS = 64


def _fail(message: str) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(2)


def _state_path(args: argparse.Namespace) -> Path:
    if args.repo:
        from opentine.repository import Repo
        from opentine.repository._paths import internal_path

        return internal_path(Repo.open(args.repo).path, "bisect", "state.json")
    return _runs_dir() / "bisect.json"


def _catalog(args: argparse.Namespace) -> RunCatalog:
    try:
        return open_catalog(args.repo, _runs_dir())
    except (OSError, ValueError) as exc:
        _fail(f"Cannot index runs: {exc}")
        raise  # unreachable


def _annotate(catalog: RunCatalog, state: BisectState, item: str, verdict: str) -> None:
    """In a repository, record the verdict on the run it is about."""
    if catalog.repo is None or verdict == "skip":
        return
    from opentine.repository._annotations import load_run_annotation, write_run_annotation

    run = state.run if state.mode == "steps" else item
    oid = catalog.canonical(catalog.run_id(run))
    metadata, tags = load_run_annotation(catalog.repo, oid)
    record = {"verdict": verdict, "mode": state.mode}
    if state.mode == "steps":
        record["step"] = item
    metadata = {**metadata, "bisect": record}
    tags = sorted({*[tag for tag in tags if not tag.startswith("bisect:")], f"bisect:{verdict}"})
    write_run_annotation(catalog.repo, oid, metadata, tags)


def _scores(catalog: RunCatalog, run: str, *, signed_only: bool = False) -> dict[str, float]:
    """The evaluation scores that decide *run*, with search's trust rules.

    A signed evaluation outranks any unsigned one: unsigned values count only
    for a name no signed evaluation scores (never with *signed_only*), and an
    unsigned value outside +/-1e6 counts for nothing -- anyone who can write an
    attestation (an MCP client) can write an unsigned one. Among several
    evaluations of the same kind, the attestation with the smallest oid decides,
    so the choice never depends on write order.
    """
    scores: dict[str, float] = {}
    if catalog.repo is not None:
        oid = catalog.canonical(catalog.run_id(run))
        chosen: dict[str, tuple[bool, str, float]] = {}
        for attestation in sorted(catalog.repo.attestations_for(oid))[:1000]:
            payload = catalog.repo.get(attestation).payload() or {}
            claim = payload.get("claim") or {}
            if not isinstance(claim, dict) or claim.get("kind") != "evaluation":
                continue
            signed = _signed(payload)
            if signed_only and not signed:
                continue
            for name, value in (claim.get("scores") or {}).items():
                number = _finite(value)
                if number is None or (not signed and abs(number) > MAX_UNSIGNED_SCORE):
                    continue
                key, current = str(name), chosen.get(str(name))
                if current is None or (signed and not current[0]):
                    chosen[key] = (signed, attestation, number)
        return {name: value for name, (_, _, value) in chosen.items()}
    if signed_only:
        return scores  # a plain run file carries no signed evaluations
    metadata = catalog.load(run).metadata or {}
    raw = metadata.get("scores") if isinstance(metadata, dict) else None
    for name, value in (raw or {}).items() if isinstance(raw, dict) else ():
        number = _finite(value)
        if number is not None:
            scores[str(name)] = number
    return scores


def _finite(value: Any) -> float | None:
    if type(value) not in (int, float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _report(args: argparse.Namespace, state: BisectState, command: str) -> None:
    index = state.current()
    payload: dict[str, Any] = {
        "mode": state.mode,
        "done": state.done,
        "first_bad": state.first_bad(),
        "next": state.candidates[index] if index is not None else None,
        "remaining": max(0, state.bad - state.good - 1 - len(state.skipped)),
        "log": state.log,
    }

    def human() -> None:
        if state.done:
            what = "step" if state.mode == "steps" else "run"
            console.print(f"First bad {what}: {_terminal(str(state.first_bad()))}")
        else:
            console.print(
                f"Test next: {_terminal(str(payload['next']))} "
                f"({payload['remaining']} left between good and bad)"
            )

    emit_or_print(args, command, payload, human)


def cmd_bisect(args: argparse.Namespace) -> None:
    try:
        _dispatch(args)
    except (BisectError, KeyError) as exc:
        _fail(str(exc).strip("'"))


def _dispatch(args: argparse.Namespace) -> None:
    path = _state_path(args)
    action = args.bisect_command
    if action == "reset":
        path.unlink(missing_ok=True)
        console.print("Bisect state cleared.")
        return
    catalog = _catalog(args)
    if action == "start":
        if args.steps:
            run = catalog.load(args.steps)
            ids = [step.id for step in run.steps]
            state = start(ids, args.good, args.bad, mode="steps", run=run.id)
        elif args.runs:
            state = start(list(args.runs), args.good, args.bad, mode="runs")
        else:
            chain = lineage(catalog.load, args.bad, args.good)
            state = start(chain, chain[0], chain[-1], mode="lineage")
        save(path, state)
        return _report(args, state, "bisect start")
    state = load(path)
    if action in ("good", "bad", "skip"):
        index = state.index_of(args.item) if args.item else state.current()
        if index is None:
            raise BisectError("the bisect is already finished; see `tine bisect log`")
        state.mark(index, action)
        _annotate(catalog, state, state.candidates[index], action)
    elif action == "run":
        _run(args, catalog, state)
    save(path, state)
    _report(args, state, f"bisect {action}")


def _run(args: argparse.Namespace, catalog: RunCatalog, state: BisectState) -> None:
    if bool(args.eval) == bool(args.score):
        raise BisectError("give exactly one of --eval CMD or --score NAME>=X")
    if args.score and state.mode == "steps":
        raise BisectError("--score reads per-run evaluations; use --eval for steps")
    for _ in range(MAX_RUN_ROUNDS):
        index = state.current()
        if index is None:
            return
        item = state.candidates[index]
        if args.score:
            verdict = score_verdict(
                _scores(catalog, item, signed_only=args.signed_only), args.score
            )
        else:
            env = {
                **os.environ,
                "OPENTINE_BISECT_RUN": state.run if state.mode == "steps" else item,
                "OPENTINE_BISECT_STEP": item if state.mode == "steps" else "",
                "OPENTINE_BISECT_INDEX": str(index),
            }
            try:
                done = subprocess.run(shlex.split(args.eval), env=env, timeout=args.timeout)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise BisectError(f"the evaluator failed to run: {exc}") from None
            verdict = exit_verdict(done.returncode)
        state.mark(index, verdict)
        _annotate(catalog, state, item, verdict)


def add_bisect_parser(sub: Any) -> None:
    bisect = sub.add_parser("bisect", help="Find the first bad run or step")
    bisect_sub = bisect.add_subparsers(dest="bisect_command", required=True)
    begin = bisect_sub.add_parser("start", help="Start between a BAD and a GOOD run (or step)")
    begin.add_argument("bad")
    begin.add_argument("good")
    choice = begin.add_mutually_exclusive_group()
    choice.add_argument("--runs", nargs="+", metavar="RUN", help="Ordered runs, good to bad")
    choice.add_argument("--steps", metavar="RUN", help="Bisect this run's steps instead")
    for verdict in ("good", "bad", "skip"):
        marked = bisect_sub.add_parser(verdict, help=f"Mark an item {verdict}")
        marked.add_argument("item", nargs="?", help="Default: the item to test next")
    runner = bisect_sub.add_parser("run", help="Let an evaluator or a score decide")
    runner.add_argument("--eval", help="Command: exit 0 good, 125 skip, 1-127 bad")
    runner.add_argument("--score", help="NAME>=X against recorded evaluations")
    runner.add_argument("--signed-only", action="store_true", help="Ignore unsigned evaluations")
    runner.add_argument("--timeout", type=float, default=None, help="Seconds per evaluator call")
    for name in ("log", "reset"):
        bisect_sub.add_parser(name, help=f"Bisect {name}")
    for parser in bisect_sub.choices.values():
        parser.add_argument("--repo", metavar="PATH", help="Bisect runs in a v3 repository")
        parser.add_argument("--json", action="store_true")


COMMANDS = {"bisect": cmd_bisect}

__all__ = ["COMMANDS", "add_bisect_parser", "cmd_bisect"]
