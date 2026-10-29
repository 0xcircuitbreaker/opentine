"""``tine fan-out`` and ``tine run --parallel``: many branches at once.

``tine fan-out RUN [--from-step N] --vary model=a,b [--repeat K] -- CMD ...`` forks
RUN once per member from one fork point (walked once), writes every
``experiments/fanout/<id>/<n>`` ref in one transaction, records the fan-out on
RUN, and runs CMD per member with ``{model}``/``{run}``/``{ref}``/``{index}``
placeholders. Without CMD it only prepares the forks. ``tine run --parallel N``
runs the same ``tine run`` invocation N times (times every ``--vary``
combination). Both take ``--jobs``, ``--timeout``, ``--budget``, ``--env``,
``--log-dir``, ``--json`` (NDJSON status) and ``--resume ID``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from opentine._cli_common import _terminal, console
from opentine._cli_flags import AUTOSAVE_FLAGS, refuse_unhonoured
from opentine.parallel._fanout import drive, prepare_forks, record
from opentine.parallel._matrix import command_digest, env_names, expand, parse_vary, render
from opentine.parallel._state import State, new_id
from opentine.parallel._status import Reporter

_HINT = "`tine run --parallel N` runs N members, each saving its own run under .tine_runs."
#: ``tine run`` flags that only ``--parallel`` honours, with their parser defaults.
PARALLEL_DEFAULTS = {
    "vary": [],
    "jobs": None,
    "timeout": None,
    "budget": None,
    "env": [],
    "log_dir": None,
    "resume": None,
    "json": False,
}
_SHARED = ("vary", "jobs", "timeout", "budget", "env", "log_dir", "resume", "json")


def _shared(parser: argparse.ArgumentParser, *, jobs_default: int | None) -> None:
    parser.add_argument("--vary", action="append", default=[], metavar="NAME=V1,V2")
    parser.add_argument("--jobs", type=int, default=jobs_default, help="Members at once")
    parser.add_argument("--timeout", type=float, metavar="SECONDS", help="Per member")
    parser.add_argument("--budget", type=float, metavar="USD", help="Shared cost cap")
    parser.add_argument(
        "--env", action="append", default=[], metavar="NAME", help="Pass this variable through"
    )
    parser.add_argument("--log-dir", metavar="DIR", help="Write each member's output here")
    parser.add_argument("--resume", metavar="ID", help="Run a fan-out's unfinished members")


def add_fanout_parsers(sub: argparse._SubParsersAction) -> None:
    fan = sub.add_parser(
        "fan-out",
        help="Fork a run N ways and run every branch concurrently",
        epilog="Give each member's command after `--`: tine fan-out RUN [options] -- CMD ARGS",
    )
    fan.add_argument("run", nargs="?")
    fan.add_argument("--from-step", help="Fork after step N (default: the last)")
    fan.add_argument("--repeat", type=int, default=1, help="Members per combination")
    _shared(fan, jobs_default=4)
    fan.add_argument("--worktree-dir", metavar="DIR", help="One tine worktree per member here")
    fan.add_argument("--repo", default=".")
    fan.add_argument("--json", action="store_true", help="Stream NDJSON status lines")
    run = sub.choices["run"]
    run.add_argument("--parallel", type=int, metavar="N", help="Run N copies concurrently")
    _shared(run, jobs_default=None)
    run.add_argument("--json", action="store_true", help="With --parallel: NDJSON status")


def split_command(argv: list[str]) -> tuple[list[str], list[str]]:
    """``[..., "fan-out", ..., "--", CMD...]`` -> (tine argv, CMD argv)."""
    verb = next((index for index, token in enumerate(argv) if not token.startswith("-")), None)
    if verb is not None and argv[verb] == "fan-out" and "--" in argv[verb:]:
        cut = argv.index("--", verb)
        return argv[:cut], argv[cut + 1 :]
    return argv, []


def _command(args: argparse.Namespace) -> list[str]:
    return list(getattr(args, "member_command", None) or [])


def _state(directory: Path, args, template: list[str], members, source: dict) -> State:
    if args.resume:
        if args.vary or getattr(args, "repeat", 1) != 1:
            raise ValueError("--resume takes the recorded members; drop --vary/--repeat")
        state = State.load(directory, args.resume)
        recorded = state.data["command_digest"]
        if recorded == command_digest([]) and template:
            state.data["command_digest"] = command_digest(template)  # prepared, now run
        elif command_digest(template) != recorded:
            raise ValueError("--resume needs the same command the fan-out was started with")
        for member in state.data["members"]:
            render(template, member["vary"])  # refuse before anything starts
        if args.budget is not None and state.data["budget"] != str(args.budget):
            raise ValueError("--resume keeps the fan-out's recorded --budget")
        return state
    budget = None if args.budget is None else str(args.budget)
    return State.create(
        directory,
        id=args.fid,
        budget=budget,
        command_digest=command_digest(template),
        members=members,
        source=source,
    )


def _drive(state: State, template: list[str], args, cwd_for=lambda member: None) -> None:
    log_dir = Path(args.log_dir) if args.log_dir else None
    if log_dir:  # member logs hold raw output (keys passed by --env included)
        log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    reporter = Reporter(state.id, json_lines=args.json)
    jobs = args.jobs or len(state.data["members"])
    code = drive(
        state,
        template,
        jobs=jobs,
        timeout=args.timeout,
        allow_env=env_names(args.env),
        reporter=reporter,
        log_dir=log_dir,
        cwd_for=cwd_for,
    )
    raise SystemExit(code)


def cmd_fanout(args: argparse.Namespace) -> None:
    from opentine._cli_git_rewrite import _events, _step
    from opentine._repo_cli_write import _run_oid
    from opentine.repo import Repo

    repo = Repo.open(args.repo)
    template = _command(args)
    directory = repo.path / "fanouts"
    args.fid = new_id()
    members: list[dict] = []
    if not args.resume:
        if not args.run:
            raise ValueError("fan-out needs a RUN (or --resume ID)")
        source = _run_oid(repo, args.run)
        events = _events(repo, source)
        fork_event = _step(events, str(args.from_step or len(events)))
        matrix = expand(parse_vary(args.vary), args.repeat)
        for values in matrix:
            render(template, values)  # refuse an option-shaped value before forking
        members = prepare_forks(repo, source, fork_event, matrix, args.fid)
        limits = {"jobs": args.jobs, "repeat": args.repeat}
        record(repo, source, args.fid, fork_event, members, limits)
    source_info = {"run": args.run or "", "kind": "fan-out"}
    state = _state(directory, args, template, members, source_info)
    if not template:
        Reporter(state.id, json_lines=args.json)(
            {"event": "prepared", "members": len(state.data["members"])}
        )
        if not args.json:
            for member in state.data["members"]:
                console.print(f"  {_terminal(member['ref'])} -> {member['run']}")
        return
    cwd_for = _worktrees(repo, state, Path(args.worktree_dir)) if args.worktree_dir else None
    _drive(state, template, args, cwd_for or (lambda member: None))


def _worktrees(repo, state: State, root: Path):
    from opentine import _worktree

    known = {row["name"]: row for row in _worktree.list_worktrees(repo)}

    def cwd_for(member: dict) -> str:
        name = f"fanout-{state.id}-{member['key']}"
        if name in known and known[name].get("state") == "ok":
            return known[name]["path"]  # a resumed member keeps its worktree
        return _worktree.add(repo, root / name, member["ref"], name=name)["path"]

    return cwd_for


def _member_argv(argv: list[str]) -> list[str]:
    """The ``tine run`` argv a member re-runs: the caller's, minus the fan-out flags."""
    from opentine._cli_parser import _build_parser

    run = _build_parser()._subparsers._group_actions[0].choices["run"]  # type: ignore[union-attr]
    ours = {"--parallel", *(f"--{name.replace('_', '-')}" for name in _SHARED)}
    takes_value = ours - {"--json"}
    options = list(run._option_string_actions)
    kept, skip = [], False
    for token in argv:
        if skip:
            skip = False
            continue
        name = token.split("=", 1)[0]
        if name.startswith("--") and name not in options:
            hits = [option for option in options if option.startswith(name)]
            name = hits[0] if len(hits) == 1 else name
        if name in ours:
            skip = name in takes_value and "=" not in token
            continue
        kept.append(token)
    # -P: with -m Python puts the cwd first on sys.path, so an opentine/ planted
    # in the project would shadow the installed package in every member. Not -I:
    # members run the user's script, which may rely on PYTHONPATH / PYTHONUTF8.
    return [sys.executable, "-P", "-m", "opentine.cli", *kept]


def cmd_run_parallel(args: argparse.Namespace) -> bool:
    """Run ``tine run --parallel``; False (after refusing stray flags) without it."""
    from opentine._cli_common import _runs_dir

    if getattr(args, "parallel", None) is None:
        # Defaults per dest: FLAG_DEFAULTS is keyed by dest across every verb, and
        # `serve --timeout` / `fan-out --jobs` give these names other defaults.
        named = [
            d for d, default in PARALLEL_DEFAULTS.items() if getattr(args, d, default) != default
        ]
        if named:
            flags = ", ".join(f"--{d.replace('_', '-')}" for d in named)
            console.print(f"[red]{flags} need(s) --parallel N. {_HINT}[/]")
            raise SystemExit(1)
        return False
    # Every member would write the same file: each saves under .tine_runs instead.
    refuse_unhonoured(args, ("save", *AUTOSAVE_FLAGS), mode="with --parallel", hint=_HINT)
    if args.parallel < 1:
        raise ValueError("--parallel must be a positive integer")
    template = _member_argv(list(getattr(args, "tine_argv", None) or sys.argv[1:]))
    args.fid = new_id()
    members = [
        {
            "cost": None,
            "key": str(index),
            "ref": None,
            "returncode": None,
            "run": None,
            "status": "pending",
            "vary": values,
        }
        for index, values in enumerate(expand(parse_vary(args.vary), args.parallel))
        if render(template, values) is not None  # refuse an option-shaped value first
    ]
    state = _state(_runs_dir() / "parallel", args, template, members, {"kind": "run"})
    _drive(state, template, args)
    return True


__all__ = ["add_fanout_parsers", "cmd_fanout", "cmd_run_parallel"]
