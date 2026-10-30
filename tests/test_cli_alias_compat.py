"""Every pinned old invocation still reaches the same handler with the same args.

The rows live in tests/cli_compat_table.py (append-only). Each argv goes through
``cli.parse`` + ``cli.resolve`` — exactly what ``cli.main`` does before calling the
handler — so alias expansion and the plain-verb -> ``repo-*`` rewrites are covered,
but no handler runs.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from opentine import Run, StepKind, cli
from opentine._cli_registry import ALIASES, VISIBLE_COMMANDS
from opentine.repository import Repo

from .cli_compat_table import ROWS


@pytest.fixture
def plain(tmp_path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    return tmp_path


@pytest.fixture
def v3(plain) -> Path:
    store = Repo.init(plain)
    run = Run(id="base0001", model_info="m-old")
    for index in range(3):
        run.add_step(StepKind.model, {"text": str(index)}, {"text": "ok"})
    store.put_run(run, ref="heads/main")
    cli.main(["config", "alias.st", "log --oneline"])
    cli.main(["config", "alias.help", "log"])
    return plain


def _resolve(argv: list[str]):
    parser, args = cli.parse(argv)
    handler, args, via_repo = cli.resolve(parser, args)
    name = f"{handler.__module__}:{handler.__qualname__}" if handler else None
    return name, via_repo, args


@pytest.mark.parametrize("row", ROWS, ids=[row[0] for row in ROWS])
def test_old_invocation_reaches_the_same_handler(row, request) -> None:
    _id, where, argv, handler, via_repo, attrs = row
    request.getfixturevalue(where)
    got, got_via, args = _resolve(list(argv))
    assert (got, got_via) == (handler, via_repo)
    assert {key: getattr(args, key) for key in attrs} == attrs


def test_table_ids_are_unique_and_rows_well_formed() -> None:
    ids = [row[0] for row in ROWS]
    assert len(ids) == len(set(ids)), "duplicate compat row id"
    assert len({(row[1], tuple(row[2])) for row in ROWS}) == len(ROWS), "duplicate argv"
    for _id, where, argv, handler, _via, attrs in ROWS:
        assert where in {"plain", "v3"} and _id == f"{where}:{' '.join(argv)}"
        assert handler and ":" in handler and "command" in attrs


def test_every_parseable_verb_has_a_row() -> None:
    parser = cli._build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    covered = {row[5]["command"] for row in ROWS} | {row[2][0] for row in ROWS}
    assert set(sub.choices) - covered == set()
    for name, child in sub.choices.items():
        for action in child._actions:
            if isinstance(action, argparse._SubParsersAction):
                pinned = {row[2][1] for row in ROWS if row[2][0] == name and len(row[2]) > 1}
                assert set(action.choices) - pinned == set(), name


def test_registry_names_only_real_verbs() -> None:
    parser = cli._build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert VISIBLE_COMMANDS <= set(sub.choices)
    assert set(ALIASES).isdisjoint(sub.choices)


def test_builtin_help_beats_a_porcelain_alias(v3) -> None:
    assert _resolve(["help"])[0] == "opentine._cli_help:cmd_help"
