"""Routing gates for the split repo CLI plus a byte-pin on its JSON verbs.

Phase 1 of the Surface Release moved the v3 handlers out of opentine/repo_cli.py into
opentine/_repo_cli_plumbing.py and made opentine.repo_cli.REPO_COMMANDS the single
source of truth for which subcommands the v3 side owns. Two things have to hold
forever after that: the parser and the dispatch tables cannot drift apart, and the
five machine-readable verbs cannot quietly change their stdout.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import pytest

import opentine.cli as cli
from opentine._cli_parser import _build_parser
from opentine.repo_cli import REPO_COMMANDS, add_repo_parsers, clone, cmd_repo
from opentine.repository import Repo

PLUMBING = Path(cli.__file__).with_name("_repo_cli_plumbing.py")


def _parser_choices() -> set[str]:
    parser = _build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("tine parser has no subcommands")


def test_legacy_and_repo_command_tables_are_disjoint() -> None:
    overlap = set(cli.LEGACY_COMMANDS) & set(REPO_COMMANDS)
    assert overlap == set(), f"a command is routed twice: {sorted(overlap)}"


def test_every_parser_choice_is_routed_by_exactly_one_table() -> None:
    choices = _parser_choices()
    routed = set(cli.LEGACY_COMMANDS) | set(REPO_COMMANDS)
    assert choices - routed == set(), "parser advertises a command nothing dispatches"
    assert routed - choices == set(), "a dispatch table routes a command the parser rejects"


def test_repo_commands_are_all_callable_handlers() -> None:
    assert set(REPO_COMMANDS) == {
        "clone",
        "fetch",
        "fsck",
        "init",
        "migrate-v3",
        "object",
        "pack",
        "push",
        "repo-log",
    }
    assert all(callable(handler) for handler in REPO_COMMANDS.values())


def test_repo_cli_keeps_its_historical_import_surface() -> None:
    # Downstream code and tests import these three names from opentine.repo_cli, and
    # opentine.repo_cli.clone is the seam transport tests monkeypatch.
    assert callable(cmd_repo) and callable(add_repo_parsers) and callable(clone)


def test_an_unrouted_named_command_exits_1(monkeypatch, capsys) -> None:
    def parser_with_a_ghost_choice() -> argparse.ArgumentParser:
        parser = _build_parser()
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                action.add_parser("ghost", help="declared but deliberately unrouted")
                return parser
        raise AssertionError("tine parser has no subcommands")

    monkeypatch.setattr(cli, "_build_parser", parser_with_a_ghost_choice)
    with pytest.raises(SystemExit) as exited:
        cli.main(["ghost"])
    # The pre-split fall-through printed the help banner and exited 0, so a verb that
    # was parsed but never wired looked like success to every caller and CI job.
    assert exited.value.code == 1
    assert "unrouted command 'ghost'" in capsys.readouterr().err


def test_bare_tine_still_prints_help_and_exits_0(capsys) -> None:
    assert cli.main([]) is None
    assert "usage: tine" in capsys.readouterr().out


@dataclass
class _Stub:
    ok: bool = True
    detail: str = "x"
    count: int = 2


# Exact bytes: bare stdout, two-space indent, one trailing newline, no Rich wrapping.
_EXPECTED = '{\n  "ok": true,\n  "detail": "x",\n  "count": 2\n}\n'


@pytest.mark.parametrize(
    ("verb", "method", "extra"),
    [
        ("fsck", "fsck", []),
        ("object", "inspect", ["deadbeef"]),
        ("migrate-v3", "migrate_v2", ["source.tine"]),
        ("fetch", "fetch", ["https://example.invalid"]),
        ("push", "push", ["https://example.invalid"]),
    ],
)
def test_json_repo_verbs_print_byte_identical_stdout(
    verb, method, extra, monkeypatch, tmp_path, capsys
):
    repo_path = tmp_path / "repo"
    Repo.init(repo_path)
    payload = asdict(_Stub()) if verb == "object" else _Stub()
    monkeypatch.setattr(Repo, method, lambda self, *args, **kwargs: payload)
    cli.main([verb, *extra, "--repo", str(repo_path)])
    assert capsys.readouterr().out == _EXPECTED


def test_json_payload_shape_is_stable() -> None:
    assert json.dumps(asdict(_Stub()), indent=2) + "\n" == _EXPECTED


def test_plumbing_keeps_exactly_five_bare_json_print_sites() -> None:
    statements = [
        line.strip()
        for line in PLUMBING.read_text(encoding="utf-8").splitlines()
        if line.startswith("    print(") or line.startswith("    console.print(json")
    ]
    # console.print would re-wrap and style these; the five verbs are consumed by
    # scripts, so the bare print + indent=2 pair is part of the public contract.
    assert statements == [
        "print(json.dumps(asdict(result), indent=2))",  # fsck
        "print(json.dumps(inspected, indent=2))",  # object
        "print(json.dumps(asdict(result), indent=2))",  # migrate-v3
        "print(json.dumps(asdict(result), indent=2))",  # fetch
        "print(json.dumps(asdict(result), indent=2))",  # push
    ]
