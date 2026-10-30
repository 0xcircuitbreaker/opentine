"""0.17 folds ``ls``/``search``/``cost``/``price`` into ``log`` and ``show``.

Each new spelling must print byte-identical output (and exit code) to the old
verb on the same runs directory, and a flag combination the old verb cannot
honour must be a usage error (exit 2), not silently dropped.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import Run, StepKind

_ROOT = str(Path(__file__).resolve().parents[1])


@pytest.fixture
def runs(tmp_path) -> Path:
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    for name, model, tag in (("aaa", "m-one", "prod"), ("bbb", "m-two", "dev")):
        run = Run(id=f"{name}00001", model_info=model, tags=[tag])
        run.add_step(StepKind.model, {"text": "hi"}, {"text": "ok"}, cost=0.25)
        run.save(runs_dir / f"{run.id}.tine")
    return tmp_path


def _tine(cwd: Path, argv: list[str]) -> tuple[int, str, str]:
    env = {
        **os.environ,
        "HOME": str(cwd / "home"),
        "XDG_CONFIG_HOME": str(cwd / "xdg"),
        "PYTHONPATH": _ROOT,
        "COLUMNS": "120",
        "NO_COLOR": "1",
        # Windows pipes default to the ANSI code page; pin UTF-8 so both verbs
        # print the same bytes on every OS.
        "PYTHONIOENCODING": "utf-8",
    }
    done = subprocess.run(
        [sys.executable, "-c", "from opentine.cli import main; main()", *argv],
        cwd=cwd,
        env=env,
        capture_output=True,
        encoding="utf-8",
        timeout=120,
    )
    return done.returncode, done.stdout, done.stderr


PAIRS = (
    (["search", "model:m-one"], ["log", "--search", "model:m-one"]),
    (["search", "tag:prod", "--json"], ["log", "--search", "tag:prod", "--json"]),
    (["ls"], ["log", "--legacy"]),
    (["ls", "--json"], ["log", "--legacy", "--json"]),
    (["ls", "--tag", "dev", "--limit", "5"], ["log", "--tag", "dev", "--limit", "5"]),
    (["ls", "--cost-min", "0.1", "--json"], ["log", "--cost-min", "0.1", "--json"]),
    (["cost", "aaa00001"], ["show", "aaa00001", "--cost"]),
    (["cost", "aaa00001", "--json"], ["show", "aaa00001", "--cost", "--json"]),
    (["price", "bbb00001"], ["show", "bbb00001", "--price"]),
    (
        ["price", "bbb00001", "--at", "2026-07-15", "--json"],
        ["show", "bbb00001", "--price", "--at", "2026-07-15", "--json"],
    ),
)


@pytest.mark.parametrize("pair", PAIRS, ids=[" ".join(new) for _, new in PAIRS])
def test_new_spelling_is_byte_identical(pair, runs) -> None:
    old, new = pair
    want = _tine(runs, old)
    assert want[1], f"the old verb printed nothing (exit {want[0]}): {want[2]}"
    assert _tine(runs, new) == want


CONFLICTS = (
    (["show", "aaa00001", "--cost", "--price"], "--cost cannot be combined with --price"),
    (["show", "aaa00001", "--at", "2026-07-15"], "--at requires --price"),
    (["show", "aaa00001", "--cost", "--legacy"], "--legacy cannot be combined with --cost"),
    (["show", "aaa00001", "--price", "--repo", "."], "--repo cannot be combined with --price"),
    (["log", "--search", "x", "--graph"], "--graph cannot be combined with --search"),
    (["log", "--search", "x", "--limit", "3"], "--limit cannot be combined with --search"),
    (["log", "--search", "x", "--tag", "a"], "--tag cannot be combined with --search"),
    (["log", "--search", "x", "heads/main"], "REF cannot be combined with --search"),
    (["log", "--legacy", "--oneline"], "--oneline cannot be combined with --legacy"),
    (["log", "--model", "m", "--repo", "."], "--repo cannot be combined with --legacy"),
)


@pytest.mark.parametrize("case", CONFLICTS, ids=[" ".join(c[0]) for c in CONFLICTS])
def test_conflicting_flags_are_usage_errors(case, runs, capsys, monkeypatch) -> None:
    from opentine import cli

    argv, message = case
    monkeypatch.chdir(runs)
    with pytest.raises(SystemExit) as exc:
        cli.parse(argv)
    assert exc.value.code == 2
    assert message in capsys.readouterr().err


def test_plain_log_and_show_are_not_rewritten() -> None:
    from opentine import _cli_fold, cli

    parser = cli._build_parser()
    for argv in (["log"], ["log", "--oneline", "--limit", "2"], ["show", "r1", "--json"]):
        assert _cli_fold.rewrite(parser, list(argv)) == argv
