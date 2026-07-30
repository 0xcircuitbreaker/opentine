"""Round 10 release-audit regressions: shipped tests must run, and flags must land.

Two user-visible lows, both about a promise the tool makes and then drops:

* the round-9 inventory tests interrogate the repository with git, but ``tests``
  ships inside the sdist, so from an unpacked tarball they reported ``fatal: not
  a git repository`` as "tracked text files contain CR bytes".  They now skip
  with a reason outside a checkout — and are proven *not* to skip inside one, so
  the CI gate they exist for cannot quietly disappear.

* ``tine run script.py --save PATH`` ignored --save and wrote
  ``.tine_runs/<id>.tine`` instead; ``--autosave*`` and every harness flag were
  ignored in script mode too.  --save is now honoured everywhere the parser
  offers it, and any flag the active mode cannot honour is refused by name.
  ``tine fork`` and ``tine replay`` had the same silent-ignore shape (harness
  configuration without --harness/--prompt, --compare on a cached replay,
  everything under --inspect/--dry-run) and are covered here as well.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import tests.test_release_audit_round9_inventory as inventory
from opentine import Run, RunStatus, StepKind, cli
from opentine._cli_flags import FLAG_DEFAULTS
from opentine._cli_parser import _build_parser

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    "from opentine import Run, RunStatus, StepKind\n"
    "run = Run(id='round10_run')\n"
    "run.add_step(StepKind.done, {'text': 'ok'})\n"
    "run.status = RunStatus.completed\n"
)


# --------------------------------------------------------------------------- #
# (1) the shipped test suite must be green from an unpacked sdist
# --------------------------------------------------------------------------- #


def test_the_git_backed_checks_run_and_are_not_skipped_here():
    """A false skip would silently drop the Windows-CRLF gate; fail loudly instead."""
    if not (ROOT / ".git").exists():
        pytest.skip(f"{ROOT} is not a git checkout, so there is no gate to protect here")
    if shutil.which("git") is None:
        # A .git directory is not enough: is_checkout_root() shells git, so with no
        # git binary this assertion fails on a real checkout and reports a missing
        # tool as a dropped CRLF gate.  Same class as the guard it is protecting.
        pytest.skip("git is not installed, so the round-9 checks correctly skip themselves")
    assert inventory.is_checkout_root(), (
        "the round-9 inventory tests would skip inside a real checkout, which is where "
        "ci.yml relies on them to keep .gitattributes pinning every tracked file"
    )
    skip = inventory.requires_checkout.markname, inventory.requires_checkout.args[0]
    assert skip == ("skipif", False), skip


def _sdist_like_tree(root: Path) -> Path:
    """Reproduce what a redistributor unpacks: shipped files, no .git anywhere."""
    tree = root / "opentine-0.3.0"
    (tree / "tests").mkdir(parents=True)
    (tree / "scripts").mkdir()
    for name in (
        "tests/test_release_audit_round9_inventory.py",
        "tests/conftest.py",
        "scripts/check_release_inventory.py",
        "pyproject.toml",
        ".gitattributes",
    ):
        shutil.copy(ROOT / name, tree / name)
    assert not (tree / ".git").exists()
    return tree


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_inventory_tests_skip_with_a_reason_when_unpacked_without_git_metadata(tmp_path: Path):
    tree = _sdist_like_tree(tmp_path)
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_release_audit_round9_inventory.py",
            "-q",
            "-rs",
        ],
        cwd=tree,
        capture_output=True,
        text=True,
        env=env,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "failed" not in output, output
    assert "2 skipped" in output, output
    assert "is not a git checkout" in output, output
    # the git-free checks still ran rather than being skipped along with them
    assert "5 passed" in output, output


# --------------------------------------------------------------------------- #
# (2) `tine run script.py --save PATH` writes the run at PATH
# --------------------------------------------------------------------------- #


def _invoke(monkeypatch, tmp_path: Path, *args: str) -> None:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


def test_run_script_writes_the_run_at_the_requested_save_path(tmp_path: Path):
    (tmp_path / "agentrun.py").write_text(SCRIPT, encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-m", "opentine.cli", "run", "agentrun.py", "--save", "out/mine.tine"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    saved = tmp_path / "out" / "mine.tine"
    assert saved.is_file(), result.stdout + result.stderr
    assert Run.load(saved).id == "round10_run"
    assert not (tmp_path / ".tine_runs").exists(), "the run was also written to the default slot"
    assert "out" in result.stdout and "mine.tine" in result.stdout


def test_run_script_without_save_still_uses_the_default_runs_dir(monkeypatch, tmp_path: Path):
    script = tmp_path / "agentrun.py"
    script.write_text(SCRIPT, encoding="utf-8")
    _invoke(monkeypatch, tmp_path, "run", str(script))
    assert (tmp_path / ".tine_runs" / "round10_run.tine").is_file()


IGNORED_IN_SCRIPT_MODE = [
    ["--autosave", "draft.tine"],
    ["--autosave-interval", "3"],
    ["--autosave-seconds", "1.5"],
    ["--prompt", "do it"],
    ["--cwd", "."],
    ["--harness-command", "agent run"],
    ["--harness-arg", "verbose"],
    ["--harness-login-env"],
    ["--harness-env", "PATH"],
    ["--harness-timeout", "5"],
    ["--harness-max-output", "10"],
    ["--harness-max-events", "2"],
    ["--harness-max-line-bytes", "10"],
]


@pytest.mark.parametrize("extra", IGNORED_IN_SCRIPT_MODE, ids=lambda extra: extra[0])
def test_run_script_refuses_every_flag_it_cannot_honour(monkeypatch, tmp_path, capsys, extra):
    script = tmp_path / "agentrun.py"
    script.write_text(SCRIPT, encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, tmp_path, "run", str(script), *extra)

    assert exc.value.code == 1
    out = capsys.readouterr().out.replace("\n", " ")
    assert extra[0] in out and "no effect without --harness" in out
    assert "--save PATH" in out, "the refusal must point at the flag that does work"
    assert not (tmp_path / ".tine_runs").exists()
    assert not list(tmp_path.glob("*.tine"))


class _StubHarness:
    """Stands in for OpentineHarness so the honouring path runs without a subprocess."""

    kwargs: dict = {}

    def __init__(self, harness, **kwargs):
        _StubHarness.kwargs = kwargs

    def run_sync(self, task, context=None, save_path=None):
        run = Run(id="round10_harness_run")
        run.add_step(StepKind.done, {"text": task})
        run.status = RunStatus.completed
        return run


@pytest.mark.parametrize(
    "extra", [["--autosave-interval", "3"], ["--autosave-seconds", "1.5"]], ids=lambda e: e[0]
)
def test_harness_run_refuses_a_checkpoint_throttle_with_no_destination(
    monkeypatch, tmp_path, capsys, extra
):
    """`Autosaver.enabled` is False without a path, so the throttle alone saves nothing."""
    monkeypatch.setattr("opentine._cli_execute.OpentineHarness", _StubHarness)

    with pytest.raises(SystemExit) as exc:
        _invoke(
            monkeypatch,
            tmp_path,
            "run",
            "--harness",
            "generic",
            "--harness-command",
            "agent run",
            "--prompt",
            "hi",
            "--save",
            str(tmp_path / "out.tine"),
            *extra,
        )

    assert exc.value.code == 1
    out = capsys.readouterr().out.replace("\n", " ")
    assert extra[0] in out and "no effect without --autosave" in out
    assert not (tmp_path / "out.tine").exists()


def test_harness_run_still_honours_a_throttle_that_has_a_destination(monkeypatch, tmp_path):
    monkeypatch.setattr("opentine._cli_execute.OpentineHarness", _StubHarness)
    _invoke(
        monkeypatch,
        tmp_path,
        "run",
        "--harness",
        "generic",
        "--harness-command",
        "agent run",
        "--prompt",
        "hi",
        "--autosave",
        str(tmp_path / "draft.tine"),
        "--autosave-interval",
        "3",
        "--autosave-seconds",
        "1.5",
        "--save",
        str(tmp_path / "out.tine"),
    )
    assert _StubHarness.kwargs["autosave_steps"] == 3
    assert _StubHarness.kwargs["autosave_seconds"] == 1.5
    assert Run.load(tmp_path / "out.tine").id == "round10_harness_run"


def test_run_still_accepts_the_harness_flags_it_does_honour():
    args = _build_parser().parse_args(
        ["run", "--harness", "codex", "--prompt", "hi", "--save", "x.tine", "--autosave", "d.tine"]
    )
    assert (args.save, args.autosave, args.prompt) == ("x.tine", "d.tine", "hi")


def test_run_help_documents_where_a_run_is_written(capsys):
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["run", "--help"])
    help_text = capsys.readouterr().out
    assert "--save PATH" in help_text
    assert ".tine_runs/<id>.tine" in help_text
    assert help_text.count("--harness runs only") == 3


# --------------------------------------------------------------------------- #
# (2) siblings: fork and replay ignored the same flags in the same way
# --------------------------------------------------------------------------- #


def _recorded_run(path: Path) -> Run:
    run = Run(id="round10_source", model_info="mock-model", user_prompt="test prompt")
    run.add_step(StepKind.think, {"text": "thinking"})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(path)
    return run


@pytest.mark.parametrize(
    ("command", "extra", "expected"),
    [
        (["fork", "--from-step", "0"], ["--prompt", "go on"], "no effect without --harness"),
        (
            ["fork", "--from-step", "0", "--harness", "codex"],
            ["--harness-command", "codex exec"],
            "no effect without --prompt",
        ),
        (["replay"], ["--compare"], "no effect for a cached replay"),
        (["replay"], ["--harness-timeout", "7"], "no effect for a cached replay"),
        (
            ["replay", "--inspect"],
            ["--save", "elsewhere.tine"],
            "no effect with --inspect/--dry-run",
        ),
        (["replay", "--dry-run"], ["--mode", "rerun"], "no effect with --inspect/--dry-run"),
        (["replay", "--dry-run"], ["--harness", "codex"], "no effect with --inspect/--dry-run"),
    ],
    ids=lambda value: "+".join(value) if isinstance(value, list) else value[:20],
)
def test_fork_and_replay_refuse_flags_their_mode_ignores(
    monkeypatch, tmp_path, capsys, command, extra, expected
):
    source = tmp_path / "source.tine"
    _recorded_run(source)

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, tmp_path, command[0], str(source), *command[1:], *extra)

    assert exc.value.code == 1
    out = capsys.readouterr().out.replace("\n", " ")
    assert extra[0] in out and expected in out
    assert not (tmp_path / "elsewhere.tine").exists()
    assert not (tmp_path / ".tine_runs").exists()


def test_the_modes_that_do_honour_those_flags_are_untouched(monkeypatch, tmp_path, capsys):
    source = tmp_path / "source.tine"
    _recorded_run(source)
    _invoke(monkeypatch, tmp_path, "replay", str(source), "--inspect")
    _invoke(monkeypatch, tmp_path, "replay", str(source), "--mode", "cache")
    _invoke(monkeypatch, tmp_path, "replay", str(source), "--save", str(tmp_path / "replayed.tine"))
    _invoke(monkeypatch, tmp_path, "fork", str(source), "--from-step", "0", "--harness", "codex")
    assert Run.load(tmp_path / "replayed.tine").metadata["replay"]["mode"] == "cache"
    assert "Inspecting recorded steps" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# class-level gates: no flag may be silently dropped again
# --------------------------------------------------------------------------- #


def _flags(parser: argparse.ArgumentParser, command: str = "") -> list[tuple[str, str, object]]:
    rows: list[tuple[str, str, object]] = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                rows.extend(_flags(sub, name))
        elif action.option_strings and action.dest != "help":
            rows.append((command, action.dest, action.default))
    return rows


def test_flag_default_table_matches_the_parser_for_every_subcommand():
    """`given()` compares against these defaults; drift would silence a refusal."""
    checked = 0
    for command, dest, default in _flags(_build_parser()):
        if dest not in FLAG_DEFAULTS:
            continue
        flag, expected = FLAG_DEFAULTS[dest]
        assert default == expected, f"tine {command} {flag}: parser={default!r} table={expected!r}"
        checked += 1
    assert checked >= len(FLAG_DEFAULTS), checked


def _source_lines() -> str:
    keep = []
    for path in sorted((ROOT / "opentine").rglob("*.py")) + sorted((ROOT / "scripts").glob("*.py")):
        if "__pycache__" in path.parts or path.name == "_cli_parser.py":
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if "add_argument" in stripped or stripped.startswith("#"):
                continue
            keep.append(stripped)
    return "\n".join(keep)


def test_every_flag_the_parser_accepts_is_read_by_some_command():
    """A flag no implementation mentions is a flag whose user is being ignored.

    Heuristic on purpose: it proves a *reader exists*, not that every mode honours
    the flag (the behavioural tests above do that for run/fork/replay).
    """
    blob = _source_lines()
    unread = sorted(
        {
            f"tine {command} --{dest.replace('_', '-')}"
            for command, dest, _ in _flags(_build_parser())
            if not re.search(rf"\.\s*{re.escape(dest)}\b", blob)
            and not re.search(rf"""["']{re.escape(dest)}["']""", blob)
        }
    )
    assert not unread, f"flags accepted by the parser that nothing reads: {unread}"
