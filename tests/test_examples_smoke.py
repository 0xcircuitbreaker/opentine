"""The shipped examples actually run, in this process, with no network.

An example that no longer executes is a broken on-ramp: it is the first code a
new user copies, and nothing else in the suite imports it. Four of the seven
need nothing but a plain install, so the suite simply runs them — two take a
working directory as ``argv[1]``, and two write into the current directory and
are executed inside ``tmp_path``.

The other three need a provider key or interactive input. They are declared in
:data:`CREDENTIAL_DEPENDENT_EXAMPLES` and compile-checked only, and
:func:`test_every_example_is_either_executed_or_declared` fails when a new file
appears in ``examples/`` without a decision either way.
"""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from opentine import Repo, Run, cli

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"

#: Offline examples that take their working directory as ``argv[1]``.
WORKDIR_EXAMPLES = ("otel_interop.py", "v3_repository.py")

#: Offline examples that write into the current directory instead.
CWD_EXAMPLES = ("forked_debug.py", "harness_comparison.py")

#: Examples that need a provider key or an interactive prompt, so they are read
#: for syntax only. Adding a key-dependent example means adding it here.
CREDENTIAL_DEPENDENT_EXAMPLES = ("cross_model.py", "demo_research.py", "live_demo.py")


def _execute(name: str, *argv: str) -> None:
    """Run one example as ``__main__`` with *argv* after the script path."""
    script = EXAMPLES / name
    original = sys.argv
    sys.argv = [str(script), *argv]
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exit_code:
        assert exit_code.code in (None, 0), f"{name} exited {exit_code.code}"
    finally:
        sys.argv = original


def test_every_example_is_either_executed_or_declared():
    present = {path.name for path in EXAMPLES.glob("*.py")}
    declared = set(WORKDIR_EXAMPLES) | set(CWD_EXAMPLES) | set(CREDENTIAL_DEPENDENT_EXAMPLES)
    assert present == declared, (
        "a new example must either be executed by this module or be declared credential-dependent"
    )


def test_v3_repository_example_builds_a_promoted_verified_repository(tmp_path, capsys):
    root = tmp_path / "demo"
    _execute("v3_repository.py", str(root))
    output = capsys.readouterr().out
    assert "Initialized OpenTine repository" in output
    assert "Created promotions/production" in output

    repo = Repo.open(root)
    assert repo.fsck().ok
    # The promotion points at the forked experiment, not at the baseline.
    promoted = repo.read_ref("promotions/production")
    assert promoted == repo.read_ref("experiments/terse")
    assert promoted != repo.read_ref("heads/main")

    cli.main(["repo-diff", "heads/main", "experiments/terse", "--repo", str(root), "--json"])
    diff = json.loads(capsys.readouterr().out)
    assert diff["identical"] is False
    assert diff["common_events"], "the fork must share its ancestors with the baseline"


def test_otel_interop_example_round_trips_a_foreign_trace(tmp_path, capsys):
    work = tmp_path / "interop"
    _execute("otel_interop.py", str(work))
    assert "survived import -> export unchanged" in capsys.readouterr().out

    document = json.loads((work / "roundtrip.json").read_text(encoding="utf-8"))
    assert len(document["resourceSpans"][0]["scopeSpans"][0]["spans"]) == 3
    assert (work / "imported.tine").is_file()
    assert Repo.open(work / "repo").fsck().ok


def test_forked_debug_example_writes_a_loadable_fork(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _execute("forked_debug.py")
    assert "Fork a Failed Run" in capsys.readouterr().out

    failed = Run.load(tmp_path / "failed_run.tine")
    fixed = Run.load(tmp_path / "fixed_run.tine")
    assert failed.status.value == "failed"
    assert fixed.status.value == "completed"
    assert fixed.metadata["forked_from"] == failed.id
    assert Run.load(tmp_path / "resumed_run.tine").steps


def test_harness_comparison_example_records_one_run_per_harness(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _execute("harness_comparison.py")
    assert "Harness comparison" in capsys.readouterr().out

    for name in ("claude-code", "codex", "cursor"):
        assert (tmp_path / f"{name}_comparison.tine").is_file()
    forked = Run.load(tmp_path / "forked_from_claude_code.tine")
    assert forked.metadata["strategy"] == "retry-from-first-tool-with-cheaper-harness"


@pytest.mark.parametrize("name", CREDENTIAL_DEPENDENT_EXAMPLES)
def test_credential_dependent_examples_still_compile(name):
    source = (EXAMPLES / name).read_text(encoding="utf-8")
    compile(source, str(EXAMPLES / name), "exec")
