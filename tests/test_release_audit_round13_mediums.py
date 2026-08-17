"""Round-13 audit regressions: the two MEDIUM findings, both duplication bugs.

Neither is exotic.  Each is one behaviour written twice, where only one copy was
ever corrected:

* ``tools/shell._clean_env`` and ``tools/python._clean_env`` were the same
  helper under the same name in two modules.  The python one scrubbed
  ``*KEY*``/``*SECRET*``/``*TOKEN*``/… on ``inherit_env``; the shell one returned
  ``dict(os.environ)`` verbatim, so ANTHROPIC_API_KEY went to the subprocess and
  came back into model context through the command's own output.
* every artifact-writing verb guards its destination with
  ``_require_output_slot`` -- sign, keygen, migrate, fork, replay, import,
  export.  ``tine run --save`` was the one that did not, so running the same
  script twice destroyed the first artifact with no warning and exit 0.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from opentine import cli
from opentine.policies import PythonPolicy, ShellPolicy
from opentine.tools import _process, python, shell

ROOT = Path(__file__).resolve().parents[1]

#: Printed by the subprocess under test: the credential it must never receive,
#: and a harmless inherited name that must still arrive.
PROBE = (
    'import os; print(os.environ.get("TEST_SECRET_TOKEN", "missing"), '
    'os.environ.get("TINE_PARITY_MARKER", "missing"), bool(os.environ.get("PATH")))'
)


@pytest.fixture
def probed(monkeypatch):
    monkeypatch.setenv("TEST_SECRET_TOKEN", "leak")
    monkeypatch.setenv("TINE_PARITY_MARKER", "kept")


# --- finding 9: the shell tool handed the caller's credentials to a subprocess ---


def test_the_shell_tool_scrubs_credentials_from_the_environment_it_inherits(probed):
    # A single-quote-wrapped -c snippet that quotes only with double quotes, and
    # python3 (aliased to sys.executable on win32): shlex.quote would emit the
    # POSIX '"'"' escape the win32 posix=False command splitter cannot parse.
    # Mirrors the shell tests in test_core so it runs on every platform without a
    # skip guard.
    out = shell.run(
        f"python3 -c '{PROBE}'",
        policy=ShellPolicy(enabled=True, executables=("python3",), inherit_env=True),
    )
    assert out == "missing kept True", out


def test_the_python_tool_still_scrubs_exactly_what_it_always_did(probed):
    # The regression guard for the shared helper: python.execute's behaviour is
    # the one being adopted, so it must be unchanged in both modes.
    inherited = python.execute(PROBE, policy=PythonPolicy(enabled=True, inherit_env=True))
    assert inherited == "missing kept True", inherited
    allowlisted = python.execute(
        PROBE,
        policy=PythonPolicy(enabled=True, env_allowlist=("TINE_PARITY_MARKER", "PATH")),
    )
    assert allowlisted == "missing kept True", allowlisted


SENSITIVE = (
    "ANTHROPIC_API_KEY",
    "aws_secret_access_key",
    "GH_TOKEN",
    "PGPASSWORD",
    "GOOGLE_CREDENTIALS",
    "PROXY_AUTH",
)


def test_both_tools_scrub_through_one_helper_so_they_cannot_diverge_again(probed, monkeypatch):
    # Two spellings of one rule is how the divergence happened; one object,
    # reached from both modules, is the fix that cannot come apart again.
    assert shell.clean_env is python.clean_env is _process.clean_env
    for module in (shell, python):
        assert not hasattr(module, "_clean_env"), module.__name__

    for name in SENSITIVE:
        monkeypatch.setenv(name, "leak")
    scrubbed = _process.clean_env(True, ())
    assert not [name for name in SENSITIVE if name in scrubbed]
    assert scrubbed["TINE_PARITY_MARKER"] == "kept" and "TEST_SECRET_TOKEN" not in scrubbed
    # The allowlist half is unchanged: named is named, sensitive or not.
    assert _process.clean_env(False, ("GH_TOKEN", "ABSENT")) == {"GH_TOKEN": "leak"}


# --- finding 10: `tine run --save` was the one verb that silently overwrote ---

SCRIPT = """
from opentine import Run, StepKind

run = Run(id="overwrite-guard")
run.add_step(StepKind.think, {"note": "first"}, {"ok": True})
"""


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "s.py").write_text(SCRIPT, encoding="utf-8")
    return tmp_path


def test_run_save_onto_an_existing_file_refuses_instead_of_destroying_it(workspace, capsys):
    keep = workspace / "keep.tine"
    keep.write_text("IRREPLACEABLE", encoding="utf-8")

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["run", "s.py", "--save", "keep.tine"])

    assert exit_info.value.code == 1
    assert "Refusing to overwrite" in capsys.readouterr().out
    assert keep.read_text(encoding="utf-8") == "IRREPLACEABLE"


def test_run_save_with_force_replaces_the_destination(workspace, capsys):
    keep = workspace / "keep.tine"
    keep.write_text("IRREPLACEABLE", encoding="utf-8")

    cli.main(["run", "s.py", "--save", "keep.tine", "--force"])

    assert "Saved:" in capsys.readouterr().out
    assert "overwrite-guard" in keep.read_text(encoding="utf-8")


def test_the_default_receipt_location_stays_unguarded(workspace, capsys):
    # Keyed by the run id, which is content-addressed: re-writing it is
    # idempotent rather than destructive, so a --force-less second run of the
    # same script must still work exactly as it always has.
    cli.main(["run", "s.py"])
    cli.main(["run", "s.py"])
    assert capsys.readouterr().out.count("Saved:") == 2
    assert (workspace / ".tine_runs" / "overwrite-guard.tine").exists()


def test_harness_mode_refuses_before_it_starts_the_agent(workspace, capsys):
    # --harness checkpoints straight into --save, so the refusal has to land
    # before the agent runs: the command names a binary that does not exist and
    # still exits on the slot, never on a failed spawn.
    from opentine._cli_execute import cmd_run
    from opentine._cli_parser import _build_parser

    keep = workspace / "keep.tine"
    keep.write_text("IRREPLACEABLE", encoding="utf-8")
    argv = ["run", "--harness", "generic", "--harness-command", "no-such-binary-xyz"]
    args = _build_parser().parse_args([*argv, "--prompt", "x", "--save", "keep.tine"])

    with pytest.raises(SystemExit) as exit_info:
        cmd_run(args)

    assert exit_info.value.code == 1
    assert "Refusing to overwrite" in capsys.readouterr().out
    assert keep.read_text(encoding="utf-8") == "IRREPLACEABLE"


def test_every_run_mode_claims_its_save_slot_before_it_writes():
    """All three ``tine run`` modes must reach the guard; none may drift past it.

    Script mode is exercised above end to end.  ``--harness`` and ``--model``
    need a live agent CLI or a provider key to get there, so the guard on those
    two is source-level: every ``_save_run_receipt`` call passes a waiver
    argument, and the one that passes ``force=True`` -- ``--harness``, whose
    checkpoints have already written the destination by then -- must claim the
    slot with ``_require_output_slot`` *before* the agent starts.
    """
    execute = (ROOT / "opentine" / "_cli_execute.py").read_text(encoding="utf-8")
    calls = []
    for name in ("_cli_execute.py", "_cli_run_model.py"):
        tree = ast.parse((ROOT / "opentine" / name).read_text(encoding="utf-8"))
        calls += [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_save_run_receipt"
        ]
    assert len(calls) == 3, "a `tine run` mode appeared or vanished; re-point this guard"
    waivers = {ast.unparse(call).split("args.save", 1)[1].strip(" ,)") for call in calls}
    assert waivers == {"args.force", "force=True"}, waivers
    assert "_require_output_slot(output, args.force)" in execute


def test_run_declares_force_with_the_default_the_refusal_table_expects():
    from opentine._cli_flags import FLAG_DEFAULTS
    from opentine._cli_parser import _build_parser

    subs = next(
        action
        for action in _build_parser()._actions
        if hasattr(action, "choices") and action.choices
    )
    force = next(action for action in subs.choices["run"]._actions if action.dest == "force")
    assert (force.default, force.option_strings) == (FLAG_DEFAULTS["force"][1], ["--force"])
