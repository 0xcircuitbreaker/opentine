"""``tine diff --json`` and ``tine diff --exit-code`` over legacy artifacts.

Three things are pinned here, and the first is the reason the other two are
safe to ship:

1. **The default invocation is untouched.** ``tine diff A B`` must still print
   exactly the bytes ``_print_diff_table`` produces and still exit 0, even when
   the two runs differ wildly. The pin is a byte comparison against that
   renderer called directly, so any stray line the command starts printing —
   a summary, a status hint, a JSON object — fails here.
2. **The drift object is one object.** ``diff --json`` and
   ``replay --verify --json`` publish the same four buckets from the same
   builder; the test compares the two live payloads rather than a literal, so
   a bucket added to one and not the other cannot pass.
3. **The exit status is git's.** 0 identical, 1 any difference, and never 2 —
   2 stays argparse's answer to a usage error, which is what lets a caller tell
   "the runs differ" from "you typed it wrong".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._cli_render import _print_diff_table

COMPAT = Path(__file__).parent / "fixtures" / "compat"
DRIFT_BUCKETS = {"structural", "accounting", "only_source", "only_replay"}


def _source(path: Path) -> Run:
    run = Run(id="diff_source", model_info="mock-model", user_prompt="test prompt")
    first = run.add_step(StepKind.think, {"text": "a"}, cost=0.25)
    second = run.add_step(StepKind.tool, {"name": "t", "arguments": {}}, parent_id=first.id)
    run.add_step(StepKind.done, {"text": "c"}, parent_id=second.id)
    run.status = RunStatus.completed
    run.save(path)
    return run


def _restated(path: Path, *, text: str = "a", cost: float = 0.25) -> Run:
    """The same shape as ``_source``, with one field free to differ."""
    run = Run(id="diff_other", model_info="mock-model", user_prompt="test prompt")
    first = run.add_step(StepKind.think, {"text": text}, cost=cost)
    second = run.add_step(StepKind.tool, {"name": "t", "arguments": {}}, parent_id=first.id)
    run.add_step(StepKind.done, {"text": "c"}, parent_id=second.id)
    run.status = RunStatus.completed
    run.save(path)
    return run


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    _source(tmp_path / "source.tine")
    return tmp_path


def _invoke(capsys, *argv: str) -> tuple[int, str]:
    """Drive one in-process ``tine`` invocation; return (exit code, stdout)."""
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _payload(capsys, *argv: str) -> tuple[int, dict]:
    code, out = _invoke(capsys, *argv)
    return code, json.loads(out)


def _documented_keys(section: str) -> set[str]:
    """The keys one ``tine ...`` section of ``_cli_json_flow``'s docstring lists."""
    from opentine import _cli_json_flow

    blocks = [
        block
        for block in (_cli_json_flow.__doc__ or "").split("``tine ")
        if block.startswith(section)
    ]
    assert len(blocks) == 1, f"{section!r} is not one heading in the docstring"
    return set(re.findall(r"^    ``(\w+)``", blocks[0], re.MULTILINE))


# --------------------------------------------------------------------------- #
# (1) the default invocation is byte-identical
# --------------------------------------------------------------------------- #


def test_the_default_invocation_prints_exactly_the_table_and_exits_zero(workspace, capsys):
    """Byte pin: plain ``tine diff`` is the renderer's output and nothing else."""
    other = _restated(workspace / "other.tine", text="different")

    code, printed = _invoke(capsys, "diff", "source.tine", "other.tine")
    _print_diff_table(Run.load(workspace / "source.tine"), Run.load(workspace / "other.tine"))
    rendered = capsys.readouterr().out

    assert printed == rendered
    assert printed.encode() == rendered.encode()
    # The runs differ, and without --exit-code that is still a successful diff.
    assert code == 0 and other.id != "diff_source"


def test_exit_code_changes_the_status_without_touching_the_rendering(workspace, capsys):
    _restated(workspace / "other.tine", text="different")

    plain_code, plain = _invoke(capsys, "diff", "source.tine", "other.tine")
    gated_code, gated = _invoke(capsys, "diff", "source.tine", "other.tine", "--exit-code")

    assert gated == plain
    assert (plain_code, gated_code) == (0, 1)


# --------------------------------------------------------------------------- #
# (2) the JSON object
# --------------------------------------------------------------------------- #


def test_the_diff_object_carries_exactly_its_documented_fields(workspace, capsys):
    """The docstring of ``_cli_json_flow`` is the schema; keep them one thing."""
    _restated(workspace / "other.tine", text="different")

    code, payload = _payload(capsys, "diff", "source.tine", "other.tine", "--json")

    assert code == 0
    assert set(payload) == _documented_keys("diff RUN_A RUN_B --json")
    assert payload["command"] == "diff"
    assert set(payload["left"]) == set(payload["right"]) == {"run_id", "short_id", "path"}
    assert payload["left"]["run_id"] == "diff_source"
    assert payload["right"]["run_id"] == "diff_other"
    assert payload["left"]["path"].endswith("source.tine")
    assert payload["right"]["path"].endswith("other.tine")


def test_json_replaces_the_table_and_writes_one_object_only(workspace, capsys):
    _restated(workspace / "other.tine", text="different")

    _, out = _invoke(capsys, "diff", "source.tine", "other.tine", "--json")

    assert json.loads(out)["command"] == "diff"  # the whole stream parses
    assert "Diff:" not in out and out.count("{\n") >= 1


def test_the_drift_object_is_the_one_replay_verify_publishes(workspace, capsys):
    """Shared builder: the two commands' drift shapes are literally the same."""
    _restated(workspace / "other.tine", text="different")

    _, diffed = _payload(capsys, "diff", "source.tine", "other.tine", "--json")
    _, verdict = _payload(capsys, "replay", "source.tine", "--verify", "--json")

    assert set(diffed["drift"]) == set(verdict["drift"]) == DRIFT_BUCKETS
    # ... and the flat fields the verdict shipped with are that object's buckets.
    assert verdict["structural_drift"] == verdict["drift"]["structural"]
    assert verdict["accounting_drift"] == verdict["drift"]["accounting"]


def test_a_run_diffed_against_itself_is_identical_with_every_bucket_empty(workspace, capsys):
    code, payload = _payload(capsys, "diff", "source.tine", "source.tine", "--json")

    assert code == 0
    assert payload["identical"] is True
    assert payload["drift"] == {bucket: [] for bucket in DRIFT_BUCKETS}
    assert payload["common_ancestor"] == Run.load(workspace / "source.tine").steps[-1].id


def test_structural_drift_names_the_field_that_changed(workspace, capsys):
    _restated(workspace / "other.tine", text="different")

    _, payload = _payload(capsys, "diff", "source.tine", "other.tine", "--json")

    assert payload["identical"] is False
    assert any(entry.endswith(" inputs") for entry in payload["drift"]["structural"])
    assert payload["drift"]["accounting"] == []


def test_accounting_drift_is_bucketed_apart_from_structure(workspace, capsys):
    """Same steps, different cost: the accounting bucket, and nothing structural."""
    _restated(workspace / "dearer.tine", cost=9.5)

    code, payload = _payload(capsys, "diff", "source.tine", "dearer.tine", "--json", "--exit-code")

    assert payload["drift"]["accounting"] == [
        f"{Run.load(workspace / 'source.tine').steps[0].short_id} cost"
    ]
    assert payload["drift"]["structural"] == []
    # git diff has no notion of a difference that does not count: any drift is 1.
    assert payload["identical"] is False and code == 1


def test_a_step_on_one_side_only_lands_in_both_the_bucket_and_the_structural_list(
    workspace, capsys
):
    """A fork keeps the ancestor closure, so the source carries steps it lacks."""
    source = Run.load(workspace / "source.tine")
    source.fork(source.steps[0].id, nonce="").save(workspace / "fork.tine")

    _, payload = _payload(capsys, "diff", "source.tine", "fork.tine", "--json")

    only_source = payload["drift"]["only_source"]
    assert only_source and payload["drift"]["only_replay"] == []
    assert {f"{entry} missing" for entry in only_source} <= set(payload["drift"]["structural"])
    assert payload["identical"] is False


# --------------------------------------------------------------------------- #
# (3) exit status: 0 identical, 1 differs, never 2
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("flags", [(), ("--json",)])
def test_identical_runs_exit_zero_under_exit_code(workspace, capsys, flags):
    code, _ = _invoke(capsys, "diff", "source.tine", "source.tine", "--exit-code", *flags)

    assert code == 0


@pytest.mark.parametrize("flags", [(), ("--json",)])
def test_differing_runs_exit_one_under_exit_code(workspace, capsys, flags):
    _restated(workspace / "other.tine", text="different")

    code, _ = _invoke(capsys, "diff", "source.tine", "other.tine", "--exit-code", *flags)

    assert code == 1


def test_a_difference_is_never_reported_as_two_because_argparse_owns_two(workspace, capsys):
    _restated(workspace / "other.tine", text="different")

    differed, _ = _invoke(capsys, "diff", "source.tine", "other.tine", "--exit-code")
    with pytest.raises(SystemExit) as usage:
        cli.main(["diff", "source.tine", "other.tine", "--no-such-flag"])

    assert differed == 1
    assert usage.value.code == 2


def test_a_missing_run_is_a_human_message_and_never_a_json_object(workspace, capsys):
    """No comparison happened, so there is no object to emit — exit 1, not 2."""
    code, out = _invoke(capsys, "diff", "source.tine", "nope.tine", "--json", "--exit-code")

    assert code == 1
    assert "Run not found" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


# --------------------------------------------------------------------------- #
# (4) backwards compatibility: the new flags read every stored-data shape
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("version", ["v0_3_0", "v0_4_0", "v0_5_0"])
def test_the_flags_run_over_artifacts_written_by_older_releases(
    monkeypatch, tmp_path, capsys, version
):
    artifact = COMPAT / version / "artifact.tine"
    if not artifact.is_file():
        pytest.skip(f"no artifact.tine in the {version} golden set")
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)

    same, payload = _payload(capsys, "diff", str(artifact), str(artifact), "--json", "--exit-code")

    assert same == 0
    assert payload["identical"] is True and set(payload["drift"]) == DRIFT_BUCKETS
    assert payload["left"] == payload["right"]


@pytest.mark.parametrize("version", ["v0_3_0", "v0_4_0", "v0_5_0"])
def test_an_older_fork_still_diffs_against_the_artifact_it_came_from(
    monkeypatch, tmp_path, capsys, version
):
    artifact, fork = COMPAT / version / "artifact.tine", COMPAT / version / "fork.tine"
    if not (artifact.is_file() and fork.is_file()):
        pytest.skip(f"no artifact/fork pair in the {version} golden set")
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)

    code, payload = _payload(capsys, "diff", str(artifact), str(fork), "--json", "--exit-code")

    # Every golden fork was taken before the artifact's tip, so the source keeps
    # steps the fork never had: the difference is real on all three versions.
    assert (code, payload["identical"]) == (1, False)
    assert set(payload["drift"]) == DRIFT_BUCKETS
    assert payload["drift"]["only_source"] and payload["drift"]["only_replay"] == []
    assert {f"{entry} missing" for entry in payload["drift"]["only_source"]} == set(
        payload["drift"]["structural"]
    )
    assert payload["left"]["run_id"] == Run.load(artifact).id
    assert payload["common_ancestor"] is not None
