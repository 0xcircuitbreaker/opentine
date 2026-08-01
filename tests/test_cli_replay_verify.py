"""``tine replay --verify`` and the ``--inspect`` preview it fixed.

Two things ship together here, because they are the same defect seen twice:

1. **The shipped preview bug.** ``tine replay --inspect``/``--dry-run`` listed
   ``graph.descendant_closure(from_step)`` — the steps *after* the fork point —
   while ``Run.fork`` retains the ANCESTOR closure, the steps that led *to* it.
   On a linear run the two agree by accident; on a branched one the preview was
   the complement of what the replay reuses. Preview, verdict and fork now read
   one helper (``_graph_analysis.retained_closure`` via ``expected_slice``), and
   the tests below pin the three against each other on a branched run.

2. **The check itself.** ``Run.fork`` deep-copies in memory, so a diff between a
   fork and its source always passes: a green check built that way proves
   nothing. ``--verify`` instead saves the replay to a temporary path, loads it
   back, derives the replay a *second* time from the source bytes, and requires
   the two to agree on the 64-hex id, on the retained slice, on the canonical
   digest of the round-tripped file, and on every structural field.

Because the check is designed never to fail on healthy data, the drift tests
sabotage the *second* derivation through the seam both derivations go through
(``cache_replay``). That is the only way to prove the comparison can fail, and
therefore the only way to prove a pass means something.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._cli_verify_replay import ACCOUNTING_FIELDS, cache_replay, expected_slice
from opentine._graph_analysis import retained_closure
from opentine._graph_diff import _drift, _fields, diff_runs
from opentine._graph_types import Step

COMPAT = Path(__file__).parent / "fixtures" / "compat"
HEX64 = re.compile(r"[0-9a-f]{64}")


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #


def _branched(path: Path | None = None) -> Run:
    """A run whose ancestor and descendant closures differ.

    ``a -> b -> c`` with a second child ``d`` hanging off ``a``. A replay from
    ``c`` retains {a, b, c}; the descendants of ``c`` are {c} alone; the whole
    run is four steps. Three different answers, so no preview can be right by
    accident.
    """
    run = Run(id="verify_source", model_info="mock-model", user_prompt="test prompt")
    first = run.add_step(StepKind.think, {"text": "a"})
    second = run.add_step(StepKind.tool, {"name": "t", "arguments": {}}, parent_id=first.id)
    run.add_step(StepKind.done, {"text": "c"}, parent_id=second.id)
    run.add_step(StepKind.think, {"text": "d"}, parent_id=first.id)
    run.status = RunStatus.completed
    if path is not None:
        run.save(path)
    return run


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    _branched(tmp_path / "source.tine")
    return tmp_path


def _invoke(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    """Drive ``cli.main()`` exactly as the console script does; return (code, output)."""
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _payload(monkeypatch, capsys, *argv: str) -> tuple[int, dict]:
    code, out = _invoke(monkeypatch, capsys, *argv)
    return code, json.loads(out)


def _tine_temp_dirs() -> set[Path]:
    return set(Path(tempfile.gettempdir()).glob("tine-verify-*"))


# --------------------------------------------------------------------------- #
# (1) the preview bug: inspect, the expected slice, and fork must agree
# --------------------------------------------------------------------------- #


def test_inspect_previews_the_ancestor_closure_the_replay_actually_retains(
    workspace, monkeypatch, capsys
):
    run = Run.load(workspace / "source.tine")
    ancestors, descendants = run.steps[:3], [run.steps[2]]

    code, out = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--inspect", "--from-step", run.steps[2].id
    )

    assert code == 0
    for step in ancestors:
        assert step.short_id in out
    assert run.steps[3].short_id not in out, "the other branch is not retained"
    assert "would reuse 3 recorded steps" in out
    # The pre-fix preview listed exactly this one step and called it the replay.
    assert len(descendants) == 1 and out.count("think") == 1


def test_the_preview_the_verdict_and_fork_all_report_the_same_slice(workspace, monkeypatch, capsys):
    run = Run.load(workspace / "source.tine")
    tip = run.steps[2].id

    point, expected = expected_slice(run, tip)
    forked = run.fork(point, intent={"replay": "cache"}, nonce="")
    _, previewed = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--inspect", "--from-step", tip
    )
    code, verdict = _payload(
        monkeypatch, capsys, "replay", "source.tine", "--verify", "--json", "--from-step", tip
    )

    assert set(forked.graph.steps) == expected == {step.id for step in run.steps[:3]}
    assert f"would reuse {len(expected)} recorded steps" in previewed
    assert (code, verdict["expected_steps"], verdict["reused_steps"]) == (0, len(expected), 3)
    assert verdict["fork_point"] == point == tip
    assert verdict["slice_ok"] is True


def test_the_expected_slice_follows_v3_causal_edges_exactly_as_fork_does():
    """The helper is not "ancestors": ``fork`` also walks ``_v3_causal_ids``."""
    run = _branched()
    tip, other = run.steps[2].id, run.steps[3].id
    run._v3_causal_ids = {tip: [other]}

    point, expected = expected_slice(run, tip)
    forked = run.fork(point, intent={"replay": "cache"}, nonce="")

    assert other in expected, "a causal parent is retained and must be previewed"
    assert expected == retained_closure(run, tip) == set(forked.graph.steps)


def test_inspect_of_a_stepless_run_still_lists_nothing_instead_of_failing(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    Run(id="empty").save(tmp_path / "empty.tine")

    code, out = _invoke(monkeypatch, capsys, "replay", "empty.tine", "--inspect")

    assert code == 0
    assert "would reuse 0 recorded steps" in out


# --------------------------------------------------------------------------- #
# (2) the round trip: what makes the check non-tautological
# --------------------------------------------------------------------------- #


def test_verify_reproduces_a_cached_replay(workspace, monkeypatch, capsys):
    code, out = _invoke(monkeypatch, capsys, "replay", "source.tine", "--verify")

    assert code == 0
    assert "REPRODUCED" in out and "DRIFT" not in out
    assert "round trip sha256:" in out and "verified" in out


def test_both_derivations_mint_the_same_hex64_id_and_the_saved_digest_verifies(
    workspace, monkeypatch, capsys
):
    """The property an in-memory diff cannot see: the id survives save->load."""
    code, verdict = _payload(monkeypatch, capsys, "replay", "source.tine", "--verify", "--json")

    assert code == 0
    assert HEX64.fullmatch(verdict["replay_id"])
    assert verdict["replay_id"] == verdict["second_id"], "two derivations, one identity"
    assert verdict["identity_ok"] is True
    assert verdict["integrity"] == {
        "ok": True,
        "algorithm": "sha256",
        "expected": verdict["integrity"]["actual"],
        "actual": verdict["integrity"]["actual"],
        "reason": "ok",
        "draft": False,
    }
    assert HEX64.fullmatch(verdict["integrity"]["actual"])


def test_verify_checks_the_bytes_a_plain_replay_would_have_written(workspace, monkeypatch, capsys):
    """One ``cache_replay`` for both, so the check cannot drift from the command."""
    replayed, verified = workspace / "plain.tine", workspace / "verified.tine"

    assert _invoke(monkeypatch, capsys, "replay", "source.tine", "--save", str(replayed))[0] == 0
    code, _ = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--verify", "--save", str(verified)
    )

    assert code == 0
    plain, checked = (json.loads(path.read_text(encoding="utf-8")) for path in (replayed, verified))
    # Everything but the wall clock, and the digest that necessarily follows it.
    for document in (plain, checked):
        document.pop("created_at")
        document["metadata"].pop("integrity")
    assert checked == plain
    assert checked["run_id"] == plain["run_id"], "one derivation, one identity"


# --------------------------------------------------------------------------- #
# (3) drift: proving the check can fail
# --------------------------------------------------------------------------- #


def _sabotage(monkeypatch, mutate) -> None:
    """Corrupt only the SECOND derivation, through the seam both go through."""
    from opentine import _cli_verify_replay as module

    original, seen = module.cache_replay, []

    def patched(run: Run, fork_point: str) -> Run:
        replayed = original(run, fork_point)
        seen.append(replayed)
        if len(seen) == 2:
            mutate(replayed)
        return replayed

    monkeypatch.setattr(module, "cache_replay", patched)


def _accounting_drift(run: Run) -> None:
    """Same step id, different cost: exactly what ``_graph_diff._drift`` reports."""
    object.__setattr__(run.steps[-1], "cost", run.steps[-1].cost + 0.25)


def _structural_drift(run: Run) -> None:
    """A leaf replaced by one with different content, so its id changes too."""
    leaf = run.steps[-1]
    twin = replace(leaf, id="f" * 64, outputs={"text": "drifted"})
    run.graph.steps.pop(leaf.id)
    run.graph.steps[twin.id] = twin
    run.graph.order[run.graph.order.index(leaf.id)] = twin.id
    run.refs = {name: (twin.id if tip == leaf.id else tip) for name, tip in run.refs.items()}


def test_structural_drift_is_reported_and_fails(workspace, monkeypatch, capsys):
    _sabotage(monkeypatch, _structural_drift)

    code, verdict = _payload(monkeypatch, capsys, "replay", "source.tine", "--verify", "--json")

    assert code == 1
    assert verdict["ok"] is False
    assert any("outputs" in entry for entry in verdict["structural_drift"]), verdict
    assert verdict["accounting_drift"] == []


def test_accounting_drift_alone_fails_but_is_downgradable(workspace, monkeypatch, capsys):
    _sabotage(monkeypatch, _accounting_drift)

    code, verdict = _payload(monkeypatch, capsys, "replay", "source.tine", "--verify", "--json")

    assert code == 1
    assert verdict["structural_drift"] == []
    assert [entry.split()[-1] for entry in verdict["accounting_drift"]] == ["cost"]
    assert verdict["identity_ok"] is True and verdict["slice_ok"] is True


def test_ignore_cost_drift_never_downgrades_structural_drift(workspace, monkeypatch, capsys):
    _sabotage(monkeypatch, _structural_drift)

    code, verdict = _payload(
        monkeypatch,
        capsys,
        "replay",
        "source.tine",
        "--verify",
        "--ignore-cost-drift",
        "--json",
    )

    assert code == 1
    assert verdict["ok"] is False and verdict["ignore_cost_drift"] is True
    assert verdict["structural_drift"]


def test_the_human_rendering_names_the_drifted_field(workspace, monkeypatch, capsys):
    _sabotage(monkeypatch, _accounting_drift)

    code, out = _invoke(monkeypatch, capsys, "replay", "source.tine", "--verify")

    assert code == 1
    assert "DRIFT" in out and "accounting drift" in out and "cost" in out


def test_the_two_drift_buckets_are_exactly_the_two_the_diff_reports():
    """Class guard: a new ``_drift`` field must join ACCOUNTING_FIELDS knowingly."""
    left = Step(id="a" * 64, parent_ids=[], kind=StepKind.think, inputs={"text": "x"})
    right = replace(
        left,
        id="b" * 64,
        inputs={"text": "y"},
        outputs={"text": "z"},
        model_info="other",
        tool_info={"name": "t"},
        error={"message": "e"},
        cost=1.5,
        usage={"input": 3},
        billing={"currency": "EUR"},
    )

    accounting = {delta.name for delta in _drift(left, right)}
    structural = {delta.name for delta in _fields(left, right)} - accounting

    assert accounting == set(ACCOUNTING_FIELDS)
    assert structural == {"inputs", "outputs", "model_info", "tool_info", "error"}


# --------------------------------------------------------------------------- #
# (4) exit codes are binary, and failures without a verdict are not JSON
# --------------------------------------------------------------------------- #


def test_a_source_that_does_not_load_exits_one_with_human_text_not_json(
    workspace, monkeypatch, capsys
):
    """No replay, no comparison, no verdict — so there is no object to emit."""
    (workspace / "broken.tine").write_text("{not json", encoding="utf-8")

    code, out = _invoke(monkeypatch, capsys, "replay", "broken.tine", "--verify", "--json")

    assert code == 1
    assert "Cannot verify" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_a_missing_source_exits_one_with_human_text_not_json(workspace, monkeypatch, capsys):
    code, out = _invoke(monkeypatch, capsys, "replay", "nowhere.tine", "--verify", "--json")

    assert code == 1
    assert "Run not found" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_an_unresolvable_step_reference_exits_one_without_a_verdict(workspace, monkeypatch, capsys):
    code, out = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--verify", "--from-step", "99", "--json"
    )

    assert code == 1
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_rerun_verify_without_a_harness_refuses_instead_of_pretending(
    workspace, monkeypatch, capsys
):
    code, out = _invoke(monkeypatch, capsys, "replay", "source.tine", "--verify", "--mode", "rerun")

    assert code == 1
    assert "Rerun replay requires an explicit --harness" in out


@pytest.mark.parametrize(
    ("mutate", "extra", "expected"),
    [
        (None, (), 0),
        (None, ("--ignore-cost-drift",), 0),
        (_accounting_drift, (), 1),
        (_accounting_drift, ("--ignore-cost-drift",), 0),
        (_structural_drift, (), 1),
        (_structural_drift, ("--ignore-cost-drift",), 1),
    ],
    ids=["clean", "clean+ignore", "cost", "cost+ignore", "structural", "structural+ignore"],
)
def test_exit_code_matrix(workspace, monkeypatch, capsys, mutate, extra, expected):
    if mutate is not None:
        _sabotage(monkeypatch, mutate)

    code, _ = _invoke(monkeypatch, capsys, "replay", "source.tine", "--verify", *extra)

    assert code == expected


# --------------------------------------------------------------------------- #
# (5) --verify writes nothing without --save, and cleans up after itself
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("target", "mutate", "expected"),
    [
        ("source.tine", None, 0),
        ("source.tine", _structural_drift, 1),
        ("broken.tine", None, 1),
        ("nowhere.tine", None, 1),
    ],
    ids=["reproduced", "drift", "unloadable", "missing"],
)
def test_verify_leaves_no_artifact_and_no_temp_directory_behind(
    workspace, monkeypatch, capsys, target, mutate, expected
):
    (workspace / "broken.tine").write_text("{not json", encoding="utf-8")
    before = _tine_temp_dirs()
    if mutate is not None:
        _sabotage(monkeypatch, mutate)

    code, _ = _invoke(monkeypatch, capsys, "replay", target, "--verify")

    assert code == expected
    runs = workspace / ".tine_runs"
    assert not runs.exists() or list(runs.glob("*")) == []
    assert sorted(path.name for path in workspace.glob("*.tine")) == ["broken.tine", "source.tine"]
    assert _tine_temp_dirs() - before == set()


def test_save_writes_the_verified_bytes_and_still_refuses_to_overwrite(
    workspace, monkeypatch, capsys
):
    output = workspace / "kept.tine"

    first, _ = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--verify", "--save", str(output)
    )
    second, out = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--verify", "--save", str(output)
    )

    assert first == 0
    assert Run.load(output).metadata["replay"]["source_run"] == "verify_source"
    assert (second, "Refusing to overwrite existing file" in out) == (1, True)
    assert "Pass --force" in out


def test_the_overwrite_refusal_happens_before_any_work(workspace, monkeypatch, capsys):
    """A refusal must not leave a temp workspace or a half-written destination."""
    output = workspace / "taken.tine"
    output.write_text("do not touch", encoding="utf-8")
    before = _tine_temp_dirs()

    code, _ = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--verify", "--save", str(output)
    )

    assert code == 1
    assert output.read_text(encoding="utf-8") == "do not touch"
    assert _tine_temp_dirs() - before == set()


def test_force_replaces_the_destination(workspace, monkeypatch, capsys):
    output = workspace / "kept.tine"
    output.write_text("stale", encoding="utf-8")

    code, _ = _invoke(
        monkeypatch, capsys, "replay", "source.tine", "--verify", "--save", str(output), "--force"
    )

    assert code == 0
    assert Run.load(output).metadata["replay"]["mode"] == "cache"


# --------------------------------------------------------------------------- #
# (6) flags no mode can honour are refused, not dropped
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (("--json",), "--json has no effect without --verify"),
        (("--ignore-cost-drift",), "--ignore-cost-drift has no effect without --verify"),
        (("--inspect", "--verify"), "--verify has no effect with --inspect/--dry-run"),
        (("--dry-run", "--json"), "--json has no effect with --inspect/--dry-run"),
    ],
    ids=["json", "ignore-cost-drift", "inspect+verify", "dry-run+json"],
)
def test_replay_refuses_verification_flags_its_mode_ignores(
    workspace, monkeypatch, capsys, argv, expected
):
    code, out = _invoke(monkeypatch, capsys, "replay", "source.tine", *argv)

    assert code == 1
    assert expected in re.sub(r"\s+", " ", out)
    assert (
        not (workspace / ".tine_runs").exists() or list((workspace / ".tine_runs").glob("*")) == []
    )


# --------------------------------------------------------------------------- #
# (7) backwards compatibility: the check runs over every stored-data shape
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("version", ["v0_3_0", "v0_4_0", "v0_5_0"])
@pytest.mark.parametrize("name", ["artifact.tine", "fork.tine"])
def test_verify_reproduces_replays_of_artifacts_written_by_older_releases(
    monkeypatch, tmp_path, capsys, version, name
):
    """A newer opentine must read >=0.3.0 data — and now replay it verifiably."""
    source = COMPAT / version / name
    if not source.is_file():
        pytest.skip(f"no {name} in the {version} golden set")
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)

    code, verdict = _payload(monkeypatch, capsys, "replay", str(source), "--verify", "--json")

    assert code == 0, verdict
    assert verdict["ok"] is True and verdict["slice_ok"] is True
    assert verdict["reused_steps"] == verdict["expected_steps"] > 0
    assert HEX64.fullmatch(verdict["replay_id"])


def test_the_verdict_object_carries_exactly_its_documented_fields(workspace, monkeypatch, capsys):
    """The docstring of ``_cli_json_flow`` is the schema; keep them one thing."""
    from opentine import _cli_json_flow

    _, verdict = _payload(monkeypatch, capsys, "replay", "source.tine", "--verify", "--json")
    documented = set(re.findall(r"^    ``(\w+)``", _cli_json_flow.__doc__ or "", re.MULTILINE))

    assert set(verdict) == documented
    assert verdict["command"] == "replay-verify"


def test_the_flow_writer_extends_the_json_contract_instead_of_restating_it():
    """One JSON writer in the CLI: this module must go through ``_cli_json.emit``."""
    source = (Path(__file__).resolve().parents[1] / "opentine/_cli_json_flow.py").read_text("utf-8")

    assert "from opentine._cli_json import emit" in source
    assert "print(" not in source and "json.dumps" not in source
    assert "_cli_json" in (source.split('"""')[1])  # the docstring points at the contract


def test_the_shared_helper_is_what_a_replay_of_old_data_retains(tmp_path):
    """The compat gate again, at the level below the CLI."""
    run = Run.load(COMPAT / "v0_3_0" / "artifact.tine")
    point, expected = expected_slice(run, None)

    replayed = cache_replay(run, point)
    replayed.save(tmp_path / "replay.tine")

    assert set(Run.load(tmp_path / "replay.tine").graph.steps) == expected
    assert diff_runs(replayed, Run.load(tmp_path / "replay.tine")).changed == []
