"""Round-11 audit regressions: shapes the loader, the accountant and the index trusted.

One class, three files. Every site here paired a default that rescues *absence*
(``.get(k, {})``, ``or {}``, ``setdefault``) with a container it then dereferenced,
iterated or grew -- so an explicit ``null`` or a scalar in an operator-editable
region of the artifact reached ``.get``/``.append``/``in``/``[key] =`` and raised a
raw interpreter error, never a typed refusal.

* ``_graph_serde.run_from_dict`` was the worst of the three because it is the
  *loader*: ``validate_run_record`` deliberately permits ``manifest.model = null``,
  ``.get("model", {})`` returns ``None`` for an explicit null, and so *every* command
  (show, cost, diff, fork, replay, ls, MCP) died with ``AttributeError: 'NoneType'
  object has no attribute 'get'`` on a file this build's own validator accepts.
* ``_runtime_accounting`` grew five ``manifest.pricing``/``metadata.warnings``
  containers without checking any of them, all reachable today through
  ``agent.resume()`` on a loaded artifact -- no fork required.
* ``index._build_entry`` contained only ``Run.load``, not the field extraction after
  it, so a run that *loads* but whose fields cannot be extracted aborted ``sync()``
  and blinded ``ls``/``search`` for every healthy run in the directory instead of
  marking one entry unreadable.

A malformed value is never laundered into a positive claim: a repaired pricing
container forces ``complete: false``, and only a literal ``True`` counts as a
proven-complete cost record for ``Budget(strict_cost=True)``.
"""

from __future__ import annotations

import asyncio
import json
import sys

import pytest

from opentine import Run, StepKind, cli
from opentine._artifact_shapes import validate_run_record
from opentine.budget import Budget
from opentine.graph import RunStatus
from opentine.index import RunIndex
from opentine.runtime import Agent

# manifest.pricing has no schema at all, so any JSON value can appear there.
NON_DICT = {"int": 5, "float": 1.5, "true": True, "str": "abc", "none": None, "list": []}
NON_LIST = {"int": 5, "str": "abc", "dict": {"a": 1}, "none": None, "true": True}
# null is validator-*legal* for manifest.model and is covered separately; these are the
# shapes the validator rejects, kept here so the loader is proved not to depend on it.
NON_MAPPING = {"int": 5, "str": "abc", "list": [1], "true": True, "float": 1.5}


def _invoke(monkeypatch, *args: str) -> None:
    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


def _saved(tmp_path, name: str, *, manifest=None, metadata=None, steps: int = 1) -> Run:
    run = Run(id=name, model_info="m/1")
    for index in range(steps):
        run.add_step(StepKind.model, {"text": f"s{index}"}, {"result": "r"}, model_info="m/1")
    run.manifest.update(manifest or {})
    run.metadata.update(metadata or {})
    run.status = RunStatus.completed
    run.save(tmp_path / f"{name}.tine")
    return run


# --------------------------------------------------------------------------------------
# (1) the loader: manifest.model = null is validator-legal and must load
# --------------------------------------------------------------------------------------


def test_validator_still_permits_a_null_manifest_model(tmp_path):
    """The contract under test: this artifact is *accepted*, so it must be loadable."""
    _saved(tmp_path, "nullmodel", manifest={"model": None})
    raw = json.loads((tmp_path / "nullmodel.tine").read_text())
    assert raw["manifest"]["model"] is None
    assert validate_run_record(raw) is raw


def test_run_load_of_a_null_manifest_model_falls_back_to_metadata(tmp_path):
    _saved(tmp_path, "nullmodel", manifest={"model": None})
    loaded = Run.load(tmp_path / "nullmodel.tine")
    # metadata.model_info is the documented fallback and it survives the null.
    assert loaded.model_info == "m/1"


@pytest.mark.parametrize("model", [None, {}, {"other": 1}])
def test_absent_empty_and_null_model_all_use_the_same_fallback(model, tmp_path):
    _saved(tmp_path, "fallback", manifest={"model": model})
    assert Run.load(tmp_path / "fallback.tine").model_info == "m/1"


def test_a_present_model_name_still_wins_over_metadata(tmp_path):
    _saved(tmp_path, "named", manifest={"model": {"name": "vendor/x"}})
    assert Run.load(tmp_path / "named.tine").model_info == "vendor/x"


@pytest.mark.parametrize("model", sorted(NON_MAPPING))
def test_the_validator_rejects_a_non_mapping_model_with_a_typed_error(model, tmp_path):
    _saved(tmp_path, "probe")
    data = json.loads((tmp_path / "probe.tine").read_text())
    data["manifest"]["model"] = NON_MAPPING[model]
    with pytest.raises(ValueError, match="manifest.model must be an object"):
        validate_run_record(data)


@pytest.mark.parametrize("model", sorted(NON_MAPPING))
def test_the_loader_does_not_lean_on_the_validator_for_the_model_shape(
    model, monkeypatch, tmp_path
):
    """With the validator neutered, run_from_dict must still not raise AttributeError.

    The null case proved the guard is needed; this proves the guard is the loader's own,
    so a future widening of validate_run_record cannot silently reintroduce the crash.
    """
    import opentine._graph_serde as serde

    _saved(tmp_path, "probe")
    data = json.loads((tmp_path / "probe.tine").read_text())
    data["manifest"]["model"] = NON_MAPPING[model]
    monkeypatch.setattr(serde.artifact_shapes, "validate_run_record", lambda payload: payload)
    assert serde.run_from_dict(data, Run).model_info == "m/1"


@pytest.mark.parametrize(
    "command",
    [("show",), ("cost",), ("verify",), ("replay", "--mode", "cache")],
)
def test_every_single_file_command_survives_a_null_manifest_model(command, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    _saved(tmp_path, "nullmodel", manifest={"model": None})
    _invoke(monkeypatch, command[0], str(tmp_path / "nullmodel.tine"), *command[1:])


def test_diff_and_fork_survive_a_null_manifest_model(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    _saved(tmp_path, "nullmodel", manifest={"model": None})
    _saved(tmp_path, "other")
    _invoke(monkeypatch, "diff", str(tmp_path / "nullmodel.tine"), str(tmp_path / "other.tine"))
    out = tmp_path / "forked.tine"
    _invoke(
        monkeypatch,
        "fork",
        str(tmp_path / "nullmodel.tine"),
        "--from-step",
        "0",
        "--save",
        str(out),
    )
    assert Run.load(out).metadata["forked_from"] == "nullmodel"


def _with_step_model_info(runs_dir, value):
    _saved(runs_dir, "stepmodel")
    path = runs_dir / "stepmodel.tine"
    data = json.loads(path.read_text())
    for step in data["graph"]["steps"].values():
        step["model_info"] = value
    path.write_text(json.dumps(data))
    return path


@pytest.mark.parametrize("value", [5, None, 1.5, ["a"], {"a": 1}])
def test_a_non_str_step_model_info_reads_and_lists_cleanly(value, monkeypatch, tmp_path):
    """_validate_step_record does not type step.model_info, unlike metadata.model_info.

    The loader keeps the value verbatim rather than silently rewriting artifact data, the
    run-level model_info still resolves to a string, and the index is unaffected.

    Two consequences of the untyped field live OUTSIDE this group's files and are still
    open (both verified pre-existing at HEAD a989053):
      * _graph_analysis.py:51-52 uses step.model_info as a dict key, so an *unhashable*
        one makes `tine cost` die with `TypeError: unhashable type`;
      * _graph_analysis.py:145-152 picks the tip step's model_info on a truthiness test
        and hands it to the child run, so `tine fork` / `tine replay` die with the
        assert_loadable ValueError "artifact metadata.model_info must be a string",
        uncontained by _cli_flow.
    """
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    path = _with_step_model_info(runs_dir, value)

    loaded = Run.load(path)
    assert loaded.steps[0].model_info == value  # preserved, not laundered
    assert loaded.model_info == "m/1"  # the run-level value stays a string
    assert RunIndex.open(runs_dir).sync().entries["stepmodel.tine"].unreadable is False
    _invoke(monkeypatch, "ls")
    _invoke(monkeypatch, "search", "s0")
    _invoke(monkeypatch, "show", str(path))


@pytest.mark.parametrize("value", [5, None, 1.5])
def test_cost_reporting_copes_with_a_hashable_non_str_step_model_info(value, monkeypatch, tmp_path):
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    path = _with_step_model_info(runs_dir, value)
    assert Run.load(path).cost_breakdown().total_cost == 0.0
    _invoke(monkeypatch, "cost", str(path))


def test_ls_and_search_survive_a_null_manifest_model(monkeypatch, tmp_path):
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    _saved(runs_dir, "nullmodel", manifest={"model": None})
    entries = RunIndex.open(runs_dir).sync().entries
    assert entries["nullmodel.tine"].unreadable is False
    assert entries["nullmodel.tine"].model == "m/1"
    _invoke(monkeypatch, "ls")
    _invoke(monkeypatch, "search", "s0")


# --------------------------------------------------------------------------------------
# (2) the accountant: five manifest containers grown without a shape check
# --------------------------------------------------------------------------------------


class _BillingModel:
    """Emits a billing record so _pin_billing runs, without touching the network."""

    name = "round11/model"

    def __init__(self, billing="default", warnings=None):
        self._billing = billing
        self._warnings = warnings

    async def complete(self, messages, **kwargs):
        response = {"text": "ok", "usage": {"input": 3, "output": 4}, "cost": 0.001}
        if self._billing == "default":
            response["billing"] = {
                "calculation": {"kind": "flat"},
                "catalog_hash": "h",
                "catalog_id": "cid",
                "catalog_provenance": ["p"],
                "effective_at": "2026-01-01",
                "rate_card_id": "rc1",
                "status": "complete",
            }
        elif self._billing is not None:
            response["billing"] = self._billing
        if self._warnings is not None:
            response["warnings"] = self._warnings
        return response


def _resume(tmp_path, name, *, manifest=None, metadata=None, model=None, strict=False, steps=0):
    manifest = {"resume": True, **(manifest or {})}
    _saved(tmp_path, name, manifest=manifest, metadata=metadata, steps=steps)
    loaded = Run.load(tmp_path / f"{name}.tine")
    agent = Agent(
        model=model or _BillingModel(),
        budget=Budget(strict_cost=True) if strict else Budget(),
    )
    return asyncio.run(agent.resume(loaded, prompt="next"))


@pytest.mark.parametrize("shape", sorted(NON_DICT))
@pytest.mark.parametrize("steps", [0, 1])
def test_resume_survives_a_non_dict_pricing_container(shape, steps, tmp_path):
    """A stepless resume does not fork, so nothing masked these before."""
    resumed = _resume(
        tmp_path, f"pd-{shape}-{steps}", manifest={"pricing": NON_DICT[shape]}, steps=steps
    )
    pricing = resumed.manifest["pricing"]
    assert isinstance(pricing, dict)
    assert len(pricing["invocations"]) == 1
    # A container we had to replace can never back a positive completeness claim.
    assert pricing["complete"] is False


@pytest.mark.parametrize("shape", sorted(NON_DICT))
def test_strict_cost_budget_survives_a_non_dict_pricing_container(shape, tmp_path):
    resumed = _resume(tmp_path, f"ps-{shape}", manifest={"pricing": NON_DICT[shape]}, strict=True)
    # Fail closed: an unreadable pricing record is not a proven-complete one.
    assert resumed.status is RunStatus.failed
    assert resumed.metadata["budget_state"]["dimension"] == "cost_completeness"


@pytest.mark.parametrize("shape", sorted(NON_LIST))
def test_resume_survives_a_non_list_catalogs_container(shape, tmp_path):
    resumed = _resume(tmp_path, f"cat-{shape}", manifest={"pricing": {"catalogs": NON_LIST[shape]}})
    catalogs = resumed.manifest["pricing"]["catalogs"]
    assert catalogs == [{"catalog_id": "cid", "catalog_hash": "h", "catalog_provenance": ["p"]}]
    assert resumed.manifest["pricing"]["complete"] is False


@pytest.mark.parametrize("shape", sorted(NON_DICT))
def test_resume_survives_a_non_dict_rate_cards_container(shape, tmp_path):
    resumed = _resume(
        tmp_path, f"rc-{shape}", manifest={"pricing": {"rate_cards": NON_DICT[shape]}}
    )
    cards = resumed.manifest["pricing"]["rate_cards"]
    assert list(cards.values()) == ["rc1"]
    assert resumed.manifest["pricing"]["complete"] is False


@pytest.mark.parametrize("shape", sorted(NON_LIST))
def test_resume_survives_a_non_list_invocations_container(shape, tmp_path):
    resumed = _resume(
        tmp_path, f"inv-{shape}", manifest={"pricing": {"invocations": NON_LIST[shape]}}
    )
    invocations = resumed.manifest["pricing"]["invocations"]
    assert [item["rate_card_id"] for item in invocations] == ["rc1"]
    assert resumed.manifest["pricing"]["complete"] is False


def test_a_healthy_pricing_record_still_records_a_complete_claim(tmp_path):
    resumed = _resume(tmp_path, "healthy", manifest={"pricing": {"complete": True}})
    pricing = resumed.manifest["pricing"]
    assert pricing["complete"] is True
    assert pricing["catalog_id"] == "cid"
    assert len(pricing["catalogs"]) == 1
    assert len(pricing["invocations"]) == 1


@pytest.mark.parametrize("prior", ["false", "true", 0, 1, [], {}, None])
def test_a_non_bool_complete_cannot_launder_a_strict_cost_refusal(prior, tmp_path):
    """``bool("false" and complete)`` used to publish complete: True from garbage."""
    resumed = _resume(
        tmp_path, f"lw-{prior!r}", manifest={"pricing": {"complete": prior}}, strict=True
    )
    assert resumed.status is RunStatus.failed
    assert resumed.metadata["budget_state"]["dimension"] == "cost_completeness"
    # The refusal fires before any step runs, so the malformed value is left verbatim
    # for the operator rather than silently rewritten.
    assert resumed.manifest["pricing"]["complete"] == prior


def test_a_non_bool_complete_is_not_inherited_as_true_by_pinning(tmp_path):
    resumed = _resume(tmp_path, "lp", manifest={"pricing": {"complete": "false"}})
    assert resumed.manifest["pricing"]["complete"] is False


@pytest.mark.parametrize("shape", sorted(NON_LIST))
def test_resume_survives_a_non_list_metadata_warnings_container(shape, tmp_path):
    resumed = _resume(
        tmp_path,
        f"mw-{shape}",
        metadata={"warnings": NON_LIST[shape]},
        model=_BillingModel(warnings=["provider said something"]),
    )
    assert resumed.metadata["warnings"] == ["provider said something"]


@pytest.mark.parametrize("warnings", [5, "abc", {"a": 1}, 1.5])
def test_resume_survives_a_non_list_response_warnings(warnings, tmp_path):
    resumed = _resume(tmp_path, "rw", model=_BillingModel(warnings=warnings))
    assert resumed.metadata["warnings"] == []


@pytest.mark.parametrize("billing", [5, "abc", [1], 1.5, True])
def test_pin_billing_refuses_a_non_dict_billing_record_without_raising(billing, tmp_path):
    """_pin_billing's signature promises a dict; a provider promises nothing."""
    from opentine.runtime import Agent as _Agent

    run = Run(id="nb", model_info="m/1")
    run.add_step(StepKind.model, {"text": "s"}, {"result": "r"}, model_info="m/1")
    _Agent._pin_billing(run, run.steps[0].id, billing)
    assert "pricing" not in run.manifest


# --------------------------------------------------------------------------------------
# (3) the index: containment must cover extraction, not only the read
# --------------------------------------------------------------------------------------

# Two poisons, one producer. Each per-step subtotal is finite inside billing_context, so
# _step_cost_decimal's own guard accepts it; only the aggregate misbehaves.
#   "raises": three of them overflow the Decimal context -- extraction raises, and
#             decimal.Overflow is an ArithmeticError, so _cli_listing's except ValueError
#             never saw it and `tine ls` printed a raw traceback.
#   "inf":    the Decimal sum is finite but float() of it is inf, so extraction *succeeds*
#             and the damage lands in _save's allow_nan=False -- outside _build_entry.
POISONS = {"raises": "9.9E+999999", "inf": "1E+400"}


def _poisoned_but_loadable(runs_dir, name: str, subtotal: str = POISONS["raises"]) -> None:
    run = Run(id=name, model_info="m/1")
    for index in range(3):
        run.add_step(StepKind.model, {"text": f"s{index}"}, {"result": "r"}, model_info="m/1")
    run.status = RunStatus.completed
    path = runs_dir / f"{name}.tine"
    run.save(path)
    data = json.loads(path.read_text())
    for step in data["graph"]["steps"].values():
        step["billing"] = {"known_subtotal_usd": subtotal}
    path.write_text(json.dumps(data))


def test_the_raising_poison_really_does_load_but_fail_extraction(tmp_path):
    """Without this, the tests below could pass for the wrong reason."""
    import decimal

    _poisoned_but_loadable(tmp_path, "overflow")
    loaded = Run.load(tmp_path / "overflow.tine")  # the read itself succeeds
    assert len(loaded.steps) == 3
    with pytest.raises(decimal.DecimalException):
        loaded.total_cost  # extraction is what fails, and it is not a ValueError


def test_the_inf_poison_extracts_a_value_the_index_reader_would_reject(tmp_path):
    """The other half of the class: the writer produced what its own reader refuses."""
    from opentine._index_types import IndexEntry as _Entry
    from opentine._index_types import entry_from_run

    _poisoned_but_loadable(tmp_path, "infcost", POISONS["inf"])
    loaded = Run.load(tmp_path / "infcost.tine")
    assert loaded.total_cost == float("inf")  # extraction succeeds
    built = entry_from_run(loaded, "infcost.tine", 1.0)
    with pytest.raises(ValueError, match="invalid run-index entry"):
        _Entry.from_dict(built.to_dict())
    with pytest.raises(ValueError, match="not JSON compliant"):
        json.dumps(built.to_dict(), allow_nan=False)


@pytest.mark.parametrize("poison", sorted(POISONS))
def test_one_unindexable_run_does_not_blind_the_whole_index(poison, tmp_path):
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    _poisoned_but_loadable(runs_dir, "bad", POISONS[poison])
    _saved(runs_dir, "healthy")

    entries = RunIndex.open(runs_dir).sync().entries
    assert sorted(entries) == ["bad.tine", "healthy.tine"]
    assert entries["bad.tine"].unreadable is True
    assert entries["bad.tine"].run_id == ""
    assert entries["bad.tine"].cost == 0.0
    # The healthy run beside it is fully indexed, which is the whole point.
    assert entries["healthy.tine"].unreadable is False
    assert entries["healthy.tine"].run_id == "healthy"


@pytest.mark.parametrize("poison", sorted(POISONS))
def test_ls_and_search_still_work_beside_an_unindexable_run(poison, monkeypatch, tmp_path):
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    _poisoned_but_loadable(runs_dir, "bad", POISONS[poison])
    _saved(runs_dir, "healthy")
    _invoke(monkeypatch, "ls")
    _invoke(monkeypatch, "search", "s0")
    assert [entry.file for entry in RunIndex.open(runs_dir).search("s0")] == ["healthy.tine"]


@pytest.mark.parametrize("poison", sorted(POISONS))
def test_update_from_file_contains_extraction_failures_too(poison, tmp_path):
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    _poisoned_but_loadable(runs_dir, "bad", POISONS[poison])
    index = RunIndex.open(runs_dir)
    index.update_from_file(runs_dir / "bad.tine")
    assert index.entries["bad.tine"].unreadable is True


@pytest.mark.parametrize("poison", sorted(POISONS))
def test_an_unreadable_entry_survives_the_index_round_trip(poison, tmp_path):
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    _poisoned_but_loadable(runs_dir, "bad", POISONS[poison])
    _saved(runs_dir, "healthy")
    RunIndex.open(runs_dir).sync()
    # Reopening reads the sidecar rather than rebuilding, so every written entry must be
    # one the reader accepts -- otherwise the index is permanently stale and rebuilds.
    reopened = RunIndex.open(runs_dir)
    assert reopened._stale is False
    assert reopened.entries["bad.tine"].unreadable is True
    assert reopened.sync().entries["bad.tine"].unreadable is True


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "POSIX-only by construction: this asserts a run id whose backslash is a legal "
        "filename character, which save() writes as one <run-id>.tine file and the index "
        "must not reject. On Windows a backslash is a path separator, so `team\\alpha` is "
        "not a single legal filename at all -- save() cannot write it as one file, so the "
        "premise (a backslash run id opentine wrote itself as one file) is unreachable "
        "and has no Windows equivalent. The traversal rule under test (from_dict rejecting "
        "'\\\\') and Path('team\\alpha.tine').name both behave differently there too."
    ),
)
def test_a_backslash_in_a_run_id_does_not_cost_the_run_its_index_entry(tmp_path):
    """The reverse failure: a guard that refuses what the previous build accepted.

    ``IndexEntry.from_dict`` applies a path-traversal rule to ``file`` because it also
    reads the *sidecar*, where the name is attacker-supplied. Inside ``_build_entry`` the
    name is this directory's own, and ``save()`` writes ``<run-id>.tine`` from a run id
    that may legally contain a backslash -- so holding the extracted entry to that rule
    as well made ``search`` lose a run opentine had just written itself.
    """
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    run = Run(id="team\\alpha", model_info="m/1")
    run.add_step(StepKind.model, {"text": "s0"}, {"result": "r"}, model_info="m/1")
    run.status = RunStatus.completed
    run.save(runs_dir / f"{run.id}.tine")

    entry = RunIndex.open(runs_dir).sync().entries["team\\alpha.tine"]
    assert entry.unreadable is False
    assert entry.run_id == "team\\alpha"
    assert [found.file for found in RunIndex.open(runs_dir).search("s0")] == ["team\\alpha.tine"]


def test_every_written_entry_is_one_the_index_reader_accepts(tmp_path):
    """The recurring release bug shape: a writer emitting what its own reader rejects."""
    from opentine._index_types import IndexEntry as _Entry

    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    for label, poison in POISONS.items():
        _poisoned_but_loadable(runs_dir, f"bad-{label}", poison)
    _saved(runs_dir, "healthy")
    index = RunIndex.open(runs_dir).sync()
    for name, entry in index.entries.items():
        assert _Entry.from_dict(entry.to_dict()) == entry, name
    json.dumps({n: e.to_dict() for n, e in index.entries.items()}, allow_nan=False)
