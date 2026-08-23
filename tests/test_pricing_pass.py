"""WS3: cost is a post-hoc function of the record.

Phase 1 made every step record an opaque ``provider``, so a run that was
*imported* rather than executed now carries ``(provider, model, usage)``. What
it did not carry was a price: ``bill()``'s only caller lived inside adapter
capture, so an imported run summed to an honest-looking ``$0.00`` exactly where
the live path would have said ``unknown``.

These tests pin the three pieces that close that gap:

* :mod:`opentine._pricing_pass` -- one pure pass that re-prices any recorded run
  from the catalog, carrying ``bill()``'s status through verbatim (an uncarded
  step is *unknown*, never free);
* ``tine price`` -- the read-only report, distinct from ``tine cost``, which
  sums what capture recorded;
* ``tine import --price`` -- the same pass applied to freshly parsed events
  *before* anything is written, so nothing content-addressed is ever rewritten.

Everything is driven in process through ``opentine.cli.main(argv)``; nothing
shells a binary.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Repo, Run, StepKind, cli
from opentine._cli_common import _cost_str
from opentine._pricing_pass import price_events, price_run, price_steps
from opentine.billing import Usage, load_catalogs
from opentine.models._metered import metered_response
from opentine.trace import to_otel_genai_document

#: A carded (provider, model) whose rates changed on a known date, so ``--at``
#: can be shown to select a *different* price rather than merely being accepted.
#:   openai:gpt-5.6-terra:2026-07-09  input 2.50 / output 15 per million
#:   openai:gpt-5.6-terra:2026-07-30  input 2.00 / output 12 per million
CARDED = ("openai", "gpt-5.6-terra")
OLD_DATE, NEW_DATE = "2026-07-15", "2026-08-01"
#: Below the card's 272k context threshold, so the base rates apply unmodified.
USAGE = {"input": 1_000, "output": 500}
OLD_COST = 1_000 * 2.50 / 1_000_000 + 500 * 15 / 1_000_000  # $0.010
NEW_COST = 1_000 * 2.00 / 1_000_000 + 500 * 12 / 1_000_000  # $0.008
UNCARDED = ("acme-cloud", "acme-supermodel-9")


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _run(provider: str, model: str, run_id: str = "b" * 64) -> Run:
    """A run with one priceable model step and one step that is not billable."""
    run = Run(id=run_id, model_info=model)
    run.add_step(
        StepKind.model,
        {"text": "ask"},
        {"text": "answer"},
        usage=dict(USAGE),
        provider=provider,
        model_info=model,
    )
    run.add_step(StepKind.tool, {"name": "grep", "arguments": {"pattern": "x"}}, {"text": "hit"})
    return run


def _otel_source(path: Path, provider: str, model: str) -> Run:
    """Write an OTLP/JSON document for a run, and strip the cost the exporter wrote.

    An imported document is the interesting case precisely because it arrives
    with usage and no price; the fixture makes that explicit instead of relying
    on the source run happening to be uncosted.
    """
    source = _run(provider, model)
    document = to_otel_genai_document(source)
    path.write_text(json.dumps(document), encoding="utf-8")
    return source


def _invoke(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _imported(workspace: Path, capsys, *extra: str, name: str = "imported.tine") -> Run:
    document = workspace / "spans.json"
    _otel_source(document, *CARDED)
    output = workspace / name
    code, _ = _invoke(
        capsys, "import", str(document), "--format", "otel-json", "--save", str(output), *extra
    )
    assert code == 0
    return Run.load(output)


# --------------------------------------------------------------------------- #
# the pass
# --------------------------------------------------------------------------- #


def test_price_run_prices_an_imported_run_from_its_recorded_provider_and_model(workspace, capsys):
    imported = _imported(workspace, capsys)
    assert [step.cost for step in imported.steps] == [0.0, 0.0]  # nothing recorded a price

    pricing = price_run(imported, effective_at=NEW_DATE)

    assert pricing.total_cost == pytest.approx(NEW_COST)
    assert pricing.by_model == {CARDED[1]: pytest.approx(NEW_COST)}
    assert pricing.by_provider == {CARDED[0]: pytest.approx(NEW_COST)}
    assert pricing.status_counts == {"complete": 1}  # the tool step is not a billable call
    assert pricing.catalog_id == load_catalogs().id
    step = pricing.steps[0]
    assert step.status == "complete"
    assert step.amount_usd == pytest.approx(NEW_COST)
    assert step.rate_card_id == "openai:gpt-5.6-terra:2026-07-30"


def test_an_uncarded_step_prices_as_unknown_and_never_as_zero(workspace, capsys):
    pricing = price_run(_run(*UNCARDED), effective_at=NEW_DATE)

    step = pricing.steps[0]
    assert step.status == "unknown"
    assert step.amount_usd is None
    assert pricing.status_counts == {"unknown": 1}
    assert pricing.unknown_steps == 1 and pricing.priced_steps == 0
    assert pricing.unknown_models == (UNCARDED[1],)
    # The whole point: an unpriced model is *named*, not listed at $0.00, so no
    # reader can mistake "we have no rate card" for "this call was free".
    assert pricing.by_model == {} and pricing.by_provider == {}
    assert "unknown" in step.billing["warnings"][0]


def test_a_carded_step_with_no_recorded_usage_is_unknown_not_zero(workspace):
    # A model call the run recorded with NO token counts at all (a streamed or
    # errored span often carries none) must price as unknown, not a $0 "complete"
    # bill — the false-free this pass exists to kill. An EXPLICIT all-zeros usage
    # is a real report of zero tokens and still bills to complete/$0.
    no_usage = Run(id="c" * 64, model_info=CARDED[1])
    no_usage.add_step(
        StepKind.model,
        {"text": "ask"},
        {"text": "answer"},
        usage={},
        provider=CARDED[0],
        model_info=CARDED[1],
    )
    step = price_run(no_usage, effective_at=NEW_DATE).steps[0]
    assert step.status == "unknown" and step.amount_usd is None

    explicit_zero = Run(id="d" * 64, model_info=CARDED[1])
    explicit_zero.add_step(
        StepKind.model,
        {"text": "ask"},
        {"text": "answer"},
        usage={"input": 0, "output": 0},
        provider=CARDED[0],
        model_info=CARDED[1],
    )
    zstep = price_run(explicit_zero, effective_at=NEW_DATE).steps[0]
    assert zstep.status == "complete" and zstep.amount_usd == pytest.approx(0.0)


def test_import_price_records_a_no_usage_span_as_unknown_not_zero(workspace, capsys):
    # The reachable-from-real-data case: a carded model whose imported span
    # carried no usage must land as unknown, not a durable $0 "complete" record.
    source = Run(id="e" * 64, model_info=CARDED[1])
    source.add_step(
        StepKind.model,
        {"text": "ask"},
        {"text": "answer"},
        usage={},
        provider=CARDED[0],
        model_info=CARDED[1],
    )
    document = workspace / "no_usage_spans.json"
    document.write_text(json.dumps(to_otel_genai_document(source)), encoding="utf-8")
    output = workspace / "priced.tine"
    code, _ = _invoke(
        capsys, "import", str(document), "--format", "otel-json", "--save", str(output), "--price"
    )
    assert code == 0
    model_step = Run.load(output).steps[0]
    assert model_step.billing.get("status") == "unknown"
    assert model_step.billing.get("status") != "complete"


def test_the_date_window_selects_the_price_that_was_in_force(workspace, capsys):
    run = _run(*CARDED)

    assert price_run(run, effective_at=OLD_DATE).total_cost == pytest.approx(OLD_COST)
    assert price_run(run, effective_at=NEW_DATE).total_cost == pytest.approx(NEW_COST)


def test_the_pass_and_adapter_capture_bottom_out_in_the_same_bill(workspace, capsys):
    """One pricing arithmetic: the post-hoc pass must not grow a second one."""
    live = metered_response(*CARDED, Usage.from_dict(USAGE), effective_at=NEW_DATE)
    posthoc = price_steps(_run(*CARDED).steps, effective_at=NEW_DATE)

    assert posthoc.total_cost == pytest.approx(live["cost"])
    assert posthoc.steps[0].status == live["billing"]["status"]
    assert posthoc.steps[0].billing["rate_card_id"] == live["billing"]["rate_card_id"]


def test_price_run_is_read_only(workspace, capsys):
    """A report may not touch the artifact it reports on."""
    imported = _imported(workspace, capsys)
    artifact = workspace / "imported.tine"
    before = artifact.read_bytes()
    ids = [step.id for step in imported.steps]

    price_run(imported, effective_at=NEW_DATE)

    assert artifact.read_bytes() == before
    assert [step.id for step in imported.steps] == ids
    assert [step.cost for step in imported.steps] == [0.0, 0.0]


# --------------------------------------------------------------------------- #
# tine price
# --------------------------------------------------------------------------- #


def test_tine_price_reports_a_post_hoc_total_and_names_its_catalog(workspace, capsys):
    _imported(workspace, capsys)

    code, printed = _invoke(capsys, "price", str(workspace / "imported.tine"), "--at", NEW_DATE)

    assert code == 0
    assert "# Price" in printed
    assert _cost_str(NEW_COST) in printed
    assert "priced=1 unknown=0" in printed
    assert load_catalogs().id in printed.replace("\n", "")


def test_tine_price_at_a_past_date_prices_under_the_older_card(workspace, capsys):
    _imported(workspace, capsys)
    artifact = str(workspace / "imported.tine")

    _, old = _invoke(capsys, "price", artifact, "--at", OLD_DATE)
    _, new = _invoke(capsys, "price", artifact, "--at", NEW_DATE)

    assert _cost_str(OLD_COST) in old and _cost_str(NEW_COST) not in old
    assert _cost_str(NEW_COST) in new and _cost_str(OLD_COST) not in new


def test_tine_price_json_round_trips_and_carries_the_status_breakdown(workspace, capsys):
    _imported(workspace, capsys)

    code, printed = _invoke(
        capsys, "price", str(workspace / "imported.tine"), "--at", NEW_DATE, "--json"
    )
    payload = json.loads(printed)

    assert code == 0
    assert payload["command"] == "price"
    assert payload["total_cost"] == pytest.approx(NEW_COST)
    assert payload["effective_at"] == NEW_DATE
    assert payload["status_counts"] == {"complete": 1}
    assert payload["unknown_models"] == []
    assert payload["by_provider"] == {CARDED[0]: pytest.approx(NEW_COST)}
    assert payload["steps"][0]["rate_card_id"] == "openai:gpt-5.6-terra:2026-07-30"


def test_tine_price_reports_an_uncarded_run_as_unknown_not_free(workspace, capsys):
    _run(*UNCARDED).save(workspace / "uncarded.tine")

    code, printed = _invoke(capsys, "price", str(workspace / "uncarded.tine"), "--json")
    payload = json.loads(printed)

    assert code == 0
    assert payload["unknown_steps"] == 1 and payload["priced_steps"] == 0
    assert payload["steps"][0]["amount_usd"] is None
    assert payload["unknown_models"] == [UNCARDED[1]]


def test_tine_price_is_not_tine_cost(workspace, capsys):
    """The distinction the verb exists for, on one artifact."""
    _imported(workspace, capsys)
    artifact = str(workspace / "imported.tine")

    _, cost = _invoke(capsys, "cost", artifact, "--json")
    _, price = _invoke(capsys, "price", artifact, "--at", NEW_DATE, "--json")

    # `cost` sums what capture recorded, and an imported run recorded nothing.
    assert json.loads(cost)["total_cost"] == 0.0
    # `price` recomputes from (provider, model, usage), so the real cost shows.
    assert json.loads(price)["total_cost"] == pytest.approx(NEW_COST)


def test_tine_price_refuses_an_unreadable_date(workspace, capsys):
    _imported(workspace, capsys)

    code, printed = _invoke(capsys, "price", str(workspace / "imported.tine"), "--at", "not-a-date")

    assert code == 1
    assert "Cannot price" in printed


# --------------------------------------------------------------------------- #
# tine import --price
# --------------------------------------------------------------------------- #


def test_import_price_lands_the_catalog_cost_on_the_saved_run(workspace, capsys):
    priced = _imported(workspace, capsys, "--price", name="priced.tine")

    model_step = priced.steps[0]
    assert model_step.kind is StepKind.model
    assert model_step.cost == pytest.approx(price_run(priced).total_cost)
    assert model_step.billing["status"] == "complete"
    assert model_step.billing["rate_card_id"].startswith("openai:gpt-5.6-terra:")
    # A tool step is not a billable call, so it stays exactly as imported.
    assert priced.steps[1].billing == {} and priced.steps[1].cost == 0.0


def test_import_without_price_is_unchanged(workspace, capsys):
    plain = _imported(workspace, capsys, name="plain.tine")

    assert [step.cost for step in plain.steps] == [0.0, 0.0]
    assert [step.billing for step in plain.steps] == [{}, {}]


def test_import_price_records_an_uncarded_call_as_unknown_not_zero(workspace, capsys):
    document = workspace / "uncarded.json"
    _otel_source(document, *UNCARDED)
    output = workspace / "uncarded.tine"

    code, _ = _invoke(
        capsys,
        "import",
        str(document),
        "--format",
        "otel-json",
        "--price",
        "--save",
        str(output),
    )

    assert code == 0
    step = Run.load(output).steps[0]
    assert step.billing["status"] == "unknown"
    assert step.billing["amount_usd"] is None
    assert step.cost == 0.0  # nothing was invented; the status says why


def test_import_price_rewrites_no_stored_object(workspace, capsys):
    """--price prices *fresh* events; it must not touch anything already stored."""
    document = workspace / "spans.json"
    _otel_source(document, *CARDED)
    repo = workspace / "repo"
    _invoke(capsys, "init", str(repo))

    def _import(ref: str, *extra: str) -> Run:
        code, _ = _invoke(
            capsys,
            "import",
            str(document),
            "--format",
            "otel-json",
            "--repo",
            str(repo),
            "--ref",
            ref,
            *extra,
        )
        assert code == 0
        return Repo.open(repo).load_run(Repo.open(repo).read_ref(ref))

    first = _import("heads/first")
    before = [(step.id, step.cost, dict(step.billing)) for step in first.steps]

    priced = _import("heads/priced", "--price")

    # Nothing already in the store moved: the earlier import's events still
    # resolve to the same content-addressed ids, with the same recorded cost.
    after = [
        (step.id, step.cost, dict(step.billing))
        for step in Repo.open(repo).load_run(Repo.open(repo).read_ref("heads/first")).steps
    ]
    assert after == before
    # The priced run is a *different* run: its model step carries more content,
    # so it (and everything chained below it) earns a new id rather than
    # rewriting an id that already exists -- which is what content addressing
    # requires and what a price written after the fact would have violated.
    assert priced.steps[0].id != first.steps[0].id
    assert first.steps[0].cost == 0.0 and priced.steps[0].cost > 0.0
    assert first.steps[0].usage == priced.steps[0].usage  # same record, priced


def test_price_events_keeps_a_cost_the_source_reported(workspace, capsys):
    """A pass that cannot price must not erase what the trace already carried."""
    from opentine.trace.schema import TraceEvent

    reported = TraceEvent(
        kind="model",
        timestamp=1.0,
        trace_id="t",
        span_id="s",
        model=UNCARDED[1],
        provider=UNCARDED[0],
        cost=0.25,
        usage=dict(USAGE),
    )

    (event,) = price_events([reported])

    assert event.cost == 0.25
    assert event.billing["status"] == "unknown"
