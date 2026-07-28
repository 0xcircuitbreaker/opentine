"""Release regressions for arithmetic and exact compatibility totals."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from decimal import ROUND_DOWN, ROUND_UP, Decimal, Inexact, Rounded, localcontext

from opentine.billing import Usage, bill
from opentine.billing.types import as_date
from opentine.budget import Budget
from opentine.graph import Run, StepKind
from opentine.models._ollama_billing import ollama_meter
from opentine.models._ollama_rates import rate_override


def _gpt_bill():
    return bill(
        "openai",
        "gpt-5.6",
        Usage(input=123_456_789, output=987_654_321),
        effective_at="2026-07-20",
    ).to_dict()


def test_billing_is_independent_of_ambient_decimal_context_and_traps():
    expected = _gpt_bill()
    for precision, rounding in ((2, ROUND_DOWN), (2, ROUND_UP), (6, ROUND_UP)):
        with localcontext() as context:
            context.prec = precision
            context.rounding = rounding
            context.traps[Inexact] = True
            context.traps[Rounded] = True
            assert _gpt_bill() == expected


def test_usage_threshold_and_ollama_compute_are_context_invariant():
    usage = Usage(input=200_000, extra={"input_audio": Decimal("0.1")})
    data = {"prompt_eval_duration": 123_456_789_012_345, "eval_duration": 987_654_321_098_765}
    rates = rate_override(None, None, 1.25)
    expected_total = usage.input_total
    expected = ollama_meter("local", data, None, rates, True)

    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_UP
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        assert usage.input_total == expected_total == Decimal("200000.1")
        assert rate_override(None, None, 1.25) == rates
        assert ollama_meter("local", data, None, rates, True) == expected


def test_total_cost_and_budget_equality_use_exact_known_subtotals():
    run = Run()
    for index in range(3):
        run.add_step(
            StepKind.model,
            {"index": index},
            cost=0.1,
            billing={"status": "complete", "known_subtotal_usd": "0.1"},
        )
    assert run.total_cost == 0.3
    breakdown = run.cost_breakdown()
    assert breakdown.total_cost == 0.3
    assert breakdown.by_kind == {"model": 0.3}
    assert Budget(max_cost=0.3).check(cost=run.total_cost, usage=0, steps=3, duration=0) is None


def test_effective_timestamp_is_normalized_to_utc_date():
    instant = datetime(2026, 9, 1, 0, 30, tzinfo=UTC)
    assert as_date(instant.astimezone(timezone(-timedelta(hours=4)))) == instant.date()
