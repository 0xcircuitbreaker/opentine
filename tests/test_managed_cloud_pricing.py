"""Managed-cloud foundation: provider identity, unpriced usage, and the price gate.

The failure this file exists to prevent, stated once:

    Bedrock, Vertex, and Azure OpenAI resell the same model weights under
    per-region, per-account contract pricing. A signed catalog that answered
    "$3/MTok" for ``bedrock``/``claude-*`` would be *wrong for almost every
    account*, and wrong while carrying opentine's signature — a false trust
    signal on a number an operator would reconcile against a real invoice. The
    only honest answer the project can sign is "not priced here".

So the bundled catalog must never price a managed provider, and no managed model
spelling may alias a direct-API card. Both are asserted below over the whole
catalog and its whole effective-date range, not over a hand-written sample: a
gate that only knows today's card ids stops working the day a card is added.
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from opentine import Run, StepKind
from opentine._cli_json import emit_cost
from opentine._runtime_accounting import AccountingMixin, pricing_summary
from opentine.billing import PricingCatalog, Usage, bill
from opentine.billing.catalog import BUNDLED_CATALOG
from opentine.models._managed_billing import (
    MANAGED_UNPRICED,
    USER_SUPPLIED,
    managed_unpriced,
)
from opentine.models._metered import metered_response
from opentine.models.anthropic import Anthropic
from opentine.models.google import Google

MANAGED_PROVIDERS = ("bedrock", "vertex", "azure-openai")

# Spellings a managed re-host uses for models the direct APIs also serve. Each is
# a chance for a card to be matched by accident, which is why they are named.
MANAGED_MODEL_IDS = (
    "us.anthropic.claude-sonnet-5-v1:0",
    "eu.anthropic.claude-sonnet-5-v1:0",
    "apac.anthropic.claude-opus-5-v1:0",
    "anthropic.claude-sonnet-5-v1:0",
    "claude-sonnet-5",
    "claude-sonnet-5@20260101",
    "gemini-3.5-flash",
    "publishers/google/models/gemini-3.5-flash",
    "gpt-5.6",
    "gpt-5.6-sol",
    "my-azure-deployment-name",
)


@pytest.fixture(scope="module")
def bundled() -> PricingCatalog:
    """Only the signed bundled snapshot.

    Deliberately not ``load_catalogs()``: an operator overlay is *allowed* to
    price their own negotiated regional rates, and picking one up here would
    make this gate pass or fail on the developer's machine state.
    """
    return PricingCatalog.load(BUNDLED_CATALOG)


def _catalog_dates(catalog: PricingCatalog) -> set[date]:
    dates = {date(2020, 1, 1), date.today(), date(2099, 12, 31)}
    for card in catalog.cards:
        dates.add(card.effective_from)
        if card.effective_until is not None:
            dates.add(card.effective_until)
    return dates


def _catalog_names(catalog: PricingCatalog) -> set[str]:
    return {name for card in catalog.cards for name in (card.model, *card.aliases)}


# --- 1. the permanent mispricing gate -------------------------------------


def test_bundled_catalog_declares_no_managed_provider(bundled):
    offenders = [card.id for card in bundled.cards if card.provider.casefold() in MANAGED_PROVIDERS]
    assert not offenders, (
        f"the signed catalog prices a managed provider: {offenders}. Regional/contract "
        "pricing cannot be stated truthfully for every account, and signing a guess "
        "puts opentine's trust signal on a number that will not match the invoice. "
        "Remove the card; managed usage is recorded with cost 'unknown' instead."
    )


def test_bundled_catalog_never_prices_a_managed_provider_for_any_model(bundled):
    """No (managed provider, model id) resolves — for every id, at every date."""
    model_ids = sorted(_catalog_names(bundled) | set(MANAGED_MODEL_IDS))
    when = sorted(_catalog_dates(bundled))
    priced = [
        (provider, model, moment.isoformat(), card.id)
        for provider in MANAGED_PROVIDERS
        for model in model_ids
        for moment in when
        if (card := bundled.lookup(provider, model, effective_at=moment)) is not None
    ]
    assert not priced, (
        f"the signed catalog priced managed calls: {priced[:5]}. A managed re-host's "
        "rates are per-region and per-contract; pricing one from the bundled snapshot "
        "reports a cost the operator never paid."
    )


def test_no_managed_model_spelling_aliases_a_direct_api_card(bundled):
    """HARD RULE: a managed model id may never alias a direct-API rate card.

    Aliasing is how mispricing would most plausibly arrive — it looks like a
    convenience ("us.anthropic.claude-sonnet-5-v1:0 is just claude-sonnet-5")
    and it silently reprices every managed call at direct-API rates.
    """
    managed_spellings = {
        name
        for name in _catalog_names(bundled)
        if name.count(".") and name.split(".", 1)[0].casefold() in {"us", "eu", "apac", "anthropic"}
    }
    assert not managed_spellings, (
        f"direct-API cards claim managed model spellings: {sorted(managed_spellings)}"
    )
    for model in MANAGED_MODEL_IDS:
        if model in _catalog_names(bundled):
            continue  # a legitimate direct-API name; the provider still gates it
        for card in bundled.cards:
            assert not card.matches(card.provider, model), f"{card.id} matches managed id {model}"


@pytest.mark.parametrize("provider", MANAGED_PROVIDERS)
def test_managed_billing_takes_the_no_card_unknown_path(provider, bundled):
    result = bill(provider, "claude-sonnet-5", Usage(input=1_000, output=1_000), catalog=bundled)
    assert result.status == "unknown"
    assert result.amount_usd is None
    assert result.rate_card_id is None
    assert float(result.known_subtotal_usd) == 0.0


# --- 2. provider identity --------------------------------------------------


def test_provider_id_is_a_class_attribute_not_a_constructor_argument():
    assert Anthropic._provider_id == "anthropic"
    assert Google._provider_id == "google"
    with pytest.raises(TypeError):
        Anthropic(provider_id="bedrock")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        Google(provider_id="vertex")  # type: ignore[call-arg]


def test_direct_adapters_still_record_their_direct_provider():
    adapter = Anthropic(model="claude-sonnet-5", api_key="k")
    payload = adapter._meter(
        type("R", (), {"usage": type("U", (), {"input_tokens": 10, "output_tokens": 5})()})()
    )
    assert payload["billing"]["calculation"]["provider"] == "anthropic"
    assert payload["billing"]["status"] == "complete"


def test_subclassing_the_provider_id_reroutes_billing_identity():
    """The Phase 12 mechanism, exercised without a Phase 12 adapter."""

    class Bedrock(Anthropic):
        _provider_id = "bedrock"

    adapter = Bedrock(model="claude-sonnet-5", api_key="k")
    payload = adapter._meter(
        type("R", (), {"usage": type("U", (), {"input_tokens": 10, "output_tokens": 5})()})()
    )
    billing = payload["billing"]
    assert billing["calculation"]["provider"] == "bedrock"
    assert billing["status"] == "unknown"
    assert billing["rate_card_id"] is None
    assert payload["usage"]["input"] == 10  # usage is still recorded in full


# --- 3. the unpriced post-processor ---------------------------------------


def _managed_payload(provider: str = "bedrock", **kwargs) -> dict:
    return metered_response(provider, "claude-sonnet-5", Usage(input=1_000, output=500), **kwargs)


def test_managed_unpriced_stamps_basis_region_and_warning():
    payload = managed_unpriced(_managed_payload(), provider="bedrock", region="us-east-1")
    billing = payload["billing"]
    assert billing["status"] == "unknown"
    assert billing["amount_usd"] is None
    assert payload["cost"] == 0.0
    assert billing["calculation"]["pricing_basis"] == MANAGED_UNPRICED
    assert billing["calculation"]["managed_region"] == "us-east-1"
    assert (
        "bedrock regional rates are not in the signed catalog; "
        "usage is recorded and cost is unknown"
    ) in billing["warnings"]
    assert payload["usage"] == {"input": 1000, "output": 500}


def test_managed_unpriced_is_idempotent():
    payload = managed_unpriced(_managed_payload(), provider="vertex", region="europe-west4")
    warnings = list(payload["billing"]["warnings"])
    again = managed_unpriced(payload, provider="vertex", region="europe-west4")
    assert again["billing"]["warnings"] == warnings


def test_managed_unpriced_no_ops_when_user_rates_priced_the_call():
    payload = _managed_payload(rate_override={"input": "1", "output": "2"})
    assert payload["billing"]["status"] == "complete"
    priced_cost = payload["cost"]
    payload = managed_unpriced(payload, provider="bedrock", region="us-west-2")
    billing = payload["billing"]
    assert billing["status"] == "complete"
    assert payload["cost"] == priced_cost
    assert billing["calculation"]["pricing_basis"] == USER_SUPPLIED
    assert not any("not in the signed catalog" in warning for warning in billing["warnings"])


def test_managed_unpriced_no_ops_when_an_overlay_card_priced_the_call(bundled, tmp_path):
    """An operator overlay carrying their negotiated regional rates is authoritative."""
    overlay = {
        "schema": "opentine-pricing/1",
        "cards": [
            {
                "id": "acme:bedrock:claude-sonnet-5",
                "provider": "bedrock",
                "model": "claude-sonnet-5",
                "rates": {"input": "3", "output": "15"},
            }
        ],
    }
    path = tmp_path / "pricing.json"
    path.write_text(json.dumps(overlay))
    catalog = bundled.overlay(
        PricingCatalog.from_dict(overlay, verify=False, require_signature=False)
    )
    payload = managed_unpriced(
        _managed_payload(catalog=catalog), provider="bedrock", region="us-east-1"
    )
    billing = payload["billing"]
    assert billing["status"] == "complete"
    assert billing["rate_card_id"] == "acme:bedrock:claude-sonnet-5"
    assert billing["calculation"]["pricing_basis"] == USER_SUPPLIED


def test_managed_unpriced_refuses_an_unexpected_billing_status():
    payload = _managed_payload()
    payload["billing"]["status"] = "surprise"
    with pytest.raises(RuntimeError, match="unpriced no-card path"):
        managed_unpriced(payload, provider="bedrock", region="us-east-1")


# --- 4. cost visibility ----------------------------------------------------


def _recorded_run(*billings: dict) -> Run:
    run = Run(id="managed-cloud-run")
    pin = AccountingMixin._pin_billing
    for index, billing in enumerate(billings):
        step = run.add_step(StepKind.model, {"text": f"step {index}"})
        pin(run, step.id, billing)
    return run


def _billing(status: str, provider: str, **extra) -> dict:
    return {
        "status": status,
        "catalog_id": "sha256:test",
        "catalog_hash": "test",
        "rate_card_id": None if status == "unknown" else f"{provider}:card",
        "calculation": {"provider": provider, **extra},
    }


def test_pricing_summary_counts_unpriced_steps_and_their_providers():
    run = _recorded_run(
        _billing("complete", "anthropic"),
        _billing("unknown", "bedrock", pricing_basis=MANAGED_UNPRICED),
        _billing("unknown", "bedrock", pricing_basis=MANAGED_UNPRICED),
    )
    assert pricing_summary(run) == {
        "complete": False,
        "unpriced_steps": 2,
        "unpriced_providers": ["bedrock"],
    }


def test_pricing_summary_is_complete_when_every_step_is_priced():
    run = _recorded_run(_billing("complete", "anthropic"), _billing("unmetered", "ollama"))
    assert pricing_summary(run) == {
        "complete": True,
        "unpriced_steps": 0,
        "unpriced_providers": [],
    }


def test_pricing_summary_never_claims_completeness_over_unpriced_steps():
    run = _recorded_run(_billing("unknown", "bedrock"))
    run.manifest["pricing"]["complete"] = True  # an operator-edited manifest
    assert pricing_summary(run)["complete"] is False


@pytest.mark.parametrize("version", ["v0_3_0", "v0_4_0", "v0_5_0"])
def test_older_runs_degrade_to_a_complete_pricing_summary(version, capsys):
    run = Run.load(f"tests/fixtures/compat/{version}/artifact.tine")
    assert "pricing" not in run.manifest
    assert pricing_summary(run) == {
        "complete": True,
        "unpriced_steps": 0,
        "unpriced_providers": [],
    }
    assert emit_cost(run) is False
    payload = json.loads(capsys.readouterr().out)
    assert payload["pricing"] == {
        "complete": True,
        "unpriced_steps": 0,
        "unpriced_providers": [],
    }


def test_cost_json_reports_the_unpriced_subtotal(capsys):
    run = _recorded_run(_billing("complete", "anthropic"), _billing("unknown", "bedrock"))
    assert emit_cost(run) is False  # visibility only: exit status is unchanged
    payload = json.loads(capsys.readouterr().out)
    assert payload["pricing"] == {
        "complete": False,
        "unpriced_steps": 1,
        "unpriced_providers": ["bedrock"],
    }
    assert payload["over_budget"] is False


def test_cost_human_output_warns_that_the_total_is_a_subtotal(tmp_path, capsys, monkeypatch):
    from argparse import Namespace

    from opentine import _cli_execute

    run = _recorded_run(_billing("complete", "anthropic"), _billing("unknown", "bedrock"))
    path = tmp_path / f"{run.id}.tine"
    run.save(path)
    monkeypatch.setattr(_cli_execute, "_find_run", lambda _run_id: path)
    _cli_execute.cmd_cost(Namespace(run_id=run.id, json=False))
    out = capsys.readouterr().out
    assert "1 step(s) unpriced (bedrock); total is a known subtotal, not the bill" in out


def test_cost_human_output_is_quiet_when_everything_is_priced(tmp_path, capsys, monkeypatch):
    from argparse import Namespace

    from opentine import _cli_execute

    run = _recorded_run(_billing("complete", "anthropic"))
    path = tmp_path / f"{run.id}.tine"
    run.save(path)
    monkeypatch.setattr(_cli_execute, "_find_run", lambda _run_id: path)
    _cli_execute.cmd_cost(Namespace(run_id=run.id, json=False))
    assert "unpriced" not in capsys.readouterr().out
