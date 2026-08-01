"""Managed-cloud adapters: recorded in full, priced never — all offline.

Every test here drives a fake SDK client. Nothing in this file touches the
network, and nothing requires ``boto3``, ``google-auth``, or the cloud SDK extras
to be installed: the adapters import their SDK inside ``_get_client``, which the
tests replace. That is deliberate and asserted at the bottom of the file — the
managed adapters are a *surface* over adapters that already exist, so a base
install must keep importing them.

The three properties this file pins:

1. **Usage-only.** Every managed call ends ``status='unknown'``,
   ``amount_usd=None``, ``cost=0.0``, with usage recorded in full — unless the
   operator supplied their own regional rates, which flips the basis to
   ``user_supplied_regional_rates`` and prices the call honestly.
2. **No account id ever lands in an artifact.** A Bedrock inference-profile ARN
   is truncated to its profile name before it is persisted, on the way out *and*
   on the way back.
3. **Vertex is never priced at Google's rates.** ``gemini-3.5-flash`` is the same
   string on both surfaces; only the provider distinguishes them.
"""

from __future__ import annotations

import importlib
import json
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from opentine import Run
from opentine.billing import PricingCatalog
from opentine.billing.catalog import BUNDLED_CATALOG
from opentine.models._managed_aws import arn_region, profile_name
from opentine.models._managed_billing import MANAGED_UNPRICED, USER_SUPPLIED
from opentine.models.google import Google
from opentine.models.managed import Bedrock, BedrockCompatible, Vertex, VertexAnthropic
from opentine.runtime import Agent
from tests.test_google_adapter import _install_fake_google_genai

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "123456789012"
PROFILE = "us.anthropic.claude-sonnet-5-v1:0"
PROFILE_ARN = f"arn:aws:bedrock:us-east-1:{ACCOUNT}:inference-profile/{PROFILE}"


# --- fakes -----------------------------------------------------------------


def _bedrock_usage() -> SimpleNamespace:
    """Bedrock reports the direct API's cache shape, ephemeral buckets included."""
    return SimpleNamespace(
        input_tokens=1_000,
        output_tokens=200,
        cache_read_input_tokens=500,
        cache_creation=SimpleNamespace(
            ephemeral_5m_input_tokens=100,
            ephemeral_1h_input_tokens=50,
        ),
    )


BEDROCK_USAGE = {
    "input": 1_000,
    "output": 200,
    "cache_read": 500,
    "cache_write_5m": 100,
    "cache_write_1h": 50,
    "total": 1_850,
}


def _messages_response(model: Any = "claude-sonnet-5-20260101", usage: Any = None) -> Any:
    response = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="hello")],
        stop_reason="end_turn",
        usage=_bedrock_usage() if usage is None else usage,
    )
    if model is not None:
        response.model = model
    return response


def _anthropic_client(response: Any, seen: dict[str, Any]) -> SimpleNamespace:
    class Messages:
        async def create(self, **kwargs: Any) -> Any:
            seen.update(kwargs)
            return response

    return SimpleNamespace(messages=Messages())


def _chat_response(model: str = "amazon.nova-pro-v1:0") -> Any:
    return SimpleNamespace(
        model=model,
        service_tier=None,
        choices=[
            SimpleNamespace(
                finish_reason="stop",
                message=SimpleNamespace(content="hello", tool_calls=None, refusal=None),
            )
        ],
        usage=SimpleNamespace(prompt_tokens=1_000, completion_tokens=200, total_tokens=1_200),
    )


def _chat_client(response: Any, seen: dict[str, Any]) -> SimpleNamespace:
    class Completions:
        async def create(self, **kwargs: Any) -> Any:
            seen.update(kwargs)
            return response

    return SimpleNamespace(chat=SimpleNamespace(completions=Completions()))


VERTEX_USAGE_METADATA = {
    "promptTokenCount": 1_000,
    "candidatesTokenCount": 200,
    "thoughtsTokenCount": 50,
    "cachedContentTokenCount": 300,
    "totalTokenCount": 1_550,
}
VERTEX_USAGE = {
    "input": 700,
    "output": 200,
    "cache_read": 300,
    "reasoning": 50,
    "total": 1_550,
}


def _gemini_response(model: str = "gemini-3.5-flash") -> Any:
    return SimpleNamespace(
        candidates=[
            SimpleNamespace(
                finish_reason="STOP",
                content=SimpleNamespace(parts=[SimpleNamespace(text="hello")]),
            )
        ],
        model_version=model,
        usage_metadata=VERTEX_USAGE_METADATA,
    )


def _genai_client(response: Any, seen: dict[str, Any]) -> SimpleNamespace:
    class Models:
        async def generate_content(self, *, model: str, contents: Any, config: Any) -> Any:
            seen.update(model=model, contents=contents, config=config)
            return response

    return SimpleNamespace(aio=SimpleNamespace(models=Models()))


def _assert_unpriced(result: dict[str, Any], provider: str, region: str | None) -> None:
    billing = result["billing"]
    assert billing["status"] == "unknown"
    assert billing["amount_usd"] is None
    assert billing["rate_card_id"] is None
    assert float(billing["known_subtotal_usd"]) == 0.0
    assert result["cost"] == 0.0
    calculation = billing["calculation"]
    assert calculation["provider"] == provider
    assert calculation["pricing_basis"] == MANAGED_UNPRICED
    if region is not None:
        assert calculation["managed_region"] == region
    assert any("not in the signed catalog" in warning for warning in billing["warnings"])


# --- 1. Bedrock: the Anthropic Messages surface ----------------------------


@pytest.mark.asyncio
async def test_bedrock_records_full_usage_and_claims_no_cost(monkeypatch):
    seen: dict[str, Any] = {}
    adapter = Bedrock(PROFILE, region="us-east-1")
    monkeypatch.setattr(
        adapter, "_get_client", lambda: _anthropic_client(_messages_response(), seen)
    )

    result = await adapter.complete([{"role": "user", "content": "hi"}], temperature=0.7)

    assert result["text"] == "hello"
    assert result["usage"] == BEDROCK_USAGE  # the cache_creation shape, unchanged
    _assert_unpriced(result, "bedrock", "us-east-1")
    assert seen["model"] == PROFILE
    assert "service_tier" not in seen and "inference_geo" not in seen


@pytest.mark.asyncio
async def test_bedrock_user_supplied_regional_rates_price_the_call(monkeypatch):
    adapter = Bedrock(PROFILE, region="eu-west-1", rates={"input": "3", "output": "15"})
    usage = SimpleNamespace(input_tokens=1_000_000, output_tokens=1_000_000)
    monkeypatch.setattr(
        adapter,
        "_get_client",
        lambda: _anthropic_client(_messages_response(model=None, usage=usage), {}),
    )

    result = await adapter.complete([{"role": "user", "content": "hi"}])

    billing = result["billing"]
    assert billing["status"] == "complete"
    assert result["cost"] == 18.0
    assert billing["calculation"]["pricing_basis"] == USER_SUPPLIED
    assert billing["calculation"]["managed_region"] == "eu-west-1"
    assert not any("not in the signed catalog" in warning for warning in billing["warnings"])


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"service_tier": "auto"}, "service_tier"),
        ({"service_tier": "standard_only"}, "service_tier"),
        ({"inference_geo": "us"}, "inference_geo"),
    ],
)
def test_bedrock_refuses_request_controls_its_surface_does_not_have(kwargs, message):
    with pytest.raises(ValueError, match=message):
        Bedrock(PROFILE, **kwargs)


def test_bedrock_provider_identity_is_not_a_constructor_argument():
    assert Bedrock._provider_id == "bedrock"
    with pytest.raises(TypeError):
        Bedrock(PROFILE, provider_id="anthropic")  # type: ignore[call-arg]


# --- 2. the ARN truncation (Q6) --------------------------------------------


def test_profile_name_truncates_only_what_it_should():
    assert profile_name(PROFILE_ARN) == PROFILE
    assert arn_region(PROFILE_ARN) == "us-east-1"
    assert (
        profile_name(f"arn:aws:bedrock:us-west-2:{ACCOUNT}:foundation-model/anthropic.claude-x")
        == "anthropic.claude-x"
    )
    # Not an ARN, or not a well-formed one: left exactly as given.
    assert profile_name(PROFILE) == PROFILE
    assert profile_name("arn:aws:bedrock:us-east-1") == "arn:aws:bedrock:us-east-1"
    assert profile_name(None) is None
    assert arn_region(PROFILE) is None


@pytest.mark.asyncio
async def test_bedrock_truncates_the_arn_before_it_is_persisted(monkeypatch):
    """The wire gets the full ARN; the artifact never sees the account id."""
    seen: dict[str, Any] = {}
    adapter = Bedrock(PROFILE_ARN)
    monkeypatch.setattr(
        adapter, "_get_client", lambda: _anthropic_client(_messages_response(), seen)
    )

    assert adapter.name == PROFILE
    assert adapter._region == "us-east-1"  # derived from the ARN, not the environment

    result = await adapter.complete([{"role": "user", "content": "hi"}])

    assert seen["model"] == PROFILE_ARN  # Bedrock still resolves the profile
    calculation = result["billing"]["calculation"]
    assert calculation["requested_model"] == PROFILE
    assert calculation["model_id_truncated"] == "inference_profile_arn"
    assert ACCOUNT not in json.dumps(result)


@pytest.mark.asyncio
async def test_bedrock_truncates_an_arn_the_response_echoes_back(monkeypatch):
    adapter = Bedrock(PROFILE_ARN)
    monkeypatch.setattr(
        adapter,
        "_get_client",
        lambda: _anthropic_client(_messages_response(model=PROFILE_ARN), {}),
    )

    result = await adapter.complete([{"role": "user", "content": "hi"}])

    assert result["model"] == PROFILE
    assert result["billing"]["calculation"]["reported_model"] == PROFILE
    assert ACCOUNT not in json.dumps(result)


@pytest.mark.asyncio
async def test_the_account_id_never_reaches_the_cost_breakdown(monkeypatch):
    """``tine cost`` groups by ``model_info``; that key must not carry the account."""
    adapter = Bedrock(PROFILE_ARN)
    monkeypatch.setattr(
        adapter,
        "_get_client",
        lambda: _anthropic_client(_messages_response(model=PROFILE_ARN), {}),
    )
    run = Run(id="bedrock-cost")
    agent = Agent(adapter)
    response, duration = await agent._invoke(run, [{"role": "user", "content": "hi"}], {})
    agent._record_model(run, response, duration)

    breakdown = run.cost_breakdown()
    assert list(breakdown.by_model) == [PROFILE]
    assert breakdown.total_cost == 0.0
    assert ACCOUNT not in json.dumps(run.to_dict())


# --- 3. BedrockCompatible: the non-Anthropic families ----------------------


@pytest.mark.asyncio
async def test_bedrock_compatible_is_unpriced_over_the_bedrock_runtime_endpoint(monkeypatch):
    seen: dict[str, Any] = {}
    adapter = BedrockCompatible("amazon.nova-pro-v1:0", region="us-west-2", api_key="token")
    monkeypatch.setattr(adapter, "_get_client", lambda: _chat_client(_chat_response(), seen))

    assert adapter._base_url == "https://bedrock-runtime.us-west-2.amazonaws.com/openai/v1"

    result = await adapter.complete([{"role": "user", "content": "hi"}])

    assert result["usage"] == {"input": 1_000, "output": 200, "total": 1_200}
    _assert_unpriced(result, "bedrock", "us-west-2")
    assert seen["model"] == "amazon.nova-pro-v1:0"


@pytest.mark.asyncio
async def test_bedrock_compatible_also_truncates_an_application_profile_arn(monkeypatch):
    arn = f"arn:aws:bedrock:us-east-1:{ACCOUNT}:application-inference-profile/amazon.nova-pro-v1:0"
    seen: dict[str, Any] = {}
    adapter = BedrockCompatible(arn)
    monkeypatch.setattr(
        adapter, "_get_client", lambda: _chat_client(_chat_response(model=arn), seen)
    )

    assert adapter.name == "amazon.nova-pro-v1:0"
    result = await adapter.complete([{"role": "user", "content": "hi"}])

    assert seen["model"] == arn
    assert result["model"] == "amazon.nova-pro-v1:0"
    assert ACCOUNT not in json.dumps(result)


# --- 4. Vertex: the mispricing regression ----------------------------------


@pytest.mark.asyncio
async def test_vertex_records_the_usage_metadata_block_unpriced(monkeypatch):
    _install_fake_google_genai(monkeypatch)
    seen: dict[str, Any] = {}
    adapter = Vertex("gemini-3.5-flash", project="acme-prod", location="europe-west4")
    monkeypatch.setattr(adapter, "_get_client", lambda: _genai_client(_gemini_response(), seen))

    result = await adapter.complete([{"role": "user", "content": "hi"}])

    assert result["text"] == "hello"
    assert result["usage"] == VERTEX_USAGE  # camelCase usageMetadata, read in full
    _assert_unpriced(result, "vertex", "europe-west4")
    assert seen["model"] == "gemini-3.5-flash"


def test_vertex_gemini_is_unknown_where_the_direct_api_is_priced():
    """THE regression: the same model string, two providers, two answers.

    Vertex reports a bare ``gemini-3.5-flash``. If provider identity were carried
    by anything a caller could set — or if cards matched on the model name alone
    — this call would be priced at Google's published rates and the operator
    would reconcile a number that is not on their Google Cloud invoice.
    """
    usage = VERTEX_USAGE_METADATA
    direct = Google("gemini-3.5-flash")._meter(usage, "gemini-3.5-flash")
    managed = Vertex("gemini-3.5-flash")._meter(usage, "gemini-3.5-flash")

    assert direct["billing"]["status"] == "complete"
    assert direct["billing"]["rate_card_id"] is not None
    assert direct["cost"] > 0

    assert managed["billing"]["calculation"]["provider"] == "vertex"
    assert managed["billing"]["status"] == "unknown"
    assert managed["billing"]["rate_card_id"] is None
    assert managed["cost"] == 0.0
    assert managed["usage"] == direct["usage"]  # identical usage, no cost claimed


def test_the_bundled_catalog_cannot_be_made_to_price_vertex():
    """Provider-first matching, asserted on the card objects themselves."""
    bundled = PricingCatalog.load(BUNDLED_CATALOG)
    assert bundled.lookup("google", "gemini-3.5-flash") is not None
    assert bundled.lookup("vertex", "gemini-3.5-flash") is None
    for card in bundled.cards:
        assert not card.matches("vertex", "gemini-3.5-flash")
        assert not card.matches("bedrock", PROFILE)


@pytest.mark.asyncio
async def test_vertex_user_supplied_rates_price_the_call(monkeypatch):
    _install_fake_google_genai(monkeypatch)
    adapter = Vertex("gemini-3.5-flash", rates={"input": "1", "output": "2"})
    usage = {"promptTokenCount": 1_000_000, "candidatesTokenCount": 1_000_000}
    monkeypatch.setattr(
        adapter,
        "_get_client",
        lambda: _genai_client(
            SimpleNamespace(
                candidates=[
                    SimpleNamespace(
                        finish_reason="STOP",
                        content=SimpleNamespace(parts=[SimpleNamespace(text="hello")]),
                    )
                ],
                model_version="gemini-3.5-flash",
                usage_metadata=usage,
            ),
            {},
        ),
    )

    result = await adapter.complete([{"role": "user", "content": "hi"}])

    assert result["billing"]["status"] == "complete"
    assert result["cost"] == 3.0
    assert result["billing"]["calculation"]["pricing_basis"] == USER_SUPPLIED


# --- 5. VertexAnthropic ----------------------------------------------------


@pytest.mark.asyncio
async def test_vertex_anthropic_records_usage_and_claims_no_cost(monkeypatch):
    seen: dict[str, Any] = {}
    adapter = VertexAnthropic("claude-sonnet-5@20260101", project="acme", region="us-east5")
    monkeypatch.setattr(
        adapter, "_get_client", lambda: _anthropic_client(_messages_response(), seen)
    )

    result = await adapter.complete([{"role": "user", "content": "hi"}])

    assert result["usage"] == BEDROCK_USAGE
    _assert_unpriced(result, "vertex", "us-east5")
    assert seen["model"] == "claude-sonnet-5@20260101"


@pytest.mark.parametrize("kwargs", [{"service_tier": "auto"}, {"inference_geo": "us"}])
def test_vertex_anthropic_refuses_tier_and_geo(kwargs):
    with pytest.raises(ValueError, match="capacity and region"):
        VertexAnthropic(**kwargs)


# --- 6. extras, and a base install that still imports ----------------------


@pytest.mark.parametrize(
    ("adapter", "extra", "blocked"),
    [
        (lambda: Bedrock(PROFILE), "opentine[bedrock]", "anthropic"),
        (lambda: VertexAnthropic(), "opentine[vertex]", "anthropic"),
        (lambda: Vertex(), "opentine[vertex]", "google.genai"),
    ],
)
def test_the_sdk_import_error_names_the_extra_that_fixes_it(adapter, extra, blocked, monkeypatch):
    monkeypatch.setitem(sys.modules, blocked, None)
    with pytest.raises(ImportError, match=extra.replace("[", r"\[").replace("]", r"\]")):
        adapter()._get_client()


def test_the_base_install_carries_no_cloud_sdk():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    core = " ".join(project["dependencies"]).lower()
    for package in ("boto3", "botocore", "google-auth", "google-genai", "anthropic"):
        assert package not in core, f"{package} must stay in an extra, not the base install"
    extras = project["optional-dependencies"]
    assert extras["bedrock"] == ["anthropic[bedrock]>=0.87"]
    assert extras["vertex"] == ["google-genai>=2.8.0", "anthropic[vertex]>=0.87"]
    assert "azure" not in extras  # Azure OpenAI is served by the `compat` extra
    for requirement in (*extras["bedrock"], *extras["vertex"]):
        assert requirement in extras["all"] or requirement.split("[")[0] in " ".join(extras["all"])


def test_the_managed_modules_import_without_any_cloud_sdk(monkeypatch):
    """The ImportError is raised at ``_get_client``, never at import time."""
    for name in ("anthropic", "boto3", "botocore", "google.auth", "google.genai"):
        monkeypatch.setitem(sys.modules, name, None)
    for name in (
        "opentine.models._managed_aws",
        "opentine.models._managed_gcp",
        "opentine.models.managed",
    ):
        importlib.reload(importlib.import_module(name))
    # And constructing an adapter is still fine — only the client needs the SDK.
    assert Bedrock(PROFILE).name == PROFILE
