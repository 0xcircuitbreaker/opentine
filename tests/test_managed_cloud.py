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
from opentine.models._chat import ChatCompletions
from opentine.models._managed_aws import arn_region, profile_name
from opentine.models._managed_billing import MANAGED_UNPRICED, USER_SUPPLIED
from opentine.models.google import Google
from opentine.models.managed import (
    AzureOpenAI,
    Bedrock,
    BedrockCompatible,
    Vertex,
    VertexAnthropic,
)
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


def _streaming_chat_client(seen: dict[str, Any]) -> SimpleNamespace:
    """A stream that reports usage only in a final, choice-less chunk.

    That is what an OpenAI-compatible endpoint sends *when asked* with
    ``stream_options={"include_usage": True}``, and what it omits entirely when
    not asked — the difference the Azure adapter exists to guarantee.
    """

    class Stream:
        def __aiter__(self):
            async def chunks():
                yield SimpleNamespace(
                    model="gpt-5.6",
                    usage=None,
                    choices=[
                        SimpleNamespace(
                            finish_reason=None,
                            delta=SimpleNamespace(content="hello", tool_calls=None),
                        )
                    ],
                )
                yield SimpleNamespace(
                    model="gpt-5.6",
                    usage=None,
                    choices=[SimpleNamespace(finish_reason="stop", delta=None)],
                )
                yield SimpleNamespace(
                    model="gpt-5.6",
                    choices=[],
                    usage=SimpleNamespace(
                        prompt_tokens=1_000, completion_tokens=200, total_tokens=1_200
                    ),
                )

            return chunks()

    class Completions:
        async def create(self, **kwargs: Any) -> Any:
            seen.update(kwargs)
            return Stream()

    return SimpleNamespace(chat=SimpleNamespace(completions=Completions()))


@pytest.fixture(autouse=True)
def _no_ambient_cloud_keys(monkeypatch):
    """A developer's exported keys must not decide what this file proves.

    ``OPENAI_API_KEY`` in particular: the Azure tests below assert it is *never*
    consulted, which is only meaningful if the assertion cannot pass by accident
    on a machine that does not have it set either.
    """
    for name in (
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_REGION",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


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


# --- 6. AzureOpenAI: the same models, a different bill ---------------------


@pytest.mark.asyncio
async def test_azure_openai_records_full_usage_and_claims_no_cost(monkeypatch):
    seen: dict[str, Any] = {}
    adapter = AzureOpenAI("gpt-5.6", resource="acme-prod", region="eastus", api_key="azure-secret")
    monkeypatch.setattr(
        adapter, "_get_client", lambda: _chat_client(_chat_response(model="gpt-5.6"), seen)
    )

    assert adapter._base_url == "https://acme-prod.openai.azure.com/openai/v1"

    result = await adapter.complete([{"role": "user", "content": "hi"}])

    assert result["text"] == "hello"
    assert result["usage"] == {"input": 1_000, "output": 200, "total": 1_200}
    _assert_unpriced(result, "azure-openai", "eastus")
    assert seen["model"] == "gpt-5.6"  # the deployment name, sent as `model`


def test_azure_openai_is_unknown_where_the_direct_openai_api_is_priced():
    """THE regression, in Azure's spelling: one model string, two bills.

    Azure echoes ``gpt-5.6`` — the exact string the direct API reports, for which
    the bundled catalog holds a card. Only ``_provider_id`` distinguishes the two
    calls, and it is a class attribute no caller can set back to ``"openai"``.
    """
    usage = SimpleNamespace(
        prompt_tokens=1_000_000,
        completion_tokens=1_000_000,
        total_tokens=2_000_000,
        prompt_tokens_details=SimpleNamespace(cached_tokens=0, cache_write_tokens=0),
        completion_tokens_details=SimpleNamespace(reasoning_tokens=0),
    )
    direct = ChatCompletions("gpt-5.6", provider="openai")._meter(usage, None, "gpt-5.6")
    managed = AzureOpenAI("gpt-5.6", resource="acme")._meter(usage, None, "gpt-5.6")

    assert direct["billing"]["status"] == "complete"
    assert direct["billing"]["rate_card_id"] is not None
    assert direct["cost"] > 0

    assert managed["billing"]["calculation"]["provider"] == "azure-openai"
    assert managed["billing"]["status"] == "unknown"
    assert managed["billing"]["rate_card_id"] is None
    assert managed["cost"] == 0.0
    assert managed["usage"] == direct["usage"]  # identical usage, no cost claimed
    # No region was supplied and none is inferred: the hostname does not name one.
    assert "managed_region" not in managed["billing"]["calculation"]


def test_the_bundled_catalog_cannot_be_made_to_price_azure():
    bundled = PricingCatalog.load(BUNDLED_CATALOG)
    assert bundled.lookup("openai", "gpt-5.6") is not None
    assert bundled.lookup("azure-openai", "gpt-5.6") is None
    for card in bundled.cards:
        assert not card.matches("azure-openai", "gpt-5.6")


# --- 6a. the base URL is assembled, never guessed --------------------------


@pytest.mark.parametrize(
    ("kwargs", "env", "expected"),
    [
        # resource= is the ordinary form.
        ({"resource": "acme-prod"}, None, "https://acme-prod.openai.azure.com/openai/v1"),
        # AZURE_OPENAI_ENDPOINT as the portal shows it, with and without a slash.
        ({}, "https://acme-prod.openai.azure.com", "https://acme-prod.openai.azure.com/openai/v1"),
        ({}, "https://acme-prod.openai.azure.com/", "https://acme-prod.openai.azure.com/openai/v1"),
        # Already suffixed: appended once, never twice.
        (
            {},
            "https://acme-prod.openai.azure.com/openai/v1",
            "https://acme-prod.openai.azure.com/openai/v1",
        ),
        # A bare resource name in the environment variable.
        ({}, "acme-prod", "https://acme-prod.openai.azure.com/openai/v1"),
        # An exact base_url is used exactly — private endpoints and gateways.
        (
            {"base_url": "https://acme.privatelink.openai.azure.com/openai/v1"},
            None,
            "https://acme.privatelink.openai.azure.com/openai/v1",
        ),
        # ...including one that is not the conventional path at all.
        ({"base_url": "https://gw.acme.internal/azure"}, None, "https://gw.acme.internal/azure"),
        # An explicit argument beats the ambient environment.
        ({"resource": "explicit"}, "https://ambient.openai.azure.com", None),
    ],
)
def test_azure_openai_assembles_its_endpoint(kwargs, env, expected, monkeypatch):
    if env is not None:
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", env)
    adapter = AzureOpenAI("gpt-5.6", **kwargs)
    assert adapter._base_url == (expected or "https://explicit.openai.azure.com/openai/v1")


def test_azure_openai_refuses_a_half_configured_endpoint(monkeypatch):
    with pytest.raises(ValueError, match="not both"):
        AzureOpenAI("gpt-5.6", resource="acme", base_url="https://acme.openai.azure.com/openai/v1")
    with pytest.raises(ValueError, match="AZURE_OPENAI_ENDPOINT"):
        AzureOpenAI("gpt-5.6")


@pytest.mark.parametrize(
    "url",
    [
        "https://acme.openai.azure.com/openai/deployments/gpt-5.6",
        "https://acme.openai.azure.com/openai/v1?api-version=2026-05-01",
    ],
)
def test_azure_openai_rejects_the_legacy_api_version_surface(url):
    """The documented non-goal, refused rather than half-supported.

    The legacy surface puts the deployment in the path and requires a dated
    ``api-version`` on every request — neither of which an OpenAI-compatible
    client sends. Accepting the URL would produce 404s the caller could not
    explain, so the error names the supported form instead.
    """
    with pytest.raises(ValueError, match="AsyncAzureOpenAI"):
        AzureOpenAI("gpt-5.6", base_url=url)


# --- 6b. the credential rule: AZURE_OPENAI_API_KEY, and nothing else -------


def test_azure_openai_never_falls_back_to_a_direct_openai_key(monkeypatch):
    """A key minted for api.openai.com must not ride out to *.openai.azure.com.

    This is the same non-forwarding rule ``OpenAICompatible`` applies to
    gateways. Without it, any developer with ``OPENAI_API_KEY`` exported would
    ship their direct-OpenAI secret to a different company's endpoint on the
    first Azure call, silently and successfully enough to look fine.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "sk-direct-openai-secret")
    adapter = AzureOpenAI("gpt-5.6", resource="acme")
    assert adapter._api_key == ""
    assert "sk-direct-openai-secret" not in json.dumps(vars(adapter), default=str)


def test_azure_openai_reads_its_own_key_from_the_environment(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "azure-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-direct-openai-secret")
    assert AzureOpenAI("gpt-5.6", resource="acme")._api_key == "azure-secret"


def test_azure_openai_accepts_a_minted_entra_bearer_token(monkeypatch):
    """Entra ID works by handing the adapter a token; acquisition stays outside.

    Token lifetime and refresh belong to the caller's identity library, so the
    adapter takes the minted bearer and does not pretend to manage it.
    """
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "the-api-key")
    adapter = AzureOpenAI("gpt-5.6", resource="acme", api_key="eyJ0eXAiOiJKV1Qi.entra.token")
    assert adapter._api_key == "eyJ0eXAiOiJKV1Qi.entra.token"  # explicit beats ambient


# --- 6c. streamed usage, and the escape hatch ------------------------------


def test_azure_asks_for_stream_usage_without_widening_the_shared_allowlist():
    """``include_usage`` is set on the adapter, not in ``_stream_usage_providers``.

    That set's documented bar is positive evidence that a provider accepts
    ``stream_options`` — a wrong entry makes every streamed call fail outright
    (Mistral answers HTTP 422). An adapter that knows its own endpoint can opt
    itself in without making a claim on behalf of anyone else.
    """
    assert "azure-openai" not in ChatCompletions._stream_usage_providers
    assert AzureOpenAI("gpt-5.6", resource="acme")._include_usage is True
    assert AzureOpenAI("gpt-5.6", resource="acme", include_usage=False)._include_usage is False


@pytest.mark.asyncio
async def test_azure_stream_requests_usage_and_reports_it_unpriced(monkeypatch):
    """The silent failure shape: a stream that ends with no usage chunk at all.

    Without ``stream_options``, an OpenAI-compatible stream yields no usage, so
    the call records zero tokens and prices as "unknown" — indistinguishable in
    the artifact from the managed-cloud silence that is *supposed* to be there.
    """
    seen: dict[str, Any] = {}
    adapter = AzureOpenAI("gpt-5.6", resource="acme", region="swedencentral")
    monkeypatch.setattr(adapter, "_get_client", lambda: _streaming_chat_client(seen))

    events = [event async for event in adapter.stream([{"role": "user", "content": "hi"}])]

    assert seen["stream_options"] == {"include_usage": True}
    usage_events = [event for event in events if event["type"] == "usage"]
    assert len(usage_events) == 1
    assert usage_events[0]["usage"] == {"input": 1_000, "output": 200, "total": 1_200}
    _assert_unpriced(usage_events[0], "azure-openai", "swedencentral")


@pytest.mark.asyncio
async def test_azure_openai_user_supplied_rates_price_the_call(monkeypatch):
    """The escape hatch: an enterprise agreement the operator can actually state."""
    adapter = AzureOpenAI(
        "gpt-5.6", resource="acme", region="eastus", rates={"input": "2", "output": "8"}
    )
    response = _chat_response(model="gpt-5.6")
    response.usage = SimpleNamespace(
        prompt_tokens=1_000_000, completion_tokens=1_000_000, total_tokens=2_000_000
    )
    monkeypatch.setattr(adapter, "_get_client", lambda: _chat_client(response, {}))

    result = await adapter.complete([{"role": "user", "content": "hi"}])

    billing = result["billing"]
    assert billing["status"] == "complete"
    assert result["cost"] == 10.0
    assert billing["calculation"]["pricing_basis"] == USER_SUPPLIED
    assert billing["calculation"]["managed_region"] == "eastus"
    assert not any("not in the signed catalog" in warning for warning in billing["warnings"])


# --- 7. extras, and a base install that still imports ----------------------


@pytest.mark.parametrize(
    ("adapter", "extra", "blocked"),
    [
        (lambda: Bedrock(PROFILE), "opentine[bedrock]", "anthropic"),
        (lambda: VertexAnthropic(), "opentine[vertex]", "anthropic"),
        (lambda: Vertex(), "opentine[vertex]", "google.genai"),
        # Azure needs no extra of its own: `compat` (the openai SDK) serves it.
        (lambda: AzureOpenAI("gpt-5.6", resource="acme"), "opentine[compat]", "openai"),
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
    for name in ("anthropic", "boto3", "botocore", "google.auth", "google.genai", "openai"):
        monkeypatch.setitem(sys.modules, name, None)
    for name in (
        "opentine.models._managed_aws",
        "opentine.models._managed_azure",
        "opentine.models._managed_gcp",
        "opentine.models.managed",
    ):
        importlib.reload(importlib.import_module(name))
    # And constructing an adapter is still fine — only the client needs the SDK.
    assert Bedrock(PROFILE).name == PROFILE
