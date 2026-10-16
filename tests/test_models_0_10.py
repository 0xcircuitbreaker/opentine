"""0.10 adapters: current model families, compatible endpoints, new vendors."""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest

from opentine.models import model_class, provider_names, resolve_model
from opentine.models._inline_reasoning import InlineReasoningStream, split_inline
from opentine.models._model_traits import claude_rules, openai_omits_temperature

# --------------------------------------------------------------------------- #
# Current families and day-one newcomers
# --------------------------------------------------------------------------- #

CLAUDE_CURRENT = [
    "claude-opus-5-5",
    "claude-sonnet-5-5",
    "claude-haiku-5-5",
    "claude-fable-5",
    "claude-fable-5-1",
]
CLAUDE_UNANNOUNCED = ["claude-fable-5-5", "claude-opus-6", "claude-sonnet-6-1", "claude-haiku-6"]
GPT_CURRENT = ["gpt-6-astra", "gpt-6-sol", "gpt-6-luna", "gpt-6.1-sol"]
GPT_UNANNOUNCED = ["gpt-6.1-luna", "gpt-6.2-sol", "gpt-7", "gpt-6.1-astra-2026-11-01"]


@pytest.mark.parametrize("model", CLAUDE_CURRENT + CLAUDE_UNANNOUNCED)
def test_claude_5_and_later_get_thinking_and_no_sampling(model):
    from opentine.models.anthropic import Anthropic

    supports, restricted, _ = claude_rules(model)
    assert supports and restricted
    kwargs = Anthropic(model, api_key="k")._kwargs([], None, None, 0.7)
    assert "temperature" not in kwargs and "extra_body" not in kwargs


@pytest.mark.parametrize("model", GPT_CURRENT + GPT_UNANNOUNCED)
def test_gpt_6_family_omits_temperature_on_every_openai_path(model, monkeypatch):
    from opentine.models._responses import ResponsesTransport
    from opentine.models.openai import OpenAI

    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    assert openai_omits_temperature(model, native=True)
    assert openai_omits_temperature(model, native=False)  # gpt-6 behind a gateway too
    assert "temperature" not in ResponsesTransport(model=model).kwargs([], None, None, 0.7)
    assert "temperature" not in OpenAI(model, api_key="k")._kwargs([], None, None, 0.7)


def test_the_defaults_are_current_models():
    from opentine.models.anthropic import Anthropic
    from opentine.models.openai import OpenAI

    assert Anthropic(api_key="k").name == "claude-sonnet-5-5"
    assert OpenAI(api_key="k").name == "gpt-6.1-sol"


@pytest.mark.parametrize(
    ("provider", "model"),
    [
        ("anthropic", "claude-opus-5-5"),
        ("anthropic", "claude-sonnet-5-5"),
        ("anthropic", "claude-haiku-5-5"),
        ("anthropic", "claude-fable-5"),
        ("anthropic", "claude-fable-5-1"),
        ("openai", "gpt-6-astra"),
        ("openai", "gpt-6-sol"),
        ("openai", "gpt-6-luna"),
        ("openai", "gpt-6.1-sol"),
    ],
)
def test_every_current_flagship_has_a_signed_card(provider, model):
    from opentine.billing.catalog import load_catalogs

    assert load_catalogs().lookup(provider, model) is not None


# --------------------------------------------------------------------------- #
# Compatible endpoints: their own provider, never a first-party card
# --------------------------------------------------------------------------- #


def test_anthropic_adapter_records_a_compatible_servers_provider():
    from opentine.models.anthropic import Anthropic

    adapter = Anthropic(
        "claude-opus-5-5",
        api_key="k",
        base_url="http://127.0.0.1:11434",
        provider="ollama",
        unmetered=True,
    )
    usage = SimpleNamespace(input_tokens=100, output_tokens=10, cache_read_input_tokens=0)
    metered = adapter._meter(SimpleNamespace(usage=usage, model="claude-opus-5-5"))
    assert metered["provider"] == "ollama"
    assert metered["billing"]["status"] == "unmetered"


def test_anthropic_cache_inclusive_servers_are_not_double_counted():
    from opentine.models._usage import anthropic_usage

    raw = SimpleNamespace(input_tokens=1000, output_tokens=5, cache_read_input_tokens=800)
    assert anthropic_usage(raw).input == 1000
    assert anthropic_usage(raw, cache_inclusive=True).input == 200
    assert anthropic_usage(raw, cache_inclusive=True).cache_read == 800


def test_openai_responses_on_a_compatible_server_records_its_provider():
    from opentine.models.openai import OpenAI

    adapter = OpenAI(
        "gpt-oss-120b",
        api_key="lm-studio",
        base_url="http://127.0.0.1:1234/v1",
        provider="lmstudio",
        responses=True,
        unmetered=True,
    )
    assert adapter._native_responses
    usage = SimpleNamespace(input_tokens=10, output_tokens=3)
    metered = adapter._responses.meter(SimpleNamespace(usage=usage, model="gpt-oss-120b"))
    assert metered["provider"] == "lmstudio" and metered["billing"]["status"] == "unmetered"
    assert "temperature" in adapter._responses.kwargs([], None, None, 0.2)  # not OpenAI's API


@pytest.mark.parametrize("host", ["eu.api.openai.com", "us.api.openai.com", "jp.api.openai.com"])
def test_openai_data_residency_hosts_stay_native(host, monkeypatch):
    from opentine.models.openai import OpenAI

    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")
    adapter = OpenAI("gpt-6.1-sol", base_url=f"https://{host}/v1")
    assert adapter._provider == "openai" and adapter._native_responses
    assert adapter._api_key == "sk-fake"


def test_lookalike_host_is_not_openai():
    from opentine.models.openai import OpenAI

    adapter = OpenAI("m", api_key="k", base_url="https://eu.api.openai.com.evil.example/v1")
    assert adapter._provider == "openai-compatible"


# --------------------------------------------------------------------------- #
# New hosted vendors and corrected defaults
# --------------------------------------------------------------------------- #

VENDORS = {
    "meta": ("meta", "https://api.meta.ai/v1"),
    "minimax": ("minimax", "https://api.minimax.io/v1"),
    "deepinfra": ("deepinfra", "https://api.deepinfra.com/v1/openai"),
    "fireworks": ("fireworks", "https://api.fireworks.ai/inference/v1"),
    "cerebras": ("cerebras", "https://api.cerebras.ai/v1"),
    "sambanova": ("sambanova", "https://api.sambanova.ai/v1"),
    "stepfun": ("stepfun", "https://api.stepfun.ai/v1"),
    "xiaomi": ("xiaomi", "https://api.xiaomimimo.com/v1"),
    "upstage": ("upstage", "https://api.upstage.ai/v1"),
    "inception": ("inception", "https://api.inceptionlabs.ai/v1"),
    "nvidia": ("nvidia", "https://integrate.api.nvidia.com/v1"),
    "huggingface": ("huggingface", "https://router.huggingface.co/v1"),
    "vercel": ("vercel", "https://ai-gateway.vercel.sh/v1"),
    "cohere": ("cohere", "https://api.cohere.ai/compatibility/v1"),
}


@pytest.mark.parametrize("name", sorted(VENDORS))
def test_a_vendor_resolves_to_its_own_provider_and_endpoint(name, monkeypatch):
    monkeypatch.delenv("FIREWORKS_BASE_URL", raising=False)
    adapter = resolve_model(name)
    assert (adapter._provider, adapter._base_url) == VENDORS[name]
    assert name in provider_names()


def test_fireworks_us_host_bills_the_us_tier(monkeypatch):
    monkeypatch.setenv("FIREWORKS_BASE_URL", "https://us.api.fireworks.ai/inference/v1")
    adapter = resolve_model("fireworks")
    assert adapter._provider == "fireworks"
    assert adapter._billing_tier([], None) == "us"
    assert adapter._billing_tier([], "priority") == "priority_us"
    monkeypatch.delenv("FIREWORKS_BASE_URL")
    assert resolve_model("fireworks")._billing_tier([], None) is None


def test_minimax_keeps_thinking_out_of_content_and_meta_omits_temperature():
    assert resolve_model("minimax")._kwargs([], None, None, 0.2)["extra_body"] == {
        "reasoning_split": True
    }
    assert "temperature" not in resolve_model("meta")._kwargs([], None, None, 0.2)


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("global.anthropic.claude-opus-5-5-v1:0", ("anthropic.claude-opus-5-5-v1:0", None)),
        ("us.anthropic.claude-opus-5-5-v1:0", ("anthropic.claude-opus-5-5-v1:0", "regional")),
        ("eu.x", ("x", "regional")),
        ("openai.gpt-oss-120b-1:0", ("gpt-oss-120b-1:0", None)),
        ("us.openai.gpt-6-astra-v1:0", ("gpt-6-astra-v1:0", "regional")),
    ],
)
def test_bedrock_routing_prefix_selects_card_and_tier(model, expected):
    from opentine.models._compat_vendors import bedrock_pricing

    assert bedrock_pricing(model) == expected


def test_bedrock_endpoint_follows_the_region(monkeypatch):
    monkeypatch.delenv("BEDROCK_BASE_URL", raising=False)
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    assert resolve_model("bedrock")._base_url == (
        "https://bedrock-runtime.eu-west-1.amazonaws.com/openai/v1"
    )


def test_bedrock_regional_claude_prices_from_the_bedrock_card():
    adapter = resolve_model("bedrock:us.anthropic.claude-opus-5-5")
    usage = {"prompt_tokens": 1_000_000, "completion_tokens": 0}
    billing = adapter._meter(usage)["billing"]
    assert billing["status"] == "complete"
    assert Decimal(billing["amount_usd"]) == Decimal("4.4")
    glob = resolve_model("bedrock:global.anthropic.claude-opus-5-5")._meter(usage)["billing"]
    assert Decimal(glob["amount_usd"]) == Decimal("4")


def test_deepinfra_reported_cost_is_the_price():
    adapter = resolve_model("deepinfra:some/unlisted-model")
    usage = SimpleNamespace(prompt_tokens=10, completion_tokens=5, estimated_cost=0.0042)
    metered = adapter._meter(usage)
    assert metered["billing"]["status"] == "complete"
    assert Decimal(metered["billing"]["amount_usd"]) == Decimal("0.0042")
    assert metered["billing"]["calculation"]["pricing_basis"] == "provider_reported_total"


@pytest.mark.parametrize(
    ("name", "model"),
    [
        ("groq", "openai/gpt-oss-120b"),
        ("together", "meta-models/Muse-Glimmer-30B"),
        ("openrouter", "openai/gpt-oss-120b"),
    ],
)
def test_retired_hosted_defaults_are_replaced(name, model):
    assert model_class(name)(api_key="k").name == model


def test_inception_top_level_cached_input_tokens_are_cache_reads():
    from opentine.models._usage import openai_usage

    usage = openai_usage({"prompt_tokens": 100, "completion_tokens": 1, "cached_input_tokens": 60})
    assert (usage.input, usage.cache_read) == (40, 60)


@pytest.mark.asyncio
async def test_mistral_tier_is_read_from_usage():
    from opentine.models.compat import Mistral

    class FakeCompletions:
        async def create(self, **kwargs: Any):
            usage = SimpleNamespace(prompt_tokens=10, completion_tokens=1, service_tier="flex")
            message = SimpleNamespace(content="ok", tool_calls=None, refusal=None)
            choice = SimpleNamespace(message=message, finish_reason="stop")
            return SimpleNamespace(choices=[choice], usage=usage, model="mistral-large-2512")

    adapter = Mistral(api_key="k")
    client = SimpleNamespace(chat=SimpleNamespace(completions=FakeCompletions()))
    result = await adapter._complete(client, [{"role": "user", "content": "hi"}])
    assert result["billing"]["calculation"]["service_tier"] == "flex"


# --------------------------------------------------------------------------- #
# Inline reasoning and stream usage
# --------------------------------------------------------------------------- #

INLINE = [
    ("<think>plan</think>\n\nAnswer", ("Answer", "plan")),
    ("[THINK]x[/THINK]y", ("y", "x")),
    (
        "<|channel|>analysis<|message|>t<|end|><|start|>assistant<|channel|>final"
        "<|message|>Hi<|return|>",
        ("Hi", "t"),
    ),
    ("Normal answer that mentions <think> tags", ("Normal answer that mentions <think> tags", "")),
    ("<think>unterminated", ("", "unterminated")),
]


@pytest.mark.parametrize(("text", "expected"), INLINE)
@pytest.mark.parametrize("size", [1, 3, 1000])
def test_inline_reasoning_is_split_the_same_whole_or_streamed(text, expected, size):
    assert split_inline(text) == expected
    stream, answer, reasoning = InlineReasoningStream(), "", ""
    for start in range(0, len(text), size):
        piece = stream.feed(text[start : start + size])
        answer, reasoning = answer + piece[0], reasoning + piece[1]
    tail = stream.flush()
    assert ((answer + tail[0]).lstrip(), reasoning + tail[1]) == expected


def test_chat_message_with_inline_think_records_reasoning():
    from opentine.models._stream_content import chat_content

    result = chat_content(SimpleNamespace(content="<think>hmm</think>Paris", tool_calls=None))
    assert result["text"] == "Paris" and result["reasoning_content"] == "hmm"
    both = chat_content(
        SimpleNamespace(content="<think>hmm</think>Paris", reasoning_content="hmm", tool_calls=None)
    )
    assert both["text"] == "Paris" and both["reasoning_content"] == "hmm"  # not recorded twice


@pytest.mark.asyncio
async def test_cumulative_stream_usage_is_emitted_once():
    from opentine.models.compat import VLLM

    class FakeCompletions:
        async def create(self, **kwargs: Any):
            async def chunks():
                for count in (1, 2, 3):
                    delta = SimpleNamespace(content="x", tool_calls=None)
                    yield SimpleNamespace(
                        choices=[SimpleNamespace(delta=delta, finish_reason="stop")],
                        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=count),
                    )

            return chunks()

    adapter = VLLM()
    client = SimpleNamespace(chat=SimpleNamespace(completions=FakeCompletions()))
    events = [event async for event in adapter._stream(client, [{"role": "user", "content": "q"}])]
    usage = [event for event in events if event["type"] == "usage"]
    assert len(usage) == 1 and usage[0]["usage"]["output"] == 3


@pytest.mark.parametrize(("model", "amount"), [("gpt-6.1-sol", "4.4"), ("gpt-4o", None)])
def test_openai_regional_host_bills_the_regional_uplift_where_carded(model, amount, monkeypatch):
    from opentine.models.openai import OpenAI

    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")
    adapter = OpenAI(model, base_url="https://eu.api.openai.com/v1")
    details = {"cached_tokens": 0, "cache_write_tokens": 0}
    usage = {"input_tokens": 1_000_000, "output_tokens": 0, "input_tokens_details": details}
    billing = adapter._responses.meter(SimpleNamespace(usage=usage, model=model))["billing"]
    tier = billing["calculation"]["service_tier"]
    if amount is None:  # released before 2026-03-05: no regional uplift is carded
        assert tier != "regional"
    else:
        assert tier == "regional" and Decimal(billing["amount_usd"]) == Decimal(amount)


# --------------------------------------------------------------------------- #
# Round-4 re-audit: ambient credentials, bounded splitter, Bedrock tier
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "base_url",
    ["http://127.0.0.1:11434", "https://gateway.example.com", "https://anthropic.com.evil"],
)
def test_third_party_anthropic_base_url_never_gets_first_party_credentials(base_url, monkeypatch):
    from opentine.models._anthropic_client import credentials
    from opentine.models.anthropic import Anthropic

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-first-party")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "fake-first-party-token")
    monkeypatch.delenv("ANTHROPIC_COMPAT_API_KEY", raising=False)
    assert credentials(None, base_url) == ("", "")
    client = Anthropic("qwen3", base_url=base_url)._get_client()
    assert client.api_key == "anthropic-compatible" and not client.auth_token
    headers = client.default_headers
    assert headers.get("X-Api-Key") == "anthropic-compatible"
    assert "fake-first-party-token" not in str(headers.get("Authorization"))
    monkeypatch.setenv("ANTHROPIC_COMPAT_API_KEY", "compat-key")
    assert credentials(None, base_url) == ("compat-key", "")
    assert credentials("explicit", base_url) == ("explicit", "")


def test_first_party_and_ambient_base_url_keep_sdk_credentials(monkeypatch):
    from opentine.models._anthropic_client import credentials

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "tok")
    assert credentials(None) == ("sk-ant-fake", "tok")
    assert credentials(None, "https://api.anthropic.com") == ("sk-ant-fake", "tok")


def test_cli_base_url_overrides_never_carry_a_vendors_ambient_key(monkeypatch):
    from opentine._cli_run_model import build_model

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-first-party")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "fake-first-party-token")
    local = build_model("anthropic:qwen3", "http://127.0.0.1:11434", None)
    assert local._api_key == "" and local._auth_token == ""
    assert local._provider == "local-anthropic-compatible" and local._unmetered
    remote = build_model("anthropic:qwen3", "https://gateway.example.com", None)
    assert remote._provider == "anthropic-compatible" and remote._api_key == ""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fake")
    with pytest.raises(ValueError, match="--api-key-env"):
        build_model("groq", "https://elsewhere.example.com/v1", None)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-openai")
    monkeypatch.delenv("OPENAI_COMPAT_API_KEY", raising=False)
    assert build_model("openai:qwen3", "https://gpu-box.example.com/v1", None)._api_key == ""


def test_inline_reasoning_stream_is_bounded_and_linear():
    from opentine.models import _inline_reasoning as inline

    stream = InlineReasoningStream()
    stream.feed("<|channel|>analysis<|message|>t<|end|>")
    started = __import__("time").perf_counter()
    for _ in range(20_000):
        stream.feed("x" * 64)
    assert __import__("time").perf_counter() - started < 2.0
    assert len(stream._pending) <= inline.GAP_LIMIT + 64
    blank = InlineReasoningStream()
    for _ in range(20_000):
        assert blank.feed(" ") == ("", "")
    assert len(blank._pending) <= 64
    assert blank.feed("Hello")[0].endswith("Hello")


def test_bedrock_regional_uplift_survives_a_default_response_tier():
    adapter = resolve_model("bedrock:us.anthropic.claude-opus-5-5")
    usage = {"prompt_tokens": 1_000_000, "completion_tokens": 0}
    for observed in ("default", "standard", "", None):
        billing = adapter._meter(usage, observed)["billing"]
        assert Decimal(billing["amount_usd"]) == Decimal("4.4"), observed


# --------------------------------------------------------------------------- #
# Final pass 6: cloud tags never unmetered; regional uplift composes with tiers
# --------------------------------------------------------------------------- #

_CLOUD_TAGS = ["glm-5.1:cloud", "qwen3-coder:480b-cloud", "gpt-oss:120b-cloud"]


@pytest.mark.parametrize("model", _CLOUD_TAGS)
def test_a_loopback_anthropic_endpoint_never_books_a_cloud_tag_unmetered(model):
    from opentine._cli_run_model import compatible_anthropic
    from opentine.models.anthropic import Anthropic

    identity = compatible_anthropic("http://127.0.0.1:11434")
    adapter = Anthropic(model, api_key="k", base_url="http://127.0.0.1:11434", **identity)
    usage = SimpleNamespace(input_tokens=200_000, output_tokens=50_000, cache_read_input_tokens=0)
    billing = adapter._meter(SimpleNamespace(usage=usage, model=model))["billing"]
    assert billing["status"] != "unmetered"
    assert any("cloud-tagged" in warning for warning in billing["warnings"])


@pytest.mark.parametrize("model", _CLOUD_TAGS)
@pytest.mark.parametrize("preset", ["llamacpp", "lmstudio", "vllm", "sglang", "localai"])
def test_a_local_preset_never_books_a_cloud_tag_unmetered(preset, model):
    from opentine.models import model_class

    adapter = model_class(preset)(model)
    usage = {"prompt_tokens": 200_000, "completion_tokens": 50_000}
    billing = adapter._meter(usage, None, model, False)["billing"]
    assert billing["status"] != "unmetered"


def test_a_local_preset_still_books_a_plain_local_model_unmetered():
    from opentine.models import model_class

    adapter = model_class("llamacpp")("qwen3:8b")
    billing = adapter._meter({"prompt_tokens": 10, "completion_tokens": 5}, None, "qwen3:8b", False)
    assert billing["billing"]["status"] == "unmetered"


@pytest.mark.parametrize("model", _CLOUD_TAGS)
def test_an_openai_compatible_unmetered_endpoint_never_books_a_cloud_tag(model):
    from opentine.models.openai import OpenAI

    adapter = OpenAI(model, base_url="http://127.0.0.1:11434/v1", api_key="k", unmetered=True)
    usage = {"input_tokens": 1000, "output_tokens": 10, "input_tokens_details": {}}
    billing = adapter._responses.meter(SimpleNamespace(usage=usage, model=model))["billing"]
    assert billing["status"] != "unmetered"


@pytest.mark.parametrize("tier", ["priority", "flex"])
def test_openai_regional_host_never_prices_priority_or_flex_at_the_global_rate(tier, monkeypatch):
    from opentine.models.openai import OpenAI

    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")
    regional = OpenAI("gpt-6.1-sol", base_url="https://eu.api.openai.com/v1", service_tier=tier)
    usage = {"input_tokens": 1_000_000, "output_tokens": 0, "input_tokens_details": {}}
    response = SimpleNamespace(usage=usage, model="gpt-6.1-sol", service_tier=tier)
    billing = regional._responses.meter(response)["billing"]
    assert billing["calculation"]["service_tier"] == f"{tier}_regional"
    assert billing["status"] != "complete"  # uncarded combination: unknown, not the global rate


def test_openai_regional_chat_completions_carry_the_uplift(monkeypatch):
    from opentine.models.openai import OpenAI

    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")
    regional = OpenAI("gpt-6.1-sol", base_url="https://eu.api.openai.com/v1")
    assert regional._billing_tier([], None) == "regional"
    assert regional._billing_tier([], "priority") == "priority_regional"
    plain = OpenAI("gpt-6.1-sol")
    assert plain._billing_tier([], None) is None


# --- final pass 7 #5: --base-url builds a hosted preset against the real host --- #

_PRESET_ENV = ("FIREWORKS_BASE_URL", "GLM_BASE_URL", "GLM_REGION", "GLM_API_KEY")


def test_base_url_gives_the_same_billing_identity_as_the_documented_env_route(monkeypatch):
    from opentine._cli_run_model import build_model

    for name in _PRESET_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TEST_PRESET_KEY", "test-key")
    us = "https://us.api.fireworks.ai/inference/v1"
    flag = build_model("fireworks:accounts/fireworks/models/glm-5p3", us, "TEST_PRESET_KEY")
    monkeypatch.setenv("FIREWORKS_BASE_URL", us)
    monkeypatch.setenv("FIREWORKS_API_KEY", "test-key")
    env = model_class("fireworks")("accounts/fireworks/models/glm-5p3")
    assert flag._base_url == env._base_url == us
    assert flag._us_host and env._us_host
    assert flag._billing_tier([], None) == env._billing_tier([], None) == "us"

    china = "https://open.bigmodel.cn/api/paas/v4"
    glm = build_model("glm:glm-5.3", china, "TEST_PRESET_KEY")
    assert glm._base_url == china and glm._provider == "glm-cn"
    international = build_model("glm:glm-5.3", "https://api.z.ai/api/paas/v4", "TEST_PRESET_KEY")
    assert international._provider == "glm"


@pytest.mark.parametrize("name", sorted(set(provider_names()) - {"google", "ollama"}))
def test_every_preset_accepts_base_url_at_construction(name, monkeypatch):
    from opentine._cli_run_model import build_model

    for variable in _PRESET_ENV:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("TEST_PRESET_KEY", "test-key")
    adapter = build_model(name, "https://gateway.example/v1", "TEST_PRESET_KEY")
    assert getattr(adapter, "_base_url", "https://gateway.example/v1").rstrip("/") in (
        "https://gateway.example/v1",
        "https://gateway.example",
    ), name
