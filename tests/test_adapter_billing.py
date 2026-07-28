"""Provider wire fixtures that retain usage on non-text responses."""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest

from opentine import Run, StepKind
from opentine.billing import load_catalogs
from opentine.models.anthropic import Anthropic
from opentine.models.compat import Kimi, Qwen
from opentine.models.google import Google
from opentine.models.ollama import Ollama
from opentine.models.openai import OpenAI
from opentine.runtime import Agent


def _qwen_explicit_cache_amount() -> str:
    """Expected charge for 1 MTok each of fresh input, cached input, and output.

    Adapters bill at wall-clock now, so this must be derived from whichever rate
    card is in force rather than frozen: a hardcoded figure silently became wrong
    the day the qwen3.7-max promotional card expired (2026-07-23), turning a
    behavioural assertion into a scheduled failure.
    """
    card = load_catalogs().lookup("qwen", "qwen3.7-max")
    assert card is not None, "qwen3.7-max must have an effective rate card"
    explicit = Decimal(card.service_rates["explicit_cache"]["cache_read"])
    # The tier is only meaningful if it actually undercuts the standard rate.
    assert explicit < Decimal(card.rates["cache_read"])
    total = Decimal(card.rates["input"]) + explicit + Decimal(card.rates["output"])
    return str(total)


@pytest.mark.asyncio
async def test_openai_responses_tool_only_retains_cache_reasoning_and_cost(monkeypatch):
    seen: dict[str, Any] = {}

    class Responses:
        async def create(self, **kwargs):
            seen.update(kwargs)
            return SimpleNamespace(
                id="resp_1",
                status="completed",
                output=[
                    SimpleNamespace(type="reasoning", id="rs_1", summary=[], status="completed"),
                    SimpleNamespace(
                        type="function_call",
                        id="fc_1",
                        call_id="call_1",
                        name="weather",
                        arguments='{"city":"Paris"}',
                    ),
                ],
                output_text="",
                usage=SimpleNamespace(
                    input_tokens=100,
                    output_tokens=30,
                    total_tokens=130,
                    input_tokens_details=SimpleNamespace(cached_tokens=40, cache_write_tokens=0),
                    output_tokens_details=SimpleNamespace(reasoning_tokens=20),
                ),
            )

    adapter = OpenAI("gpt-5.6")
    monkeypatch.setattr(adapter, "_get_client", lambda: SimpleNamespace(responses=Responses()))
    result = await adapter.complete([{"role": "user", "content": "weather?"}])

    assert "temperature" not in seen
    assert result["text"] == ""
    assert result["tool_calls"] == [
        {"name": "weather", "arguments": {"city": "Paris"}, "id": "call_1"}
    ]
    assert result["usage"] == {
        "input": 60,
        "output": 10,
        "cache_read": 40,
        "reasoning": 20,
        "total": 130,
    }
    assert result["billing"]["status"] == "complete"
    assert result["cost"] > 0


@pytest.mark.asyncio
async def test_anthropic_tool_only_cache_buckets_and_adaptive_sampling(monkeypatch):
    seen: dict[str, Any] = {}

    class Messages:
        async def create(self, **kwargs):
            seen.update(kwargs)
            return SimpleNamespace(
                content=[
                    SimpleNamespace(type="tool_use", id="tool_1", name="lookup", input={"q": 1})
                ],
                stop_reason="tool_use",
                usage=SimpleNamespace(
                    input_tokens=100,
                    output_tokens=20,
                    cache_read_input_tokens=50,
                    cache_creation=SimpleNamespace(
                        ephemeral_5m_input_tokens=10,
                        ephemeral_1h_input_tokens=5,
                    ),
                ),
            )

    adapter = Anthropic("claude-fable-5")
    monkeypatch.setattr(adapter, "_get_client", lambda: SimpleNamespace(messages=Messages()))
    result = await adapter.complete([{"role": "user", "content": "lookup"}], temperature=0.8)

    assert "temperature" not in seen
    assert result["tool_calls"][0]["id"] == "tool_1"
    assert result["usage"] == {
        "input": 100,
        "output": 20,
        "cache_read": 50,
        "cache_write_5m": 10,
        "cache_write_1h": 5,
        "total": 185,
    }
    assert result["billing"]["status"] == "complete"


@pytest.mark.asyncio
async def test_anthropic_response_geo_controls_billing(monkeypatch):
    seen: dict[str, Any] = {}

    class Messages:
        async def create(self, **kwargs):
            seen.update(kwargs)
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text="ok")],
                stop_reason="end_turn",
                usage=SimpleNamespace(
                    input_tokens=1_000_000,
                    output_tokens=1_000_000,
                    inference_geo="us",
                ),
            )

    adapter = Anthropic("claude-fable-5", inference_geo="global")
    monkeypatch.setattr(adapter, "_get_client", lambda: SimpleNamespace(messages=Messages()))
    result = await adapter.complete([{"role": "user", "content": "hello"}])

    assert seen["inference_geo"] == "global"
    assert result["billing"]["calculation"]["service_tier"] == "us"
    assert result["billing"]["calculation"]["service_modifier"] == "1.1"
    assert result["billing"]["amount_usd"] == "66.0"


@pytest.mark.asyncio
@pytest.mark.parametrize(("output_tokens", "expected_cost"), [(0, 0.0), (5, 0.00025)])
async def test_anthropic_early_vs_midstream_refusal_billing(
    monkeypatch, output_tokens: int, expected_cost: float
):
    response = SimpleNamespace(
        content=[SimpleNamespace(type="refusal", refusal="cannot comply")],
        stop_reason="refusal",
        usage=SimpleNamespace(input_tokens=0, output_tokens=output_tokens),
    )

    class Messages:
        async def create(self, **kwargs):
            return response

    adapter = Anthropic("claude-fable-5")
    monkeypatch.setattr(adapter, "_get_client", lambda: SimpleNamespace(messages=Messages()))
    result = await adapter.complete([{"role": "user", "content": "request"}])
    assert result["refusal"] == "cannot comply"
    assert result["cost"] == pytest.approx(expected_cost)
    if output_tokens:
        assert "non-billable" not in " ".join(result["billing"]["warnings"])
    else:
        assert "non-billable" in " ".join(result["billing"]["warnings"])


def test_anthropic_refusal_discards_partial_text_but_retains_billable_usage():
    response = SimpleNamespace(
        content=[
            SimpleNamespace(type="text", text="unsafe partial"),
            SimpleNamespace(type="refusal", refusal="cannot comply"),
        ],
        stop_reason="refusal",
        usage=SimpleNamespace(input_tokens=10, output_tokens=5, service_tier="standard"),
    )
    result = Anthropic("claude-fable-5")._result(response)
    assert result["text"] == "" and result["refusal"] == "cannot comply"
    assert result["usage"]["output"] == 5 and result["cost"] > 0
    assert "discarded partial output" in " ".join(result["warnings"])


def test_only_fable_early_empty_refusal_is_nonbillable():
    response = SimpleNamespace(
        content=[SimpleNamespace(type="refusal", refusal="cannot comply")],
        stop_reason="refusal",
        usage=SimpleNamespace(input_tokens=1_000, output_tokens=0),
    )
    result = Anthropic("claude-sonnet-5")._result(response)
    assert result["billing"]["amount_usd"] != "0"
    assert "refusal_modifier" not in result["billing"]["calculation"]


@pytest.mark.asyncio
async def test_kimi_omits_temperature_and_preserves_reasoning_continuation(monkeypatch):
    seen: dict[str, Any] = {}

    class Completions:
        async def create(self, **kwargs):
            seen.update(kwargs)
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content="",
                            reasoning_content="chain-state",
                            tool_calls=[
                                SimpleNamespace(
                                    id="call_1",
                                    function=SimpleNamespace(name="lookup", arguments="{}"),
                                )
                            ],
                        )
                    )
                ],
                usage=SimpleNamespace(prompt_tokens=1_000_000, completion_tokens=1_000_000),
            )

    adapter = Kimi()
    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    monkeypatch.setattr(adapter, "_get_client", lambda: client)
    result = await adapter.complete([{"role": "user", "content": "lookup"}], temperature=0.9)
    assert "temperature" not in seen
    assert result["reasoning_content"] == "chain-state"
    assert result["cost"] == pytest.approx(18.0)
    continued = adapter._build_messages(
        [
            {
                "role": "assistant",
                "content": "",
                "reasoning_content": result["reasoning_content"],
                "tool_calls": result["tool_calls"],
            }
        ],
        None,
    )
    assert continued[0]["reasoning_content"] == "chain-state"


@pytest.mark.asyncio
async def test_qwen_explicit_cache_marker_selects_exact_hit_rate(monkeypatch):
    class Completions:
        async def create(self, **kwargs):
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="ok", tool_calls=[]))],
                usage=SimpleNamespace(
                    prompt_tokens=2_000_000,
                    completion_tokens=1_000_000,
                    prompt_tokens_details=SimpleNamespace(
                        cached_tokens=1_000_000,
                        cache_creation_input_tokens=0,
                    ),
                ),
            )

    adapter = Qwen()
    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    monkeypatch.setattr(adapter, "_get_client", lambda: client)
    result = await adapter.complete(
        [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "cached prompt",
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
            }
        ]
    )
    assert result["billing"]["calculation"]["service_tier"] == "explicit_cache"
    assert result["billing"]["amount_usd"] == _qwen_explicit_cache_amount()


@pytest.mark.asyncio
async def test_qwen_stream_requests_usage_and_preserves_explicit_cache_tier(monkeypatch):
    seen: dict[str, Any] = {}

    async def chunks():
        yield SimpleNamespace(
            choices=[],
            service_tier="default",
            usage=SimpleNamespace(
                prompt_tokens=2_000_000,
                completion_tokens=1_000_000,
                prompt_tokens_details=SimpleNamespace(cached_tokens=1_000_000),
            ),
        )

    class Completions:
        async def create(self, **kwargs):
            seen.update(kwargs)
            return chunks()

    adapter = Qwen()
    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    monkeypatch.setattr(adapter, "_get_client", lambda: client)
    messages = [
        {
            "role": "user",
            "content": [{"type": "text", "text": "cached", "cache_control": {"type": "ephemeral"}}],
        }
    ]

    events = [event async for event in adapter.stream(messages)]

    assert seen["stream_options"] == {"include_usage": True}
    assert events[0]["billing"]["calculation"]["service_tier"] == "explicit_cache"
    assert events[0]["billing"]["amount_usd"] == _qwen_explicit_cache_amount()


def test_google_usage_and_ollama_timing_are_normalized():
    google = Google("gemini-3-flash-preview")._meter(
        SimpleNamespace(
            prompt_token_count=100,
            cached_content_token_count=25,
            candidates_token_count=20,
            thoughts_token_count=5,
            total_token_count=125,
        )
    )
    assert google["usage"] == {
        "input": 75,
        "output": 20,
        "cache_read": 25,
        "reasoning": 5,
        "total": 125,
    }
    assert google["billing"]["status"] == "complete"

    ollama = Ollama("qwen3")._meter(
        {
            "prompt_eval_count": 10,
            "eval_count": 4,
            "total_duration": 3_000_000_000,
            "load_duration": 500_000_000,
            "prompt_eval_duration": 1_000_000_000,
            "eval_duration": 1_500_000_000,
        }
    )
    assert ollama["usage"]["input"] == 10
    assert ollama["usage"]["output"] == 4
    assert ollama["usage"]["total_seconds"] == 3
    assert ollama["usage"]["eval_seconds"] == "1.5"
    assert ollama["billing"]["status"] == "unmetered"
    assert ollama["cost"] == 0


@pytest.mark.asyncio
async def test_unknown_hosted_model_is_runnable_but_visibly_unpriced(monkeypatch):
    class Completions:
        async def create(self, **kwargs):
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="ok", tool_calls=[]))],
                usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20),
            )

    adapter = Kimi("future-model")
    monkeypatch.setattr(
        adapter,
        "_get_client",
        lambda: SimpleNamespace(chat=SimpleNamespace(completions=Completions())),
    )
    result = await adapter.complete([{"role": "user", "content": "hi"}])
    assert result["text"] == "ok"
    assert result["cost"] == 0
    assert result["billing"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_billable_partial_error_is_recorded_before_reraise():
    class PartialFailure(RuntimeError):
        opentine_response = {
            "text": "partial",
            "cost": 0.25,
            "usage": {"input": 10, "output": 2},
            "billing": {
                "status": "partial",
                "known_subtotal_usd": "0.25",
                "amount_usd": None,
                "rate_card_id": "partial-card",
            },
        }

    class FailedModel:
        name = "failed-model"
        supports_tools = False
        supports_thinking = False

        async def complete(self, messages, tools=None, system=None, temperature=0.0):
            raise PartialFailure("stream failed")

    run = Run(id="partial", model_info="failed-model")
    agent = Agent(FailedModel())
    with pytest.raises(PartialFailure):
        await agent._invoke(run, [{"role": "user", "content": "go"}], {})
    assert len(run.steps) == 1 and run.steps[0].kind == StepKind.error
    assert run.steps[0].cost == 0.25 and run.steps[0].usage["output"] == 2
    assert run.manifest["pricing"]["complete"] is False
