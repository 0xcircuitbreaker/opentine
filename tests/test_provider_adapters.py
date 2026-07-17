"""Provider adapter contract tests with fake SDK clients."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from opentine.models.anthropic import Anthropic
from opentine.models.compat import GLM, Kimi, LlamaCpp, LMStudio
from opentine.models.openai import OpenAI


def _weather_schema() -> dict[str, Any]:
    return {
        "name": "get_weather",
        "description": "Get weather.",
        "input_schema": {
            "type": "object",
            "required": ["city"],
            "properties": {"city": {"type": "string"}},
        },
    }


@pytest.mark.asyncio
async def test_openai_stream_payload_includes_tools_and_transcript(monkeypatch: pytest.MonkeyPatch):
    seen: dict[str, Any] = {}

    class FakeCompletions:
        async def create(self, **kwargs: Any):
            seen.update(kwargs)

            async def chunks():
                yield SimpleNamespace(
                    choices=[SimpleNamespace(delta=SimpleNamespace(content="ok"))]
                )

            return chunks()

    fake_client = SimpleNamespace(
        chat=SimpleNamespace(completions=FakeCompletions()),
    )
    adapter = OpenAI("gpt-test")
    client_calls = []

    def get_client():
        client_calls.append(fake_client)
        return fake_client

    monkeypatch.setattr(adapter, "_get_client", get_client)

    chunks = [
        chunk
        async for chunk in adapter.stream(
            [
                {"role": "user", "content": "Weather?"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"id": "call_1", "name": "get_weather", "arguments": {"city": "Paris"}}
                    ],
                },
                {
                    "role": "tool",
                    "name": "get_weather",
                    "tool_call_id": "call_1",
                    "content": "rain",
                },
            ],
            [_weather_schema()],
            system="Answer briefly.",
            temperature=0.2,
        )
    ]

    assert chunks[0] == {"type": "text_delta", "text": "ok"}
    assert chunks[1]["type"] == "usage"
    assert chunks[1]["billing"]["status"] == "unknown"
    assert seen["model"] == "gpt-test"
    assert seen["temperature"] == 0.2
    assert seen["stream"] is True
    assert seen["messages"][0] == {"role": "system", "content": "Answer briefly."}
    assert seen["messages"][2]["tool_calls"][0]["id"] == "call_1"
    assert seen["messages"][3] == {
        "role": "tool",
        "content": "rain",
        "tool_call_id": "call_1",
    }
    assert seen["tools"][0]["function"]["name"] == "get_weather"
    assert client_calls == [fake_client]


@pytest.mark.asyncio
async def test_anthropic_stream_payload_includes_tools_and_transcript(
    monkeypatch: pytest.MonkeyPatch,
):
    seen: dict[str, Any] = {}

    class FakeStream:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        def __aiter__(self):
            self._events = iter(
                [
                    SimpleNamespace(
                        type="content_block_delta",
                        delta=SimpleNamespace(text="ok"),
                    )
                ]
            )
            return self

        async def __anext__(self):
            try:
                return next(self._events)
            except StopIteration:
                raise StopAsyncIteration

    class FakeMessages:
        def stream(self, **kwargs: Any):
            seen.update(kwargs)
            return FakeStream()

    fake_client = SimpleNamespace(messages=FakeMessages())
    adapter = Anthropic("claude-test")
    monkeypatch.setattr(adapter, "_get_client", lambda: fake_client)

    chunks = [
        chunk
        async for chunk in adapter.stream(
            [
                {"role": "user", "content": "Weather?"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"id": "toolu_1", "name": "get_weather", "arguments": {"city": "Paris"}}
                    ],
                },
                {
                    "role": "tool",
                    "name": "get_weather",
                    "tool_call_id": "toolu_1",
                    "content": "rain",
                },
            ],
            [_weather_schema()],
            system="Answer briefly.",
            temperature=0.2,
        )
    ]

    assert chunks == [{"type": "text_delta", "text": "ok"}]
    assert seen["model"] == "claude-test"
    assert seen["temperature"] == 0.2
    assert seen["system"] == "Answer briefly."
    assert seen["tools"][0]["name"] == "get_weather"
    assert seen["messages"][1]["content"][0] == {
        "type": "tool_use",
        "id": "toolu_1",
        "name": "get_weather",
        "input": {"city": "Paris"},
    }
    assert seen["messages"][2]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "toolu_1",
        "content": "rain",
    }


def test_openai_compatible_wrappers_set_expected_endpoints():
    kimi = Kimi(api_key="k")
    assert kimi._base_url == "https://api.moonshot.ai/v1"
    assert kimi._model == "kimi-k3"
    assert kimi._api_key == "k"
    assert LMStudio(host="http://127.0.0.1:1234")._base_url == "http://127.0.0.1:1234/v1"
    assert LlamaCpp(host="http://127.0.0.1:8080")._api_key == "llama-cpp"

    glm = GLM(api_key="id.secret")
    assert glm._base_url == "https://open.bigmodel.cn/api/paas/v4"
    assert glm._provider == "glm-cn"
    assert len(glm._api_key.split(".")) == 3
    global_glm = GLM(api_key="opaque-global-key")
    assert global_glm._base_url == "https://api.z.ai/api/paas/v4"
    assert global_glm._provider == "glm"
    assert global_glm.supports_thinking and kimi.supports_thinking


def test_kimi_preserves_reasoning_continuation_without_tool_calls():
    converted = Kimi._build_messages(
        [
            {
                "role": "assistant",
                "content": "answer",
                "reasoning_content": "private continuation token",
            }
        ],
        None,
    )
    assert converted == [
        {
            "role": "assistant",
            "content": "answer",
            "reasoning_content": "private continuation token",
        }
    ]


def _fake_openai_client_with_usage() -> Any:
    class FakeCompletions:
        async def create(self, **kwargs: Any):
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="ok", tool_calls=None))],
                usage=SimpleNamespace(prompt_tokens=1_000_000, completion_tokens=1_000_000),
            )

    return SimpleNamespace(chat=SimpleNamespace(completions=FakeCompletions()))


@pytest.mark.asyncio
async def test_openai_default_cost_uses_gpt4o_pricing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    adapter = OpenAI("gpt-4o")
    clients = []

    def get_client():
        clients.append(_fake_openai_client_with_usage())
        return clients[-1]

    monkeypatch.setattr(adapter, "_get_client", get_client)
    resp = await adapter.complete([{"role": "user", "content": "hi"}])
    # 1M input @ $2.5 + 1M output @ $10 = $12.5
    assert resp["cost"] == pytest.approx(12.5)
    assert len(clients) == 1


@pytest.mark.asyncio
async def test_custom_openai_base_url_does_not_inherit_openai_pricing(
    monkeypatch: pytest.MonkeyPatch,
):
    adapter = OpenAI("gpt-4o", base_url="https://compatible.example/v1")
    monkeypatch.setattr(adapter, "_get_client", _fake_openai_client_with_usage)

    resp = await adapter.complete([{"role": "user", "content": "hi"}])

    assert adapter._provider == "openai-compatible"
    assert resp["billing"]["status"] == "unknown"
    assert resp["billing"]["amount_usd"] is None
    assert resp["cost"] == 0.0


@pytest.mark.asyncio
async def test_openai_base_url_environment_does_not_inherit_openai_pricing(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://compatible.example/v1")
    adapter = OpenAI("gpt-4o")
    monkeypatch.setattr(adapter, "_get_client", _fake_openai_client_with_usage)

    resp = await adapter.complete([{"role": "user", "content": "hi"}])

    assert adapter._provider == "openai-compatible"
    assert resp["billing"]["status"] == "unknown"
    assert resp["cost"] == 0.0


@pytest.mark.asyncio
async def test_custom_openai_base_url_honors_explicit_provider(
    monkeypatch: pytest.MonkeyPatch,
):
    adapter = OpenAI(
        "gpt-4o",
        base_url="https://openai-proxy.example/v1",
        provider="openai",
    )
    monkeypatch.setattr(adapter, "_get_client", _fake_openai_client_with_usage)

    resp = await adapter.complete([{"role": "user", "content": "hi"}])

    assert adapter._provider == "openai"
    assert resp["billing"]["status"] == "complete"
    assert resp["cost"] == pytest.approx(12.5)


@pytest.mark.asyncio
async def test_custom_openai_base_url_honors_explicit_rate_override(
    monkeypatch: pytest.MonkeyPatch,
):
    adapter = OpenAI(
        "gpt-4o",
        base_url="https://compatible.example/v1",
        rates={"input": "1.25", "output": "3.75"},
    )
    monkeypatch.setattr(adapter, "_get_client", _fake_openai_client_with_usage)

    resp = await adapter.complete([{"role": "user", "content": "hi"}])

    assert adapter._provider == "openai-compatible"
    assert resp["billing"]["status"] == "complete"
    assert resp["cost"] == pytest.approx(5.0)


@pytest.mark.asyncio
async def test_local_compat_wrappers_report_zero_cost(monkeypatch: pytest.MonkeyPatch):
    adapter = LMStudio()
    monkeypatch.setattr(adapter, "_get_client", _fake_openai_client_with_usage)
    resp = await adapter.complete([{"role": "user", "content": "hi"}])
    assert resp["cost"] == 0.0
