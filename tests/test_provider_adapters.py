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

    assert chunks == [{"type": "text_delta", "text": "ok"}]
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
    assert Kimi(api_key="k")._base_url == "https://api.moonshot.cn/v1"
    assert Kimi(api_key="k")._api_key == "k"
    assert LMStudio(host="http://127.0.0.1:1234")._base_url == "http://127.0.0.1:1234/v1"
    assert LlamaCpp(host="http://127.0.0.1:8080")._api_key == "llama-cpp"

    glm = GLM(api_key="id.secret")
    assert glm._base_url == "https://open.bigmodel.cn/api/paas/v4"
    assert len(glm._api_key.split(".")) == 3
