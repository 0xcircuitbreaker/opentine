"""Ollama adapter contract tests.

These are provider-shape tests, not live model validation. They verify the
HTTP payload shape Opentine sends to Ollama's current /api/chat contract.
"""

from __future__ import annotations

from typing import Any

import pytest

from opentine.models.ollama import Ollama


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


def test_ollama_uses_tool_name_for_tool_results():
    adapter = Ollama("qwen3", think=True)
    payload = adapter._build_payload(
        [
            {"role": "user", "content": "Weather in Paris?"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"name": "get_weather", "arguments": {"city": "Paris"}}],
            },
            {
                "role": "tool",
                "name": "get_weather",
                "tool_call_id": "call_1",
                "content": "rain",
            },
        ],
        [_weather_schema()],
        "Answer briefly.",
        0.0,
        stream=False,
    )

    assert payload["model"] == "qwen3"
    assert payload["think"] is True
    assert payload["tools"][0]["function"]["name"] == "get_weather"
    assert payload["messages"][0] == {"role": "system", "content": "Answer briefly."}
    assert payload["messages"][2]["tool_calls"] == [
        {
            "type": "function",
            "function": {"name": "get_weather", "arguments": {"city": "Paris"}},
        }
    ]
    assert payload["messages"][3] == {
        "role": "tool",
        "content": "rain",
        "tool_name": "get_weather",
    }
    assert "name" not in payload["messages"][3]


def test_ollama_stream_payload_includes_tools_and_stream_flag():
    adapter = Ollama("llama3.1")
    payload = adapter._build_payload(
        [{"role": "user", "content": "Use a tool."}],
        [_weather_schema()],
        None,
        0.2,
        stream=True,
    )

    assert payload["stream"] is True
    assert payload["options"] == {"temperature": 0.2}
    assert payload["tools"][0]["type"] == "function"
    assert "think" not in payload


@pytest.mark.parametrize(
    ("model", "expected"),
    [("llama3.1", False), ("qwen3", True), ("deepseek-r1:8b", True), ("gpt-oss:20b", True)],
)
def test_ollama_thinking_capability_is_model_specific(model: str, expected: bool):
    assert Ollama(model).supports_thinking is expected


def test_supports_tools_reflects_show_capabilities(monkeypatch: pytest.MonkeyPatch):
    adapter = Ollama("gemma3:4b")
    monkeypatch.setattr(adapter, "_capabilities", {"completion", "vision"})
    assert adapter.supports_tools is False

    capable = Ollama("llama3.1:8b")
    monkeypatch.setattr(capable, "_capabilities", {"completion", "tools"})
    assert capable.supports_tools is True


def test_tools_capable_is_optimistic_when_probe_fails(monkeypatch: pytest.MonkeyPatch):
    adapter = Ollama("offline-model", host="http://127.0.0.1:1")
    # Real probe against an unreachable host: should not raise, stays optimistic.
    assert adapter.supports_tools is True


@pytest.mark.asyncio
async def test_complete_drops_tools_and_warns_for_incapable_model(
    monkeypatch: pytest.MonkeyPatch,
):
    adapter = Ollama("gemma3:4b")
    monkeypatch.setattr(adapter, "_capabilities", {"completion", "vision"})

    sent: dict[str, Any] = {}

    class FakeResp:
        def raise_for_status(self) -> None: ...

        def json(self) -> dict[str, Any]:
            return {"message": {"content": "42"}}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def post(self, url: str, json: dict[str, Any]):
            sent.update(json)
            return FakeResp()

    monkeypatch.setattr("opentine.models.ollama.httpx.AsyncClient", lambda *a, **k: FakeClient())

    result = await adapter.complete(
        [{"role": "user", "content": "What is 6 * 7?"}],
        tools=[_weather_schema()],
    )

    assert "tools" not in sent  # tools were dropped from the payload
    assert result["text"] == "42"
    assert result["warnings"] == [
        "ollama/gemma3:4b: model does not support tool calling; ran without tools"
    ]
