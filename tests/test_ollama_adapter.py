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
