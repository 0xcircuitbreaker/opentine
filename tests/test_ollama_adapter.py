"""Ollama adapter contract tests.

These are provider-shape tests, not live model validation. They verify the
HTTP payload shape Opentine sends to Ollama's current /api/chat contract.
"""

from __future__ import annotations

import json
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


def test_capability_probe_ignores_proxies_and_redirects(monkeypatch: pytest.MonkeyPatch):
    options: dict[str, Any] = {}

    class Response:
        def raise_for_status(self): ...

        def iter_raw(self, **kwargs):
            yield b'{"capabilities":["tools"]}'

    class Stream:
        def __enter__(self):
            return Response()

        def __exit__(self, *exc):
            return None

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def stream(self, *args, **kwargs):
            return Stream()

    def factory(**kwargs):
        options.update(kwargs)
        return Client()

    monkeypatch.setattr("opentine.models.ollama.httpx.Client", factory)
    assert Ollama("qwen3").supports_tools is True
    assert options["trust_env"] is False and options["follow_redirects"] is False


@pytest.mark.asyncio
async def test_complete_drops_tools_and_warns_for_incapable_model(
    monkeypatch: pytest.MonkeyPatch,
):
    adapter = Ollama("gemma3:4b")
    monkeypatch.setattr(adapter, "_capabilities", {"completion", "vision"})

    sent: dict[str, Any] = {}
    client_options: dict[str, Any] = {}

    class FakeResp:
        def raise_for_status(self) -> None: ...

        async def aiter_raw(self, **kwargs):
            yield json.dumps({"message": {"content": "42"}}).encode()

    class FakeStream:
        async def __aenter__(self):
            return FakeResp()

        async def __aexit__(self, *exc):
            return None

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        def stream(self, method: str, url: str, json: dict[str, Any], **kwargs):
            sent.update(json)
            return FakeStream()

    def client_factory(*args, **kwargs):
        client_options.update(kwargs)
        return FakeClient()

    monkeypatch.setattr("opentine.models.ollama.httpx.AsyncClient", client_factory)

    result = await adapter.complete(
        [{"role": "user", "content": "What is 6 * 7?"}],
        tools=[_weather_schema()],
    )

    assert "tools" not in sent  # tools were dropped from the payload
    assert result["text"] == "42"
    assert result["warnings"] == [
        "ollama/gemma3:4b: model does not support tool calling; ran without tools"
    ]
    assert client_options["trust_env"] is False
    assert client_options["follow_redirects"] is False


def test_capability_probe_stops_at_response_limit(monkeypatch: pytest.MonkeyPatch):
    import opentine.models.ollama as module

    consumed = 0

    class Response:
        def raise_for_status(self): ...

        def iter_raw(self, **kwargs):
            nonlocal consumed
            for chunk in (b"12345", b"should-not-be-read"):
                consumed += 1
                yield chunk

    class Stream:
        def __enter__(self):
            return Response()

        def __exit__(self, *exc): ...

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *exc): ...

        def stream(self, *args, **kwargs):
            return Stream()

    monkeypatch.setattr(module._http, "MAX_SHOW_BYTES", 4)
    monkeypatch.setattr(module.httpx, "Client", lambda **kwargs: Client())
    assert Ollama("hostile", host="https://ollama.example").supports_tools is True
    assert consumed == 1


@pytest.mark.asyncio
async def test_complete_stops_at_response_limit(monkeypatch: pytest.MonkeyPatch):
    import opentine.models.ollama as module

    class Response:
        def raise_for_status(self): ...

        async def aiter_raw(self, **kwargs):
            yield b'{"message":{"content":"too large"}}'

    class Stream:
        async def __aenter__(self):
            return Response()

        async def __aexit__(self, *exc): ...

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc): ...

        def stream(self, *args, **kwargs):
            return Stream()

    monkeypatch.setattr(module._http, "MAX_CHAT_BYTES", 8)
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **kwargs: Client())
    with pytest.raises(ValueError, match="response exceeds size limit"):
        await Ollama("hostile", host="https://ollama.example").complete(
            [{"role": "user", "content": "hi"}]
        )


@pytest.mark.asyncio
async def test_stream_bounds_each_line_and_aggregate_body(monkeypatch: pytest.MonkeyPatch):
    from opentine.models import _ollama_http

    class Response:
        def __init__(self, chunks):
            self.chunks = chunks

        async def aiter_raw(self, **kwargs):
            for chunk in self.chunks:
                yield chunk

    monkeypatch.setattr(_ollama_http, "MAX_STREAM_LINE_BYTES", 8)
    monkeypatch.setattr(_ollama_http, "MAX_STREAM_BYTES", 64)
    with pytest.raises(ValueError, match="line exceeds size limit"):
        _ = [item async for item in _ollama_http.iter_ndjson(Response([b"x" * 9]))]

    monkeypatch.setattr(_ollama_http, "MAX_STREAM_LINE_BYTES", 32)
    monkeypatch.setattr(_ollama_http, "MAX_STREAM_BYTES", 8)
    with pytest.raises(ValueError, match="aggregate size limit"):
        _ = [item async for item in _ollama_http.iter_ndjson(Response([b"{}\n" * 3, b"{}\n"]))]


@pytest.mark.asyncio
async def test_stream_parser_handles_split_ndjson_without_aiter_lines():
    from opentine.models._ollama_http import iter_ndjson

    class Response:
        async def aiter_raw(self, **kwargs):
            for chunk in (b'{"message":', b'{"content":"ok"}}\n', b'{"done":true}'):
                yield chunk

    assert [item async for item in iter_ndjson(Response())] == [
        {"message": {"content": "ok"}},
        {"done": True},
    ]
