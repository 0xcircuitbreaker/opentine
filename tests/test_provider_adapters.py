"""Provider adapter contract tests with fake SDK clients."""

from __future__ import annotations

import base64
import json
import sys
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest

from opentine.models._stream_content import anthropic_content, chat_content, google_content
from opentine.models._streaming import ChatStreamState
from opentine.models.anthropic import Anthropic
from opentine.models.compat import (
    GLM,
    DeepSeek,
    Groq,
    Kimi,
    LlamaCpp,
    LMStudio,
    LocalOpenAICompatible,
    Mistral,
    OpenAICompatible,
)
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
async def test_provider_cleanup_failure_does_not_erase_billable_response(
    monkeypatch: pytest.MonkeyPatch,
):
    client = _fake_openai_client_with_usage()

    async def broken_close():
        raise OSError("transport cleanup failed")

    client.close = broken_close
    adapter = OpenAI("gpt-4o", base_url="https://compatible.example/v1")
    monkeypatch.setattr(adapter, "_get_client", lambda: client)
    with pytest.warns(ResourceWarning, match="cleanup failed"):
        response = await adapter.complete([{"role": "user", "content": "hello"}])
    assert response["usage"]["total"] == 2_000_000


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

    assert chunks[0] == {"type": "text_delta", "text": "ok"}
    assert chunks[-1]["type"] == "response"
    assert "without a final message" in chunks[-1]["refusal"]
    assert chunks[-1]["billing"]["status"] == "unknown"
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
    assert glm._api_key == "id.secret"
    jwt = glm._client_api_key()
    assert len(jwt.split(".")) == 3
    payload = jwt.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims["timestamp"] > 1_000_000_000_000
    assert claims["exp"] - claims["timestamp"] == 3_600_000
    assert "temperature" not in glm._kwargs([], None, None, 0.0)
    global_glm = GLM(api_key="opaque-global-key")
    assert global_glm._base_url == "https://api.z.ai/api/paas/v4"
    assert global_glm._provider == "glm"
    assert global_glm.supports_thinking and kimi.supports_thinking


def test_local_compatible_exact_urls_auth_and_capabilities():
    secured = LMStudio(host="http://127.0.0.1:1234/v1", api_key="local-secret")
    assert secured._base_url == "http://127.0.0.1:1234/v1"
    assert secured._api_key == "local-secret"

    webui = LocalOpenAICompatible(
        "loaded-model",
        base_url="http://localhost:3000/api/",
        api_key="webui-secret",
        supports_tools=False,
        extra_body={"chat_template_kwargs": {"enable_thinking": True}},
    )
    kwargs = webui._kwargs(
        [{"role": "user", "content": "hello"}],
        [_weather_schema()],
        None,
        0.0,
    )
    assert webui._base_url == "http://localhost:3000/api"
    assert webui._unmetered is True
    assert webui.supports_tools is False
    assert "tools" not in kwargs
    assert kwargs["extra_body"] == {"chat_template_kwargs": {"enable_thinking": True}}

    hosted_proxy = OpenAICompatible(
        "provider/model",
        base_url="https://proxy.example/openai",
        api_key="proxy-secret",
    )
    assert hosted_proxy._unmetered is False
    priced_local = LocalOpenAICompatible(
        "local-model",
        base_url="http://localhost:8000/v1",
        rates={"input": "1", "output": "2"},
    )
    assert priced_local._unmetered is False
    with pytest.raises(ValueError, match="host or exact base_url"):
        LocalOpenAICompatible(
            "model",
            host="http://localhost:8000",
            base_url="http://localhost:8000/v1",
        )


@pytest.mark.asyncio
async def test_compatible_clients_disable_ambient_proxy_and_redirects(
    monkeypatch: pytest.MonkeyPatch,
):
    class FakeTransport:
        def __init__(self, **kwargs: Any):
            self._trust_env = kwargs["trust_env"]
            self.follow_redirects = kwargs["follow_redirects"]

    class FakeClient:
        def __init__(self, **kwargs: Any):
            self._client = kwargs["http_client"]
            self.max_retries = kwargs["max_retries"]

        async def close(self):
            return None

    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(
            AsyncOpenAI=FakeClient,
            DefaultAsyncHttpxClient=FakeTransport,
        ),
    )
    for adapter in (
        OpenAICompatible("model", base_url="http://localhost:8000/v1"),
        OpenAI("model", base_url="http://localhost:8000/v1"),
    ):
        client = adapter._get_client()
        try:
            transport = client._client
            assert transport._trust_env is False
            assert transport.follow_redirects is False
            assert client.max_retries == 0
        finally:
            await client.close()


def test_custom_openai_base_does_not_forward_ambient_openai_key(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-live-must-not-leak")
    monkeypatch.delenv("OPENAI_COMPAT_API_KEY", raising=False)
    assert OpenAI("local", base_url="http://localhost:8000/v1")._api_key == ""

    monkeypatch.setenv("OPENAI_COMPAT_API_KEY", "local-proxy-key")
    assert OpenAI("local", base_url="http://localhost:8000/v1")._api_key == "local-proxy-key"
    assert OpenAI()._api_key == "sk-live-must-not-leak"
    assert OpenAI()._model == "gpt-5.6"


def test_kimi_accepts_official_moonshot_environment_names(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("KIMI_API_KEY", raising=False)
    monkeypatch.delenv("KIMI_BASE_URL", raising=False)
    monkeypatch.setenv("MOONSHOT_API_KEY", "moonshot-key")
    monkeypatch.setenv("MOONSHOT_BASE_URL", "https://moonshot-proxy.example/v1")
    adapter = Kimi()
    assert adapter._api_key == "moonshot-key"
    assert adapter._base_url == "https://moonshot-proxy.example/v1"


@pytest.mark.asyncio
async def test_deepseek_stream_requests_final_usage(monkeypatch: pytest.MonkeyPatch):
    seen: dict[str, Any] = {}

    class FakeCompletions:
        async def create(self, **kwargs: Any):
            seen.update(kwargs)

            async def chunks():
                if False:
                    yield None

            return chunks()

    adapter = DeepSeek(api_key="key")
    client = SimpleNamespace(chat=SimpleNamespace(completions=FakeCompletions()))
    monkeypatch.setattr(adapter, "_get_client", lambda: client)
    list([event async for event in adapter.stream([{"role": "user", "content": "hi"}])])
    assert seen["stream_options"] == {"include_usage": True}


@pytest.mark.asyncio
async def test_groq_stream_requests_and_reads_extension_usage(monkeypatch: pytest.MonkeyPatch):
    seen: dict[str, Any] = {}

    class FakeCompletions:
        async def create(self, **kwargs: Any):
            seen.update(kwargs)

            async def chunks():
                yield SimpleNamespace(
                    choices=[],
                    x_groq=SimpleNamespace(
                        usage=SimpleNamespace(prompt_tokens=1_000_000, completion_tokens=0)
                    ),
                )

            return chunks()

    adapter = Groq(api_key="key")
    client = SimpleNamespace(chat=SimpleNamespace(completions=FakeCompletions()))
    monkeypatch.setattr(adapter, "_get_client", lambda: client)
    events = [event async for event in adapter.stream([{"role": "user", "content": "hi"}])]

    assert seen["stream_options"] == {"include_usage": True}
    assert events[0]["type"] == "usage"
    assert events[0]["usage"]["input"] == 1_000_000
    assert events[0]["billing"]["status"] == "complete"
    assert Decimal(events[0]["billing"]["known_subtotal_usd"]) > 0


def test_together_reasoning_field_is_normalized_for_complete_and_stream():
    complete = chat_content(SimpleNamespace(content="answer", reasoning="thinking"))
    assert complete["text"] == "answer"
    assert complete["reasoning_content"] == "thinking"

    state = ChatStreamState()
    assert state.add(SimpleNamespace(content=None, reasoning="think")) == [
        {"type": "reasoning_delta", "text": "think"}
    ]
    assert state.result()["reasoning_content"] == "think"


def test_mistral_list_reasoning_is_preserved_and_replayable():
    blocks = [
        SimpleNamespace(
            type="thinking",
            thinking=[SimpleNamespace(type="text", text="private thought")],
        ),
        SimpleNamespace(type="text", text="public answer"),
    ]
    complete = chat_content(SimpleNamespace(content=blocks))
    assert complete["text"] == "public answer"
    assert complete["reasoning_content"] == "private thought"
    assert complete["content_blocks"] == [
        {"type": "thinking", "thinking": [{"type": "text", "text": "private thought"}]},
        {"type": "text", "text": "public answer"},
    ]
    replay = Mistral._build_messages(
        [
            {
                "role": "assistant",
                "content": complete["text"],
                "content_blocks": complete["content_blocks"],
                "reasoning_content": complete["reasoning_content"],
            }
        ],
        None,
    )
    assert replay == [{"role": "assistant", "content": complete["content_blocks"]}]

    state = ChatStreamState()
    events = state.add(SimpleNamespace(content=blocks))
    assert {event["type"] for event in events} == {"text_delta", "reasoning_delta"}
    assert state.result()["content_blocks"] == complete["content_blocks"]
    request = Mistral(reasoning_effort="high")._kwargs([], None, None, 0.0)
    assert request["reasoning_effort"] == "high"
    with pytest.raises(ValueError, match="reasoning_effort"):
        Mistral(reasoning_effort="maximum")


def test_mistral_reasoning_block_count_is_aggregate_bounded():
    nested = [SimpleNamespace(type="text", text="") for _ in range(2_000)]
    parsed = chat_content(
        SimpleNamespace(
            content=[SimpleNamespace(type="thinking", thinking=nested)],
        )
    )
    assert len(parsed["content_blocks"][0]["thinking"]) == 1_023
    assert parsed["warnings"] == ["Chat content blocks truncated at 1024 blocks"]


def test_anthropic_signed_thinking_blocks_are_replayed_exactly():
    raw = [
        SimpleNamespace(type="thinking", thinking="", signature="signed-empty-thought"),
        SimpleNamespace(type="redacted_thinking", data="opaque-redacted-data"),
        SimpleNamespace(type="tool_use", id="a1", name="weather", input={"city": "Paris"}),
    ]
    parsed = anthropic_content(SimpleNamespace(content=raw))
    expected = [
        {"type": "thinking", "thinking": "", "signature": "signed-empty-thought"},
        {"type": "redacted_thinking", "data": "opaque-redacted-data"},
        {"type": "tool_use", "id": "a1", "name": "weather", "input": {"city": "Paris"}},
    ]
    assert parsed["anthropic_content"] == expected
    converted = Anthropic._convert_messages(
        [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": parsed["tool_calls"],
                "anthropic_content": parsed["anthropic_content"],
            }
        ]
    )
    assert converted == [{"role": "assistant", "content": expected}]


def test_google_response_normalizes_opaque_signature_and_call_id():
    part = SimpleNamespace(
        thought=True,
        thought_signature=b"opaque-google-signature",
        function_call=SimpleNamespace(id="g1", name="weather", args={"city": "Paris"}),
    )
    response = SimpleNamespace(candidates=[SimpleNamespace(content=SimpleNamespace(parts=[part]))])
    parsed = google_content(response)
    assert parsed["tool_calls"][0]["id"] == "g1"
    assert parsed["google_content"] == [
        {
            "thought": True,
            "thought_signature": "b3BhcXVlLWdvb2dsZS1zaWduYXR1cmU=",
            "function_call": {
                "id": "g1",
                "name": "weather",
                "args": {"city": "Paris"},
            },
        }
    ]


def test_missing_provider_call_ids_remain_absent_for_runtime_synthesis():
    assert (
        chat_content(
            SimpleNamespace(
                content="",
                tool_calls=[
                    SimpleNamespace(id=None, function=SimpleNamespace(name="x", arguments="{}"))
                ],
            )
        )["tool_calls"][0]["id"]
        is None
    )
    assert (
        anthropic_content(
            SimpleNamespace(content=[SimpleNamespace(type="tool_use", id=None, name="x", input={})])
        )["tool_calls"][0]["id"]
        is None
    )
    assert (
        google_content(
            SimpleNamespace(
                candidates=[
                    SimpleNamespace(
                        content=SimpleNamespace(
                            parts=[
                                SimpleNamespace(
                                    function_call=SimpleNamespace(id=None, name="x", args={})
                                )
                            ]
                        )
                    )
                ]
            )
        )["tool_calls"][0]["id"]
        is None
    )


def test_anthropic_adaptive_thinking_and_service_tier_rules():
    kwargs = Anthropic("claude-opus-4-8", service_tier="standard_only")._kwargs([], None, None, 0.7)
    assert kwargs["thinking"] == {"type": "adaptive"}
    assert "temperature" not in kwargs
    with pytest.raises(ValueError, match="service_tier"):
        Anthropic("claude-sonnet-5", service_tier="priority")


def test_chat_stream_reasoning_blocks_use_one_aggregate_count():
    state = ChatStreamState()
    nested = [SimpleNamespace(type="text", text="") for _ in range(1_023)]
    state.add(SimpleNamespace(content=[SimpleNamespace(type="thinking", thinking=nested)]))
    state.add(SimpleNamespace(content=[SimpleNamespace(type="thinking", thinking=nested)]))
    result = state.result()
    assert len(result["content_blocks"]) == 1
    assert result["warnings"] == ["Chat content blocks truncated at 1024 blocks"]


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
@pytest.mark.parametrize(
    ("legacy_rates", "known"),
    [
        ({"input_cost_per_mtok": 1.25}, 1.25),
        ({"output_cost_per_mtok": 3.75}, 3.75),
    ],
)
async def test_partial_legacy_rate_override_never_makes_omitted_dimensions_free(
    monkeypatch: pytest.MonkeyPatch,
    legacy_rates: dict[str, float],
    known: float,
):
    adapter = OpenAI(
        "custom-model",
        base_url="https://compatible.example/v1",
        **legacy_rates,
    )
    monkeypatch.setattr(adapter, "_get_client", _fake_openai_client_with_usage)
    response = await adapter.complete([{"role": "user", "content": "hi"}])
    assert response["billing"]["status"] == "partial"
    assert response["billing"]["amount_usd"] is None
    assert response["cost"] == pytest.approx(known)


@pytest.mark.asyncio
async def test_local_compat_wrappers_report_zero_cost(monkeypatch: pytest.MonkeyPatch):
    adapter = LMStudio()
    monkeypatch.setattr(adapter, "_get_client", _fake_openai_client_with_usage)
    resp = await adapter.complete([{"role": "user", "content": "hi"}])
    assert resp["cost"] == 0.0
