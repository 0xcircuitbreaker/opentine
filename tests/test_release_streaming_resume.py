"""Final regressions for streamed semantics and resumable client recovery."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from opentine.models import _streaming
from opentine.models._responses import ResponsesTransport, parse_response
from opentine.models._stream_content import (
    OllamaStreamState,
    anthropic_content,
    chat_content,
    google_content,
)
from opentine.models._streaming import ChatStreamState, SizeBudget, WarningList
from opentine.models._usage import google_usage, openai_usage
from opentine.models.anthropic import Anthropic
from opentine.models.compat import Kimi
from opentine.models.google import Google
from opentine.models.ollama import Ollama
from opentine.models.openai import OpenAI
from opentine.repository import Repo
from opentine.repository.client import _upload
from opentine.repository.pack import inspect_pack, minimum_upload_chunk


@pytest.mark.asyncio
async def test_chat_stream_retains_tool_reasoning_refusal_and_usage(monkeypatch):
    async def chunks():
        yield SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(
                        reasoning_content="checking",
                        refusal="policy ",
                        tool_calls=[
                            SimpleNamespace(
                                index=0,
                                id="call_1",
                                function=SimpleNamespace(name="weather", arguments='{"city":'),
                            )
                        ],
                    )
                )
            ]
        )
        yield SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(
                        refusal="refusal",
                        tool_calls=[
                            SimpleNamespace(
                                index=0,
                                function=SimpleNamespace(arguments='"Paris"}'),
                            )
                        ],
                    )
                )
            ]
        )
        yield SimpleNamespace(
            choices=[],
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=4),
        )

    class Completions:
        async def create(self, **kwargs):
            return chunks()

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    adapter = OpenAI("compat-model", base_url="https://compat.example/v1")
    monkeypatch.setattr(adapter, "_get_client", lambda: client)

    events = [event async for event in adapter.stream([{"role": "user", "content": "go"}])]
    assert adapter._provider == "openai-compatible"
    final = events[-1]
    assert final["type"] == "response" and final["text"] == ""
    assert final["tool_calls"] == [
        {"name": "weather", "arguments": {"city": "Paris"}, "id": "call_1"}
    ]
    assert final["reasoning_content"] == "checking"
    assert final["refusal"] == "policy refusal"
    assert final["usage"]["total"] == 14 and "billing" in final


@pytest.mark.asyncio
async def test_kimi_stream_reads_final_choice_usage(monkeypatch):
    async def chunks():
        yield SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(content="ok"),
                    usage=SimpleNamespace(prompt_tokens=11, completion_tokens=3),
                )
            ]
        )

    class Completions:
        async def create(self, **kwargs):
            return chunks()

    adapter = Kimi()
    monkeypatch.setattr(
        adapter,
        "_get_client",
        lambda: SimpleNamespace(chat=SimpleNamespace(completions=Completions())),
    )
    events = [event async for event in adapter.stream([{"role": "user", "content": "go"}])]
    assert events[0] == {"type": "text_delta", "text": "ok"}
    assert events[1]["type"] == "usage"
    assert events[1]["usage"]["input"] == 11 and events[1]["usage"]["output"] == 3
    assert events[1]["billing"]["status"] == "complete"


@pytest.mark.asyncio
async def test_missing_wire_usage_is_explicitly_unknown_for_complete_and_stream(monkeypatch):
    async def chunks():
        yield SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="ok"))])

    class Completions:
        async def create(self, **kwargs):
            if kwargs.get("stream"):
                return chunks()
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))])

    adapter = OpenAI("compat-model", base_url="https://compat.example/v1")
    monkeypatch.setattr(
        adapter,
        "_get_client",
        lambda: SimpleNamespace(chat=SimpleNamespace(completions=Completions())),
    )
    complete = await adapter.complete([{"role": "user", "content": "go"}])
    events = [event async for event in adapter.stream([{"role": "user", "content": "go"}])]
    assert complete["billing"]["status"] == "unknown"
    assert events[-1]["type"] == "usage" and events[-1]["billing"]["status"] == "unknown"
    assert ResponsesTransport(model="gpt-5.6").meter(SimpleNamespace())["billing"]["status"] == (
        "unknown"
    )
    assert Google("gemini-test")._meter(None)["billing"]["status"] == "unknown"
    assert Anthropic("claude-test")._meter(SimpleNamespace())["billing"]["status"] == "unknown"
    assert Ollama("qwen3")._meter({})["billing"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_anthropic_stream_uses_final_tool_thinking_and_refusal_billing(monkeypatch):
    response = SimpleNamespace(
        content=[
            SimpleNamespace(type="thinking", thinking="considered"),
            SimpleNamespace(type="tool_use", name="weather", input={"city": "Paris"}, id="t1"),
            SimpleNamespace(type="refusal", refusal="declined"),
        ],
        stop_reason="refusal",
        usage=SimpleNamespace(input_tokens=10, output_tokens=3),
    )

    class Stream:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        def __aiter__(self):
            async def events():
                yield SimpleNamespace(
                    type="content_block_delta",
                    delta=SimpleNamespace(thinking="considered"),
                )

            return events()

        async def get_final_message(self):
            return response

    adapter = Anthropic("claude-test")
    monkeypatch.setattr(
        adapter,
        "_get_client",
        lambda: SimpleNamespace(messages=SimpleNamespace(stream=lambda **kwargs: Stream())),
    )
    events = [event async for event in adapter.stream([{"role": "user", "content": "go"}])]
    final = events[-1]
    assert final["type"] == "response"
    assert final["tool_calls"][0]["id"] == "t1"
    assert final["reasoning_content"] == "considered"
    assert final["refusal"] == "declined"
    assert final["usage"]["total"] == 13 and "billing" in final


@pytest.mark.asyncio
async def test_google_stream_retains_function_call_thought_refusal_and_usage(monkeypatch):
    function = SimpleNamespace(name="weather", args={"city": "Paris"}, id="g1")
    chunk = SimpleNamespace(
        candidates=[
            SimpleNamespace(
                content=SimpleNamespace(
                    parts=[
                        SimpleNamespace(text="considered", thought=True),
                        SimpleNamespace(function_call=function),
                    ]
                ),
                finish_reason="SAFETY",
            )
        ],
        usage_metadata=SimpleNamespace(
            prompt_token_count=10, candidates_token_count=2, total_token_count=12
        ),
    )

    async def chunks():
        yield chunk

    class Models:
        async def generate_content_stream(self, **kwargs):
            return chunks()

    adapter = Google("gemini-test")
    monkeypatch.setattr(adapter, "_request", lambda *args: ([], object()))
    monkeypatch.setattr(
        adapter, "_get_client", lambda: SimpleNamespace(aio=SimpleNamespace(models=Models()))
    )
    events = [event async for event in adapter.stream([{"role": "user", "content": "go"}])]
    final = events[-1]
    assert final["type"] == "response" and final["text"] == ""
    assert final["tool_calls"] == [{"name": "weather", "arguments": {"city": "Paris"}, "id": "g1"}]
    assert final["reasoning_content"] == "considered"
    assert final["refusal"] == "SAFETY"
    assert final["usage"]["total"] == 12 and "billing" in final


@pytest.mark.asyncio
async def test_ollama_stream_retains_tool_thinking_refusal_and_final_metrics(monkeypatch):
    lines = [
        json.dumps(
            {
                "message": {
                    "thinking": "considered",
                    "refusal": "declined",
                    "tool_calls": [
                        {
                            "id": "o1",
                            "function": {"name": "weather", "arguments": {"city": "Paris"}},
                        }
                    ],
                }
            }
        ),
        json.dumps(
            {
                "done": True,
                "message": {},
                "prompt_eval_count": 10,
                "eval_count": 2,
                "total_duration": 1_000_000_000,
            }
        ),
    ]

    class Response:
        def raise_for_status(self):
            return None

        async def aiter_raw(self, **kwargs):
            for line in lines:
                yield line.encode() + b"\n"

    class StreamContext:
        async def __aenter__(self):
            return Response()

        async def __aexit__(self, *exc):
            return None

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        def stream(self, *args, **kwargs):
            return StreamContext()

    monkeypatch.setattr("opentine.models.ollama.httpx.AsyncClient", lambda **kwargs: Client())
    events = [event async for event in Ollama("qwen3").stream([{"role": "user", "content": "go"}])]
    final = events[-1]
    assert final["type"] == "response" and final["thinking"] == "considered"
    assert final["refusal"] == "declined" and final["tool_calls"][0]["id"] == "o1"
    assert final["usage"]["total"] == 12 and final["metrics"]["total_duration"] == 1_000_000_000


def test_stream_accumulators_bound_untrusted_provider_output(monkeypatch):
    monkeypatch.setattr(_streaming, "MAX_STREAM_CHARS", 8)
    chat = ChatStreamState()
    chat.add(SimpleNamespace(content="x" * 32))
    chat.add(
        SimpleNamespace(
            tool_calls=[
                SimpleNamespace(
                    index=0,
                    function=SimpleNamespace(name="tool", arguments='{"value":"too long"}'),
                )
            ]
        )
    )
    chat_result = chat.result()
    assert chat_result["text"] == "x" * 8
    assert chat_result["tool_calls"][0]["arguments"] == {"_truncated": True}
    assert any("truncated" in warning for warning in chat_result["warnings"])

    anthropic = anthropic_content(
        SimpleNamespace(content=[SimpleNamespace(type="text", text="a" * 32)])
    )
    assert anthropic["text"] == "a" * 8 and anthropic["warnings"]

    google = google_content(
        SimpleNamespace(
            candidates=[
                SimpleNamespace(content=SimpleNamespace(parts=[SimpleNamespace(text="g" * 32)]))
            ]
        )
    )
    assert google["text"] == "g" * 8 and google["warnings"]

    google_budget = SizeBudget()

    def function_chunk(value):
        return SimpleNamespace(
            candidates=[
                SimpleNamespace(
                    content=SimpleNamespace(
                        parts=[SimpleNamespace(function_call=SimpleNamespace(name="f", args=value))]
                    )
                )
            ]
        )

    google_content(function_chunk({"a": "1234"}), google_budget)
    bounded_google = google_content(function_chunk({"b": "4567"}), google_budget)
    assert bounded_google["tool_calls"][0]["arguments"] == {"_truncated": True}

    complete_chat = chat_content(SimpleNamespace(content="c" * 32, tool_calls=[], refusal="r" * 32))
    assert complete_chat["text"] == "c" * 8 and complete_chat["refusal"] == "r" * 8
    responses = parse_response(SimpleNamespace(output=[], output_text="z" * 32))
    assert responses["text"] == "z" * 8 and responses["warnings"]

    warnings: list[str] = []
    ollama = OllamaStreamState(warnings)
    assert ollama.add({"content": "o" * 32}) == [{"type": "text_delta", "text": "o" * 32}]
    assert ollama.message()["content"] == "o" * 8 and warnings

    warning_list = WarningList()
    for index in range(10_000):
        warning_list.extend(["duplicate", f"unique-{index}"])
    assert len(warning_list) == _streaming.MAX_STREAM_WARNINGS
    assert warning_list.count("duplicate") == 1

    noisy_chat = ChatStreamState()
    noisy_delta = SimpleNamespace(
        tool_calls=[SimpleNamespace(index=0, id="i" * 5000, function=SimpleNamespace())]
    )
    for _ in range(1000):
        noisy_chat.add(noisy_delta)
    assert noisy_chat.warnings == ["streamed tool call id truncated at 4096 characters"]


@pytest.mark.parametrize("value", [True, 1.5, -1, 10**20 + 1, "10"])
def test_provider_usage_rejects_lossy_or_unsafe_token_counters(value):
    with pytest.raises(ValueError, match="safe integer"):
        openai_usage(SimpleNamespace(prompt_tokens=value, completion_tokens=0))


def test_provider_usage_rejects_impossible_sub_bucket_totals():
    with pytest.raises(ValueError, match="sub-buckets"):
        openai_usage(
            SimpleNamespace(
                prompt_tokens=10,
                completion_tokens=2,
                prompt_tokens_details=SimpleNamespace(cached_tokens=11),
            )
        )
    with pytest.raises(ValueError, match="reasoning"):
        openai_usage(
            SimpleNamespace(
                prompt_tokens=1,
                completion_tokens=2,
                completion_tokens_details=SimpleNamespace(reasoning_tokens=3),
            )
        )
    with pytest.raises(ValueError, match="cache/audio"):
        google_usage(SimpleNamespace(prompt_token_count=10, cached_content_token_count=11))


def _pack(tmp_path) -> bytes:
    repo = Repo.init(tmp_path)
    repo.put("blob", b"resumable", redact=False)
    return repo.pack()


def test_upload_recovers_offset_from_bodyless_head_after_transport_loss(tmp_path):
    data = _pack(tmp_path / "repo")
    chunk_size = max(minimum_upload_chunk(len(data)), len(data) // 2)
    accepted = 0
    methods: list[str] = []
    expected_id, expected_objects, _ = inspect_pack(data)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal accepted
        methods.append(request.method)
        if request.method == "POST":
            return httpx.Response(201, json={"offset": 0, "upload_id": "a" * 32})
        if request.method == "HEAD":
            return httpx.Response(200, headers={"Upload-Offset": str(accepted)})
        chunk = request.content
        accepted += len(chunk)
        if methods.count("PATCH") == 1:
            raise httpx.ReadError("ack lost", request=request)
        return httpx.Response(
            201,
            json={"offset": accepted, "objects": len(expected_objects), "pack_id": expected_id},
        )

    with httpx.Client(
        base_url="https://remote.example", transport=httpx.MockTransport(handler)
    ) as client:
        result = _upload(client, "/packs", data, chunk_size=chunk_size)
    assert methods[:3] == ["POST", "PATCH", "HEAD"]
    assert result["offset"] == len(data) and result["pack_id"] == expected_id


def test_upload_fails_closed_when_final_ack_and_server_resume_state_are_lost(tmp_path):
    data = _pack(tmp_path / "repo-final")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"offset": 0, "upload_id": "b" * 32})
        if request.method == "HEAD":
            return httpx.Response(404)
        raise httpx.ReadError("final ack lost", request=request)

    with httpx.Client(
        base_url="https://remote.example", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ValueError, match="lost resumable upload state"):
            _upload(client, "/packs", data, chunk_size=len(data))
