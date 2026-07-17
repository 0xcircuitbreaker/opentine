"""Google adapter contract tests with a fake google-genai SDK."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from opentine.models.google import Google


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


def _install_fake_google_genai(monkeypatch: pytest.MonkeyPatch) -> None:
    google_module = ModuleType("google")
    genai_module = ModuleType("google.genai")

    class GenerateContentConfig:
        def __init__(self, temperature: float):
            self.temperature = temperature

    class FunctionDeclaration:
        def __init__(self, name: str, description: str, parameters: dict[str, Any]):
            self.name = name
            self.description = description
            self.parameters = parameters

    class Tool:
        def __init__(self, function_declarations: list[FunctionDeclaration]):
            self.function_declarations = function_declarations

    class Part:
        @staticmethod
        def from_text(text: str) -> dict[str, Any]:
            return {"text": text}

        @staticmethod
        def from_function_response(name: str, response: dict[str, Any]) -> dict[str, Any]:
            return {"function_response": {"name": name, "response": response}}

        @staticmethod
        def from_function_call(name: str, args: dict[str, Any]) -> dict[str, Any]:
            return {"function_call": {"name": name, "args": args}}

    class Content:
        def __init__(self, role: str, parts: list[Any]):
            self.role = role
            self.parts = parts

    genai_module.types = SimpleNamespace(
        GenerateContentConfig=GenerateContentConfig,
        FunctionDeclaration=FunctionDeclaration,
        Tool=Tool,
        Part=Part,
        Content=Content,
    )
    google_module.genai = genai_module

    monkeypatch.setitem(sys.modules, "google", google_module)
    monkeypatch.setitem(sys.modules, "google.genai", genai_module)


@pytest.mark.asyncio
async def test_google_stream_payload_includes_tools(monkeypatch: pytest.MonkeyPatch):
    _install_fake_google_genai(monkeypatch)
    seen: dict[str, Any] = {}

    class FakeModels:
        async def generate_content_stream(
            self,
            *,
            model: str,
            contents: list[Any],
            config: Any,
        ):
            seen["model"] = model
            seen["contents"] = contents
            seen["config"] = config

            async def chunks():
                yield SimpleNamespace(text="ok")

            return chunks()

    fake_client = SimpleNamespace(aio=SimpleNamespace(models=FakeModels()))
    adapter = Google("gemini-test")
    monkeypatch.setattr(adapter, "_get_client", lambda: fake_client)

    chunks = [
        chunk
        async for chunk in adapter.stream(
            [{"role": "user", "content": "Use a tool."}],
            [_weather_schema()],
            system="Answer briefly.",
            temperature=0.2,
        )
    ]

    assert chunks[0] == {"type": "text_delta", "text": "ok"}
    assert chunks[1]["type"] == "usage"
    assert chunks[1]["billing"]["status"] == "unknown"
    assert seen["model"] == "gemini-test"
    assert seen["config"].temperature == 0.2
    assert seen["config"].system_instruction == "Answer briefly."
    assert seen["config"].tools[0].function_declarations[0].name == "get_weather"
