"""Google Gemini adapter via google-genai SDK."""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any


class Google:
    """Adapter for Google Gemini models."""

    def __init__(self, model: str = "gemini-2.0-flash", api_key: str | None = None):
        self._model = model
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")

    @property
    def name(self) -> str:
        return self._model

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        return "thinking" in self._model

    def _get_client(self):
        try:
            from google import genai
        except ImportError:
            raise ImportError("pip install opentine[google]")
        return genai.Client(api_key=self._api_key)

    def _build_tools(self, tools: list[dict[str, Any]] | None):
        if not tools:
            return None
        try:
            from google.genai import types
        except ImportError:
            raise ImportError("pip install opentine[google]")
        declarations = []
        for t in tools:
            declarations.append(types.FunctionDeclaration(
                name=t["name"], description=t["description"],
                parameters=t["input_schema"],
            ))
        return [types.Tool(function_declarations=declarations)]

    async def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                       system: str | None = None, temperature: float = 0.0) -> dict[str, Any]:
        client = self._get_client()
        try:
            from google.genai import types
        except ImportError:
            raise ImportError("pip install opentine[google]")

        contents = []
        for m in messages:
            role = "model" if m["role"] == "assistant" else "user"
            contents.append(types.Content(role=role, parts=[types.Part.from_text(text=m["content"])]))

        config = types.GenerateContentConfig(temperature=temperature)
        if system:
            config.system_instruction = system
        gemini_tools = self._build_tools(tools)
        if gemini_tools:
            config.tools = gemini_tools

        resp = await client.aio.models.generate_content(
            model=self._model, contents=contents, config=config,
        )

        text = resp.text or ""
        tool_calls = []
        if resp.candidates and resp.candidates[0].content:
            for part in resp.candidates[0].content.parts:
                if part.function_call:
                    tool_calls.append({"name": part.function_call.name,
                                       "arguments": dict(part.function_call.args or {})})
        return {"text": text, "tool_calls": tool_calls, "cost": 0.0}

    async def stream(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                     system: str | None = None, temperature: float = 0.0) -> AsyncIterator[dict[str, Any]]:
        client = self._get_client()
        try:
            from google.genai import types
        except ImportError:
            raise ImportError("pip install opentine[google]")

        contents = []
        for m in messages:
            role = "model" if m["role"] == "assistant" else "user"
            contents.append(types.Content(role=role, parts=[types.Part.from_text(text=m["content"])]))

        config = types.GenerateContentConfig(temperature=temperature)
        if system:
            config.system_instruction = system

        async for chunk in await client.aio.models.generate_content_stream(
            model=self._model, contents=contents, config=config,
        ):
            if chunk.text:
                yield {"type": "text_delta", "text": chunk.text}
