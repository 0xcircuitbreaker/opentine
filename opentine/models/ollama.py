"""Ollama adapter — local models via HTTP API."""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import httpx


class Ollama:
    """Adapter for Ollama local models."""

    def __init__(self, model: str = "llama3.1", host: str | None = None):
        self._model = model
        self._host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")

    @property
    def name(self) -> str:
        return f"ollama/{self._model}"

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        return False

    def _build_tools(self, tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        return [{"type": "function", "function": {
            "name": t["name"], "description": t["description"],
            "parameters": t["input_schema"],
        }} for t in tools]

    async def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                       system: str | None = None, temperature: float = 0.0) -> dict[str, Any]:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        for m in messages:
            msgs.append({"role": m["role"], "content": m["content"]})

        payload: dict[str, Any] = {"model": self._model, "messages": msgs, "stream": False,
                                   "options": {"temperature": temperature}}
        api_tools = self._build_tools(tools)
        if api_tools:
            payload["tools"] = api_tools

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(f"{self._host}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()

        text = data.get("message", {}).get("content", "")
        tool_calls = []
        for tc in data.get("message", {}).get("tool_calls", []):
            fn = tc.get("function", {})
            tool_calls.append({"name": fn.get("name", ""), "arguments": fn.get("arguments", {})})
        return {"text": text, "tool_calls": tool_calls, "cost": 0.0}

    async def stream(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                     system: str | None = None, temperature: float = 0.0) -> AsyncIterator[dict[str, Any]]:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        for m in messages:
            msgs.append({"role": m["role"], "content": m["content"]})

        payload: dict[str, Any] = {"model": self._model, "messages": msgs, "stream": True,
                                   "options": {"temperature": temperature}}

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream("POST", f"{self._host}/api/chat", json=payload) as resp:
                resp.raise_for_status()
                import json
                async for line in resp.aiter_lines():
                    if line.strip():
                        chunk = json.loads(line)
                        content = chunk.get("message", {}).get("content", "")
                        if content:
                            yield {"type": "text_delta", "text": content}
