"""Ollama adapter — local models via HTTP API."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from decimal import Decimal
from typing import Any

import httpx

from opentine.billing import PricingCatalog
from opentine.models import _ollama_http as _http
from opentine.models._stream_content import OllamaStreamState
from opentine.models._streaming import WarningList, ollama_result
from opentine.models._usage import metered_response, ollama_usage

_IDENTITY = {"Accept-Encoding": "identity"}


class Ollama:
    """Adapter for Ollama local models."""

    def __init__(
        self,
        model: str = "llama3.1",
        host: str | None = None,
        think: bool | str | None = None,
        *,
        input_cost_per_mtok: float | None = None,
        output_cost_per_mtok: float | None = None,
        compute_cost_per_second: float | None = None,
        catalog: PricingCatalog | None = None,
    ):
        self._model = model
        self._host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self._think = think
        self._capabilities: set[str] | None = None
        self._catalog = catalog
        self._rate_override: dict[str, Any] | None = None
        if any(
            value is not None
            for value in (input_cost_per_mtok, output_cost_per_mtok, compute_cost_per_second)
        ):
            per_second = Decimal(str(compute_cost_per_second or 0)) * 1_000_000
            self._rate_override = {
                "input": input_cost_per_mtok or 0,
                "output": output_cost_per_mtok or 0,
                "prompt_eval_seconds": per_second,
                "eval_seconds": per_second,
                "total_seconds": 0,
                "load_seconds": 0,
            }

    @property
    def name(self) -> str:
        return f"ollama/{self._model}"

    def _tools_capable(self) -> bool:
        """Cache the model capabilities reported by ``/api/show``."""
        if self._capabilities is None:
            try:
                url = f"{self._host}/api/show"
                request = {"model": self._model}
                with httpx.Client(timeout=5, trust_env=False, follow_redirects=False) as client:
                    with client.stream("POST", url, json=request, headers=_IDENTITY) as resp:
                        resp.raise_for_status()
                        data = _http.read_json(resp, max_bytes=_http.MAX_SHOW_BYTES)
                    self._capabilities = set(data.get("capabilities") or ["tools"])
            except Exception:
                self._capabilities = {"tools"}
        return "tools" in self._capabilities

    @property
    def supports_tools(self) -> bool:
        return self._tools_capable()

    @property
    def supports_thinking(self) -> bool:
        model = self._model.lower()
        return (
            model.startswith("qwen3")
            or model.startswith("deepseek-r1")
            or model.startswith("deepseek-v3.1")
            or model.startswith("gpt-oss")
        )

    def _build_tools(self, tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

    def _build_messages(
        self, messages: list[dict[str, Any]], system: str | None
    ) -> list[dict[str, Any]]:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        for m in messages:
            if m["role"] == "assistant" and m.get("tool_calls"):
                msgs.append(
                    {
                        "role": "assistant",
                        "content": m.get("content", ""),
                        "tool_calls": [
                            {
                                "type": "function",
                                "function": {
                                    "name": tc["name"],
                                    "arguments": tc.get("arguments", {}),
                                },
                            }
                            for tc in m["tool_calls"]
                        ],
                    }
                )
            elif m["role"] == "tool":
                msgs.append(
                    {
                        "role": "tool",
                        "content": m["content"],
                        "tool_name": m.get("tool_name")
                        or m.get("name")
                        or m.get("tool_call_id", ""),
                    }
                )
            else:
                msgs.append({"role": m["role"], "content": m["content"]})
        return msgs

    def _build_payload(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str | None,
        temperature: float,
        *,
        stream: bool,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": self._build_messages(messages, system),
            "stream": stream,
            "options": {"temperature": temperature},
        }
        api_tools = self._build_tools(tools)
        if api_tools:
            payload["tools"] = api_tools
        if self._think is not None:
            payload["think"] = self._think
        return payload

    def _meter(self, data: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(data)
        for source, target in (
            ("total_duration", "total_seconds"),
            ("load_duration", "load_seconds"),
            ("prompt_eval_duration", "prompt_eval_seconds"),
            ("eval_duration", "eval_seconds"),
        ):
            if source in normalized:
                normalized[target] = Decimal(normalized[source]) / Decimal(1_000_000_000)
                normalized.pop(source)
        usage = ollama_usage(normalized)
        return metered_response(
            "ollama",
            self._model,
            usage,
            catalog=self._catalog,
            rate_override=self._rate_override,
            unmetered=self._rate_override is None,
            usage_reported=any(name in data for name in ("prompt_eval_count", "eval_count")),
        )

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        warnings: list[str] = WarningList()
        if tools and not self._tools_capable():
            warnings.append(f"{self.name}: model does not support tool calling; ran without tools")
            tools = None
        payload = self._build_payload(messages, tools, system, temperature, stream=False)
        url = f"{self._host}/api/chat"

        async with httpx.AsyncClient(
            timeout=120, trust_env=False, follow_redirects=False
        ) as client:
            async with client.stream("POST", url, json=payload, headers=_IDENTITY) as resp:
                resp.raise_for_status()
                data = await _http.read_json_async(resp, max_bytes=_http.MAX_CHAT_BYTES)

        result = ollama_result(data, warnings)
        result.update(self._meter(data))
        return result

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        warnings: list[str] = WarningList()
        if tools and not self._tools_capable():
            warnings.append(f"{self.name}: model does not support tool calling; ran without tools")
            tools = None
        payload = self._build_payload(messages, tools, system, temperature, stream=True)
        state = OllamaStreamState(warnings)
        saw_done = False
        url = f"{self._host}/api/chat"

        async with httpx.AsyncClient(
            timeout=120, trust_env=False, follow_redirects=False
        ) as client:
            async with client.stream("POST", url, json=payload, headers=_IDENTITY) as resp:
                resp.raise_for_status()
                async for chunk in _http.iter_ndjson(resp):
                    message = chunk.get("message", {})
                    if not isinstance(message, dict):
                        raise ValueError("Ollama stream message must be a JSON object")
                    for event in state.add(message):
                        yield event
                    if chunk.get("done"):
                        saw_done = True
                        metered = self._meter(chunk)
                        result = ollama_result({**chunk, "message": state.message()}, warnings)
                        result.update(metered)
                        yield {"type": "usage", **metered}
                        if result["tool_calls"] or result.get("refusal") or result.get("thinking"):
                            yield {"type": "response", **result}
        if not saw_done:
            yield {"type": "usage", **self._meter({})}
