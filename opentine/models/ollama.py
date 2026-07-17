"""Ollama adapter — local models via HTTP API."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import httpx

from opentine.billing import PricingCatalog
from opentine.models import _ollama_http as _http
from opentine.models._ollama_billing import ollama_meter
from opentine.models._ollama_rates import rate_override
from opentine.models._ollama_request import build_messages, build_tools
from opentine.models._provider_meta import model_name
from opentine.models._stream_content import OllamaStreamState
from opentine.models._streaming import WarningList, ollama_result
from opentine.models._terminal import reject_refused_tool_calls

_IDENTITY = {"Accept-Encoding": "identity"}


class Ollama:
    """Adapter for Ollama local models."""

    _build_messages = staticmethod(build_messages)
    _build_tools = staticmethod(build_tools)

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
        self._compute_rate = compute_cost_per_second is not None
        self._rate_override = rate_override(
            input_cost_per_mtok, output_cost_per_mtok, compute_cost_per_second
        )

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
        return ollama_meter(
            self._model, data, self._catalog, self._rate_override, self._compute_rate
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
        if data.get("error"):
            result["refusal"] = f"Ollama error: {str(data['error'])[:4096]}"
            warnings.append(result["refusal"])
        elif data.get("done") is not True:
            result["refusal"] = "incomplete response: response did not complete"
            warnings.append(result["refusal"])
        reject_refused_tool_calls(result)
        result.update(self._meter(data))
        if reported_model := model_name(data.get("model")):
            result["model"] = reported_model
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
                    if chunk.get("error"):
                        saw_done = True
                        metered = self._meter(chunk)
                        result = ollama_result({**chunk, "message": state.message()}, warnings)
                        result["refusal"] = f"Ollama error: {str(chunk['error'])[:4096]}"
                        warnings.append(result["refusal"])
                        reject_refused_tool_calls(result)
                        result.update(metered)
                        yield {"type": "usage", **metered}
                        yield {"type": "response", **result}
                        break
                    message = chunk.get("message", {})
                    if not isinstance(message, dict):
                        raise ValueError("Ollama stream message must be a JSON object")
                    for event in state.add(message):
                        yield event
                    if chunk.get("done") is True:
                        saw_done = True
                        metered = self._meter(chunk)
                        result = ollama_result({**chunk, "message": state.message()}, warnings)
                        result.update(metered)
                        if reported_model := model_name(chunk.get("model")):
                            result["model"] = reported_model
                        yield {"type": "usage", **metered}
                        if result["tool_calls"] or result.get("refusal") or result.get("thinking"):
                            yield {"type": "response", **result}
        if not saw_done:
            metered = self._meter({})
            yield {"type": "usage", **metered}
            result = ollama_result({"message": state.message()}, warnings)
            result["refusal"] = "incomplete response: stream ended before done marker"
            warnings.append(result["refusal"])
            reject_refused_tool_calls(result)
            result.update(metered)
            yield {"type": "response", **result}
