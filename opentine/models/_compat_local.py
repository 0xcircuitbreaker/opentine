"""Unmetered local OpenAI-compatible runtimes."""

from __future__ import annotations

from typing import Any

from opentine.models._chat import ChatCompletions


class _Local(ChatCompletions):
    provider = "local"
    default_host = ""
    default_key = "local"

    def __init__(self, model: str = "default", host: str | None = None, **kwargs: Any):
        kwargs.setdefault("unmetered", True)
        super().__init__(
            model,
            provider=self.provider,
            api_key=self.default_key,
            base_url=f"{host or self.default_host}/v1",
            **kwargs,
        )


class LMStudio(_Local):
    provider = "lmstudio"
    default_host = "http://localhost:1234"
    default_key = "lm-studio"

    def __init__(
        self, model: str = "local-model", host: str = "http://localhost:1234", **kwargs: Any
    ):
        super().__init__(model, host, **kwargs)


class VLLM(_Local):
    provider = "vllm"
    default_host = "http://localhost:8000"
    default_key = "vllm"


class Unsloth(VLLM):
    provider = "unsloth"
    default_key = "unsloth"


class LlamaCpp(_Local):
    provider = "llamacpp"
    default_host = "http://localhost:8080"
    default_key = "llama-cpp"


class LocalAI(_Local):
    provider = "localai"
    default_host = "http://localhost:8080"
    default_key = "local-ai"


class Jan(_Local):
    provider = "jan"
    default_host = "http://localhost:1337"
    default_key = "jan"
