"""Hosted OpenAI-compatible adapters with provider-scoped billing."""

from __future__ import annotations

import os
from typing import Any

from opentine.models._chat import ChatCompletions, env_key
from opentine.models._compat_auth import glm_jwt


def _base(
    instance: ChatCompletions,
    model: str,
    provider: str,
    key: str,
    key_env: str,
    url: str,
    kwargs: dict[str, Any],
) -> None:
    ChatCompletions.__init__(
        instance,
        model,
        provider=provider,
        api_key=key or env_key(key_env),
        base_url=url,
        **kwargs,
    )


class Kimi(ChatCompletions):
    def __init__(self, model: str = "kimi-k2.6", api_key: str | None = None, **kwargs: Any):
        kwargs.setdefault("omit_temperature", True)
        _base(
            self,
            model,
            "kimi",
            api_key or "",
            "KIMI_API_KEY",
            os.environ.get("KIMI_BASE_URL", "https://api.moonshot.ai/v1"),
            kwargs,
        )


class DeepSeek(ChatCompletions):
    def __init__(self, model: str = "deepseek-v4-flash", api_key: str | None = None, **kwargs: Any):
        _base(
            self,
            model,
            "deepseek",
            api_key or "",
            "DEEPSEEK_API_KEY",
            os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            kwargs,
        )


class Qwen(ChatCompletions):
    def __init__(self, model: str = "qwen3.7-max", api_key: str | None = None, **kwargs: Any):
        _base(
            self,
            model,
            "qwen",
            api_key or "",
            "QWEN_API_KEY",
            os.environ.get(
                "QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
            ),
            kwargs,
        )


class GLM(ChatCompletions):
    def __init__(self, model: str = "glm-5.1", api_key: str | None = None, **kwargs: Any):
        raw_key = api_key or env_key("GLM_API_KEY")
        configured_region = os.environ.get("GLM_REGION")
        china = (configured_region or "").lower() == "china" or (
            configured_region is None and "." in raw_key
        )
        if china and "." in raw_key:
            raw_key = glm_jwt(raw_key)
        url = (
            "https://open.bigmodel.cn/api/paas/v4"
            if china
            else os.environ.get("GLM_BASE_URL", "https://api.z.ai/api/paas/v4")
        )
        _base(self, model, "glm", raw_key, "GLM_API_KEY", url, kwargs)

    _make_jwt = staticmethod(glm_jwt)


ZAI = GLM


class Grok(ChatCompletions):
    def __init__(self, model: str = "grok-4.5", api_key: str | None = None, **kwargs: Any):
        _base(
            self,
            model,
            "xai",
            api_key or "",
            "XAI_API_KEY",
            os.environ.get("XAI_BASE_URL", "https://api.x.ai/v1"),
            kwargs,
        )


class Groq(ChatCompletions):
    def __init__(
        self,
        model: str = "llama-3.3-70b-versatile",
        api_key: str | None = None,
        **kwargs: Any,
    ):
        _base(
            self,
            model,
            "groq",
            api_key or "",
            "GROQ_API_KEY",
            "https://api.groq.com/openai/v1",
            kwargs,
        )


class Together(ChatCompletions):
    def __init__(
        self,
        model: str = "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        api_key: str | None = None,
        **kwargs: Any,
    ):
        _base(
            self,
            model,
            "together",
            api_key or "",
            "TOGETHER_API_KEY",
            "https://api.together.xyz/v1",
            kwargs,
        )


class Mistral(ChatCompletions):
    def __init__(self, model: str = "mistral-large-3", api_key: str | None = None, **kwargs: Any):
        _base(
            self,
            model,
            "mistral",
            api_key or "",
            "MISTRAL_API_KEY",
            "https://api.mistral.ai/v1",
            kwargs,
        )


class Ministral(Mistral):
    def __init__(self, model: str = "ministral-3-14b", api_key: str | None = None, **kwargs: Any):
        super().__init__(model=model, api_key=api_key, **kwargs)


class OpenRouter(ChatCompletions):
    def __init__(
        self,
        model: str = "nousresearch/hermes-4-70b",
        api_key: str | None = None,
        **kwargs: Any,
    ):
        _base(
            self,
            model,
            "openrouter",
            api_key or "",
            "OPENROUTER_API_KEY",
            "https://openrouter.ai/api/v1",
            kwargs,
        )


class Hermes(ChatCompletions):
    def __init__(self, model: str = "Hermes-4-70B", api_key: str | None = None, **kwargs: Any):
        _base(
            self,
            model,
            "nous",
            api_key or "",
            "NOUS_API_KEY",
            os.environ.get("NOUS_BASE_URL", "https://inference-api.nousresearch.com/v1"),
            kwargs,
        )
