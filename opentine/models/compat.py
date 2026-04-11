"""OpenAI-compatible providers — thin wrappers with pre-set base URLs.

Any provider that speaks the OpenAI Chat Completions API works here.
Each class is just the OpenAI adapter with a different endpoint and
env var. No new code, no new protocol, no impact on core.py.

Cloud providers: Kimi, DeepSeek, Qwen, GLM, Groq, Together, Mistral
Local providers: LMStudio, VLLM, LlamaCpp, LocalAI, Jan
"""

from __future__ import annotations

import os

from opentine.models.openai import OpenAI


class Kimi(OpenAI):
    """Moonshot AI Kimi models (moonshot-v1-8k, moonshot-v1-32k, moonshot-v1-128k)."""

    def __init__(self, model: str = "moonshot-v1-8k", api_key: str | None = None):
        super().__init__(
            model=model,
            api_key=api_key or os.environ.get("KIMI_API_KEY", ""),
            base_url="https://api.moonshot.cn/v1",
        )


class DeepSeek(OpenAI):
    """DeepSeek models (deepseek-chat, deepseek-reasoner)."""

    def __init__(self, model: str = "deepseek-chat", api_key: str | None = None):
        super().__init__(
            model=model,
            api_key=api_key or os.environ.get("DEEPSEEK_API_KEY", ""),
            base_url="https://api.deepseek.com",
        )


class Qwen(OpenAI):
    """Alibaba Qwen models via DashScope (qwen-plus, qwen-turbo, qwen-max)."""

    def __init__(self, model: str = "qwen-plus", api_key: str | None = None):
        super().__init__(
            model=model,
            api_key=api_key or os.environ.get("QWEN_API_KEY", ""),
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        )


class GLM(OpenAI):
    """Zhipu AI GLM models (glm-4, glm-4-flash, glm-4-plus)."""

    def __init__(self, model: str = "glm-4-flash", api_key: str | None = None):
        super().__init__(
            model=model,
            api_key=api_key or os.environ.get("GLM_API_KEY", ""),
            base_url="https://open.bigmodel.cn/api/paas/v4",
        )


class Groq(OpenAI):
    """Groq inference (llama-3.1-70b-versatile, mixtral-8x7b-32768, etc.)."""

    def __init__(self, model: str = "llama-3.1-70b-versatile", api_key: str | None = None):
        super().__init__(
            model=model,
            api_key=api_key or os.environ.get("GROQ_API_KEY", ""),
            base_url="https://api.groq.com/openai/v1",
        )


class Together(OpenAI):
    """Together AI (meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo, etc.)."""

    def __init__(
        self,
        model: str = "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        api_key: str | None = None,
    ):
        super().__init__(
            model=model,
            api_key=api_key or os.environ.get("TOGETHER_API_KEY", ""),
            base_url="https://api.together.xyz/v1",
        )


class Mistral(OpenAI):
    """Mistral AI (mistral-large-latest, mistral-small-latest, etc.)."""

    def __init__(self, model: str = "mistral-large-latest", api_key: str | None = None):
        super().__init__(
            model=model,
            api_key=api_key or os.environ.get("MISTRAL_API_KEY", ""),
            base_url="https://api.mistral.ai/v1",
        )


# --- Local providers (no API key needed, no pip extra needed) ---------------


class LMStudio(OpenAI):
    """LM Studio local server (any model loaded in the app)."""

    def __init__(self, model: str = "local-model", host: str = "http://localhost:1234"):
        super().__init__(model=model, api_key="lm-studio", base_url=f"{host}/v1")


class VLLM(OpenAI):
    """vLLM high-performance inference server."""

    def __init__(self, model: str = "default", host: str = "http://localhost:8000"):
        super().__init__(model=model, api_key="vllm", base_url=f"{host}/v1")


class LlamaCpp(OpenAI):
    """llama.cpp server (lightweight C++ inference)."""

    def __init__(self, model: str = "default", host: str = "http://localhost:8080"):
        super().__init__(model=model, api_key="llama-cpp", base_url=f"{host}/v1")


class LocalAI(OpenAI):
    """LocalAI — drop-in OpenAI replacement for local models."""

    def __init__(self, model: str = "default", host: str = "http://localhost:8080"):
        super().__init__(model=model, api_key="local-ai", base_url=f"{host}/v1")


class Jan(OpenAI):
    """Jan desktop app local server."""

    def __init__(self, model: str = "default", host: str = "http://localhost:1337"):
        super().__init__(model=model, api_key="jan", base_url=f"{host}/v1")
