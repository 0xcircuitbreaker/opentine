"""OpenAI-compatible hosted and local provider adapters."""

from opentine.models._compat_hosted import (
    GLM,
    ZAI,
    DeepSeek,
    Grok,
    Groq,
    Hermes,
    Kimi,
    Ministral,
    Mistral,
    OpenRouter,
    Qwen,
    Together,
)
from opentine.models._compat_local import VLLM, Jan, LlamaCpp, LMStudio, LocalAI, Unsloth

__all__ = [
    "DeepSeek",
    "GLM",
    "Grok",
    "Groq",
    "Hermes",
    "Jan",
    "Kimi",
    "LlamaCpp",
    "LMStudio",
    "LocalAI",
    "Ministral",
    "Mistral",
    "OpenRouter",
    "Qwen",
    "Together",
    "Unsloth",
    "VLLM",
    "ZAI",
]
