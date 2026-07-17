"""Convenience presets for OpenAI-compatible local inference servers."""

from opentine.models._compat_local import LocalOpenAICompatible


class SGLang(LocalOpenAICompatible):
    provider = "sglang"
    default_host = "http://localhost:30000"
    default_key = "sglang"
    default_include_usage = True


class TGI(LocalOpenAICompatible):
    provider = "tgi"
    default_host = "http://localhost:8080"
    default_key = "tgi"
    default_include_usage = True


class MLXLM(LocalOpenAICompatible):
    provider = "mlx-lm"
    default_host = "http://localhost:8080"
    default_key = "mlx-lm"
    default_include_usage = True


class NvidiaNIM(LocalOpenAICompatible):
    provider = "nvidia-nim"
    default_host = "http://localhost:8000"
    default_key = "nvidia-nim"
    default_include_usage = True


class TensorRTLLM(LocalOpenAICompatible):
    provider = "tensorrt-llm"
    default_host = "http://localhost:8000"
    default_key = "tensorrt-llm"
    default_include_usage = True


class KoboldCpp(LocalOpenAICompatible):
    provider = "koboldcpp"
    default_host = "http://localhost:5001"
    default_key = "koboldcpp"


class LiteLLM(LocalOpenAICompatible):
    provider = "litellm"
    default_host = "http://localhost:4000"
    default_key = "litellm"
    default_include_usage = True

    def __init__(self, model: str = "default", host: str | None = None, **kwargs):
        kwargs.setdefault("unmetered", False)
        super().__init__(model, host, **kwargs)


class LlamaCppPython(LocalOpenAICompatible):
    provider = "llama-cpp-python"
    default_host = "http://localhost:8000"
    default_key = "llama-cpp-python"
    default_include_usage = True
