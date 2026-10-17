"""Convenience presets for OpenAI-compatible local inference servers."""

from opentine.models._compat_local import LocalOpenAICompatible


class SGLang(LocalOpenAICompatible):
    provider = "sglang"
    default_host = "http://localhost:30000"
    default_key = "sglang"
    default_include_usage = True


class TGI(LocalOpenAICompatible):
    """Hugging Face TGI. Deprecated upstream: archived, maintenance mode since 2025-12."""

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
    default_include_usage = True


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


def _preset(
    name: str,
    provider: str,
    host: str,
    *,
    prefix: str = "/v1",
    usage: bool = True,
    base_url_required: bool = False,
    doc: str,
) -> type[LocalOpenAICompatible]:
    return type(
        name,
        (LocalOpenAICompatible,),
        {
            "__doc__": doc,
            "__module__": __name__,
            "provider": provider,
            "default_host": host,
            "default_key": provider,
            "api_prefix": prefix,
            "default_include_usage": usage,
            "requires_base_url": base_url_required,
        },
    )


DockerModelRunner = _preset(
    "DockerModelRunner",
    "docker-model-runner",
    "http://localhost:12434",
    prefix="/engines/v1",
    doc="Docker Model Runner's OpenAI-compatible API (TCP host access on 12434).",
)
Lemonade = _preset(
    "Lemonade",
    "lemonade",
    "http://localhost:13305",
    prefix="/api/v1",
    doc="AMD Lemonade Server.",
)
MistralRs = _preset(
    "MistralRs", "mistralrs", "http://localhost:1234", doc="mistral.rs ``mistralrs serve``."
)
TabbyAPI = _preset(
    "TabbyAPI",
    "tabbyapi",
    "http://localhost:5000",
    doc="TabbyAPI (ExLlamaV3). Auth is on by default: set TABBYAPI_API_KEY.",
)
Xinference = _preset("Xinference", "xinference", "http://localhost:9997", doc="Xorbits Xinference.")
LMDeploy = _preset("LMDeploy", "lmdeploy", "http://localhost:23333", doc="LMDeploy api_server.")
Llamafile = _preset("Llamafile", "llamafile", "http://localhost:8080", doc="Mozilla llamafile.")
Dynamo = _preset("Dynamo", "dynamo", "http://localhost:8000", doc="NVIDIA Dynamo frontend.")
Aphrodite = _preset("Aphrodite", "aphrodite", "http://localhost:2242", doc="Aphrodite Engine.")
FoundryLocal = _preset(
    "FoundryLocal",
    "foundry-local",
    "http://localhost:5273",
    base_url_required=True,
    doc="Microsoft Foundry Local; its port is chosen at start (`foundry service status`).",
)
OVMS = _preset(
    "OVMS",
    "ovms",
    "http://localhost:8000",
    prefix="/v3",
    base_url_required=True,
    doc="OpenVINO Model Server (``/v3`` paths; no default REST port).",
)
