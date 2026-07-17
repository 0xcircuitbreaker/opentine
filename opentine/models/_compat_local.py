"""Exact-base OpenAI-compatible transport and local runtime presets."""

from __future__ import annotations

from typing import Any

from opentine.models._chat import ChatCompletions


def _exact_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url.lower().startswith(("http://", "https://")):
        raise ValueError("base_url must be an absolute HTTP(S) URL")
    return base_url.rstrip("/")


def _versioned_url(host: str, prefix: str) -> str:
    root = _exact_url(host)
    suffix = f"/{prefix.strip('/')}" if prefix.strip("/") else ""
    return root if not suffix or root.endswith(suffix) else f"{root}{suffix}"


class OpenAICompatible(ChatCompletions):
    """Chat Completions at an exact base URL; hosted billing is unknown by default."""

    def __init__(
        self,
        model: str,
        *,
        base_url: str,
        api_key: str = "",
        provider: str = "openai-compatible",
        unmetered: bool = False,
        supports_tools: bool = True,
        include_usage: bool = False,
        extra_body: dict[str, Any] | None = None,
        trust_env: bool = False,
        **kwargs: Any,
    ):
        self._supports_tools = supports_tools
        self._extra_body = dict(extra_body or {})
        self._trust_env = trust_env
        super().__init__(
            model,
            provider=provider,
            api_key=api_key,
            base_url=_exact_url(base_url),
            unmetered=unmetered,
            include_usage=include_usage,
            **kwargs,
        )

    @property
    def supports_tools(self) -> bool:
        return self._supports_tools

    def _get_client(self):
        try:
            import openai
        except ImportError:
            raise ImportError("pip install opentine[compat]") from None
        return openai.AsyncOpenAI(
            api_key=self._api_key or "local",
            base_url=self._base_url,
            max_retries=0,
            http_client=openai.DefaultAsyncHttpxClient(
                trust_env=self._trust_env,
                follow_redirects=False,
            ),
        )

    def _kwargs(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str | None,
        temperature: float,
    ) -> dict[str, Any]:
        request = super()._kwargs(
            messages,
            tools if self._supports_tools else None,
            system,
            temperature,
        )
        if self._extra_body:
            request["extra_body"] = dict(self._extra_body)
        return request


class LocalOpenAICompatible(OpenAICompatible):
    """Unmetered local runtime with a conventional host plus API-prefix helper."""

    provider = "local"
    default_host = "http://localhost:8000"
    default_key = "local"
    api_prefix = "/v1"
    default_include_usage = False

    def __init__(
        self,
        model: str = "default",
        host: str | None = None,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        unmetered: bool | None = None,
        api_prefix: str | None = None,
        **kwargs: Any,
    ):
        if host is not None and base_url is not None:
            raise ValueError("pass host or exact base_url, not both")
        if unmetered is None:
            priced = kwargs.get("rates") is not None or any(
                kwargs.get(name) is not None
                for name in ("input_cost_per_mtok", "output_cost_per_mtok")
            )
            unmetered = not priced
        endpoint = (
            _exact_url(base_url)
            if base_url is not None
            else _versioned_url(
                host or self.default_host,
                self.api_prefix if api_prefix is None else api_prefix,
            )
        )
        kwargs.setdefault("include_usage", self.default_include_usage)
        super().__init__(
            model,
            base_url=endpoint,
            api_key=api_key or self.default_key,
            provider=self.provider,
            unmetered=unmetered,
            **kwargs,
        )


class LMStudio(LocalOpenAICompatible):
    provider = "lmstudio"
    default_host = "http://localhost:1234"
    default_key = "lm-studio"
    default_include_usage = True

    def __init__(self, model: str = "local-model", host: str | None = None, **kwargs: Any):
        super().__init__(model, host, **kwargs)


class VLLM(LocalOpenAICompatible):
    provider = "vllm"
    default_key = "vllm"
    default_include_usage = True


class Unsloth(VLLM):
    provider = "unsloth"
    default_key = "unsloth"


class LlamaCpp(LocalOpenAICompatible):
    provider = "llamacpp"
    default_host = "http://localhost:8080"
    default_key = "llama-cpp"
    default_include_usage = True


class LocalAI(LocalOpenAICompatible):
    provider = "localai"
    default_host = "http://localhost:8080"
    default_key = "local-ai"


class Jan(LocalOpenAICompatible):
    provider = "jan"
    default_host = "http://localhost:1337"
    default_key = "jan"
    default_include_usage = True
