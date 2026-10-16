"""More hosted OpenAI-compatible vendors, one data row each.

Each class records its own provider id, so a vendor's card (or the absence of
one) prices it -- never another vendor's card for the same open-weight model.
Every row is a documented endpoint (round-3 model research, 2026-10-14); a
vendor without a card records ``unknown`` honestly rather than a guessed price.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

from opentine.models._chat import ChatCompletions
from opentine.models._chat_billing import chat_meter


def _env(*names: str) -> str:
    return next((os.environ[name] for name in names if os.environ.get(name)), "")


class _Vendor(ChatCompletions):
    provider_id = ""
    default_model = ""
    base_url = ""
    key_env: tuple[str, ...] = ()
    base_url_env = ""
    #: ``stream_options`` only with positive evidence: a server that rejects it
    #: fails every streamed call, one that omits it only loses streamed usage.
    stream_usage = False
    no_temperature = False
    extra_body: dict[str, Any] = {}

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        kwargs.setdefault("include_usage", self.stream_usage)
        kwargs.setdefault("omit_temperature", self.no_temperature)
        # An explicit base_url (``--base-url``) is the endpoint from construction
        # on, so the provider and any host-derived tier come from the real URL.
        env_url = os.environ.get(self.base_url_env) if self.base_url_env else None
        url = kwargs.pop("base_url", None) or env_url or self._url()
        super().__init__(
            model or self.default_model,
            provider=self._provider_for(url),
            api_key=api_key or _env(*self.key_env),
            base_url=url,
            **kwargs,
        )

    def _url(self) -> str:
        return self.base_url

    def _provider_for(self, url: str) -> str:
        return self.provider_id

    def _kwargs(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        request = super()._kwargs(*args, **kwargs)
        if self.extra_body:
            request["extra_body"] = dict(self.extra_body)
        return request


class Meta(_Vendor):
    """Meta's Model API (Muse). Meta advises leaving temperature at its default."""

    provider_id, default_model = "meta", "muse-spark-1.3"
    base_url, key_env = "https://api.meta.ai/v1", ("META_API_KEY", "MODEL_API_KEY")
    no_temperature, stream_usage = True, True


class MiniMax(_Vendor):
    """MiniMax. ``reasoning_split`` keeps thinking out of ``content``."""

    provider_id, default_model = "minimax", "MiniMax-M3"
    base_url, key_env = "https://api.minimax.io/v1", ("MINIMAX_API_KEY",)
    extra_body, stream_usage = {"reasoning_split": True}, True


class DeepInfra(_Vendor):
    """DeepInfra; each response carries ``usage.estimated_cost``."""

    provider_id, default_model = "deepinfra", "deepseek-ai/DeepSeek-V4.1-Flash"
    base_url, key_env = "https://api.deepinfra.com/v1/openai", ("DEEPINFRA_API_KEY",)


class Fireworks(_Vendor):
    """Fireworks. The ``us.`` host bills 1.5x for the same id: the card's ``us`` tier."""

    provider_id, default_model = "fireworks", "accounts/fireworks/models/glm-5p3"
    base_url, key_env = "https://api.fireworks.ai/inference/v1", ("FIREWORKS_API_KEY",)
    base_url_env = "FIREWORKS_BASE_URL"

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        super().__init__(model, api_key, **kwargs)
        host = (urlsplit(self._base_url or "").hostname or "").lower()
        if host.startswith("us.") and self._service_tier is None:
            self._us_host = True

    _us_host = False

    def _billing_tier(self, messages: list[dict[str, Any]], reported: str | None) -> str | None:
        tier = super()._billing_tier(messages, reported)
        if not self._us_host:
            return tier
        return "us" if tier in (None, "", "default", "standard") else f"{tier}_us"


class Cerebras(_Vendor):
    provider_id, default_model = "cerebras", "gpt-oss-120b"
    base_url, key_env = "https://api.cerebras.ai/v1", ("CEREBRAS_API_KEY",)


class SambaNova(_Vendor):
    provider_id, default_model = "sambanova", "MiniMax-M3"
    base_url, key_env = "https://api.sambanova.ai/v1", ("SAMBANOVA_API_KEY",)
    stream_usage = True  # SambaNova reports streamed usage only on request


class StepFun(_Vendor):
    provider_id, default_model = "stepfun", "step-5-preview"
    base_url, key_env = "https://api.stepfun.ai/v1", ("STEPFUN_API_KEY",)


class Xiaomi(_Vendor):
    provider_id, default_model = "xiaomi", "mimo-v2.6-pro"
    base_url, key_env = "https://api.xiaomimimo.com/v1", ("MIMO_API_KEY", "XIAOMI_API_KEY")


class Upstage(_Vendor):
    provider_id, default_model = "upstage", "solar-pro4"
    base_url, key_env = "https://api.upstage.ai/v1", ("UPSTAGE_API_KEY",)


class Inception(_Vendor):
    provider_id, default_model = "inception", "mercury-2.5"
    base_url, key_env = "https://api.inceptionlabs.ai/v1", ("INCEPTION_API_KEY",)


class Nvidia(_Vendor):
    """NVIDIA API Catalog (build.nvidia.com): free prototyping, no rate card."""

    provider_id, default_model = "nvidia", "openai/gpt-oss-120b"
    base_url, key_env = "https://integrate.api.nvidia.com/v1", ("NVIDIA_API_KEY",)


class HuggingFace(_Vendor):
    """Hugging Face router: a price needs a pinned ``Org/Model:provider`` id."""

    provider_id, default_model = "huggingface", "openai/gpt-oss-120b:cerebras"
    base_url, key_env = "https://router.huggingface.co/v1", ("HF_TOKEN",)


class Vercel(_Vendor):
    """Vercel AI Gateway; its cost arrives later from ``/v1/generation``."""

    provider_id, default_model = "vercel", "openai/gpt-oss-120b"
    base_url, key_env = "https://ai-gateway.vercel.sh/v1", ("AI_GATEWAY_API_KEY",)


class Cohere(_Vendor):
    """Cohere's compatibility endpoint, which does not accept ``stream_options``."""

    provider_id, default_model = "cohere", "command-a-plus-05-2026"
    base_url, key_env = "https://api.cohere.ai/compatibility/v1", ("COHERE_API_KEY", "CO_API_KEY")


#: Bedrock model ids may carry a cross-region routing prefix: ``global.`` bills
#: the list price, a geographic one (``us.``, ``eu.``…) 1.1x -- the card's
#: ``regional`` modifier. A bare id prices from its card as is. OpenAI models
#: are carded under OpenAI's own name (``gpt-6-astra``), without ``openai.``.
_NO_TIER = (None, "", "default", "standard", "auto")
_BEDROCK_ROUTES = ("global.", "us.", "eu.", "au.", "apac.", "jp.", "ca.")


class Bedrock(_Vendor):
    """AWS Bedrock's OpenAI-compatible endpoint with a Bedrock API key (Bearer)."""

    provider_id, default_model = "bedrock", "openai.gpt-oss-120b-1:0"
    key_env = ("AWS_BEARER_TOKEN_BEDROCK",)
    base_url_env = "BEDROCK_BASE_URL"

    def _url(self) -> str:
        region = _env("AWS_REGION", "AWS_DEFAULT_REGION") or "us-east-1"
        return f"https://bedrock-runtime.{region}.amazonaws.com/openai/v1"

    def _meter(self, raw_usage: Any, service_tier: str | None = None, *args: Any, **kwargs: Any):
        model, route_tier = bedrock_pricing(self._model)
        reported = args[0] if args else kwargs.get("reported_model")
        # A response's own "default"/"standard" says nothing about the route: it
        # must not erase the regional uplift (Fireworks treats its host alike).
        observed = None if service_tier in _NO_TIER else service_tier
        tier = observed or self._service_tier
        if route_tier and tier and tier != route_tier:
            tier = f"{tier}_{route_tier}"  # e.g. batch_regional, as carded
        return chat_meter(
            self._provider,
            model,
            raw_usage,
            self._catalog,
            self._rate_override,
            tier or route_tier,
            self._unmetered,
            reported and bedrock_pricing(str(reported))[0],
        )


def bedrock_pricing(model: str) -> tuple[str, str | None]:
    """``(card model id, service tier)`` for a Bedrock request id."""
    tier = None
    for route in _BEDROCK_ROUTES:
        if model.startswith(route):
            model, tier = model[len(route) :], None if route == "global." else "regional"
            break
    return model.removeprefix("openai."), tier


VENDORS = (
    Bedrock,
    Cerebras,
    Cohere,
    DeepInfra,
    Fireworks,
    HuggingFace,
    Inception,
    Meta,
    MiniMax,
    Nvidia,
    SambaNova,
    StepFun,
    Upstage,
    Vercel,
    Xiaomi,
)

__all__ = [cls.__name__ for cls in VENDORS] + ["VENDORS", "bedrock_pricing"]
