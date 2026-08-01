"""Amazon Bedrock adapters: the same wire, a different billing identity.

Bedrock re-hosts models the direct APIs also serve, under per-region,
per-account contract pricing that no signed snapshot can state truthfully. These
adapters therefore reuse the existing request/usage handling wholesale and
change exactly two things: ``_provider_id`` (so no rate card can price the call
— ``RateCard.matches`` compares provider first) and a ``managed_unpriced`` pass
after metering (so the silence is explicit rather than a ``0`` that reads like a
bill). Usage is recorded in full; cost is recorded as unknown.

REJECTED, and recorded here so 0.7.0 does not relitigate it mid-release: a
generic ``boto3`` Converse adapter. It buys the non-Anthropic model families a
second time — ``BedrockCompatible`` already reaches Nova/Llama/Mistral over the
OpenAI-compatible endpoint with zero new normalizers — at the cost of a
sync-only client needing an async bridge, plus fresh content-block, streaming,
and usage normalizers for a wire shape nothing else in the codebase speaks. That
is a large reimplementation of code that already exists and is tested, which is
the opposite of this release's thesis: managed clouds are a *surface* over the
adapters we have, not a new provider stack.
"""

from __future__ import annotations

import os
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._compat_local import OpenAICompatible
from opentine.models._managed_billing import managed_unpriced, reject_unsupported_controls
from opentine.models.anthropic import Anthropic

#: ``arn:partition:service:region:account:resource`` — the resource itself may
#: contain further colons (``...claude-sonnet-5-v1:0``), so the split is bounded.
_ARN_PARTS = 6


def profile_name(model: Any) -> Any:
    """Truncate a Bedrock inference-profile ARN to its bare profile name.

    ``arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-5-v1:0``
    carries the caller's **AWS account id**. Every model identity an adapter
    produces is persisted — ``requested_model``, ``reported_model``, the step's
    ``model_info``, and so every ``tine cost`` ``by_model`` row — into artifacts
    that are shared, diffed, and attached to pull requests. An account id is not
    a secret, but it identifies an organization's infrastructure and nobody
    chose to publish it by naming a model.

    Only the *recorded* identity is truncated: the request still goes out with
    the full ARN, because that is what Bedrock resolves.
    """
    if not isinstance(model, str) or not model.lower().startswith("arn:"):
        return model
    parts = model.split(":", _ARN_PARTS - 1)
    if len(parts) < _ARN_PARTS:
        return model
    return parts[-1].rsplit("/", 1)[-1] or model


def arn_region(model: Any) -> str | None:
    """The region an inference-profile ARN names, when it names one."""
    if not isinstance(model, str) or not model.lower().startswith("arn:"):
        return None
    parts = model.split(":", _ARN_PARTS - 1)
    return parts[3] or None if len(parts) >= _ARN_PARTS else None


def _resolved_region(model: Any, region: str | None) -> str | None:
    return (
        region
        or arn_region(model)
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or None
    )


class Bedrock(Anthropic):
    """Anthropic models on Bedrock: the Messages wire, priced as unknown.

    Usage extraction needs no new code — Bedrock reports the same
    ``cache_creation``/``cache_read_input_tokens`` shape the direct API does, and
    the model rules are substring matches, so ``us.anthropic.claude-sonnet-5-v1:0``
    resolves its sampling and thinking behaviour the same way ``claude-sonnet-5``
    does.
    """

    _provider_id = "bedrock"
    #: A response echoing the requested inference profile must not smuggle the
    #: account id back in through ``reported_model``.
    _model_id = staticmethod(profile_name)

    def __init__(
        self,
        model: str = "us.anthropic.claude-sonnet-5-v1:0",
        *,
        region: str | None = None,
        rates: dict[str, Any] | None = None,
        catalog: PricingCatalog | None = None,
        service_tier: str | None = None,
        inference_geo: str | None = None,
    ):
        reject_unsupported_controls(
            "Bedrock Messages", service_tier=service_tier, inference_geo=inference_geo
        )
        self._model_ref = model
        self._region = _resolved_region(model, region)
        super().__init__(profile_name(model), api_key="", rates=rates, catalog=catalog)
        # SigV4 only. Never carry a direct-API key on a managed adapter, not even
        # unused: the credential and the billing identity must not disagree.
        self._api_key = ""

    def _get_client(self):
        try:
            from anthropic import AsyncAnthropicBedrock
        except ImportError:
            raise ImportError("pip install opentine[bedrock]") from None
        return AsyncAnthropicBedrock(aws_region=self._region, max_retries=0)

    def _kwargs(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str | None,
        temperature: float,
    ) -> dict[str, Any]:
        kwargs = super()._kwargs(messages, tools, system, temperature)
        kwargs["model"] = self._model_ref  # the wire resolves the full ARN
        return kwargs

    def _meter(self, response: Any, *, early_refusal: bool = False) -> dict[str, Any]:
        payload = managed_unpriced(
            super()._meter(response, early_refusal=early_refusal),
            provider=self._provider_id,
            region=self._region,
        )
        if self._model_ref != self._model:
            payload["billing"]["calculation"]["model_id_truncated"] = "inference_profile_arn"
        return payload


class BedrockCompatible(OpenAICompatible):
    """Bedrock's OpenAI-compatible endpoint, for the non-Anthropic families.

    Nova, Llama, and Mistral on Bedrock speak Chat Completions at
    ``bedrock-runtime.<region>.amazonaws.com/openai/v1``; a preset over the
    adapter that already speaks it is the whole implementation. Authentication is
    the Bedrock API key (``AWS_BEARER_TOKEN_BEDROCK``), not SigV4.
    """

    _provider_id = "bedrock"
    _model_id = staticmethod(profile_name)

    def __init__(
        self,
        model: str,
        *,
        region: str | None = None,
        api_key: str = "",
        base_url: str | None = None,
        **kwargs: Any,
    ):
        self._region = _resolved_region(model, region) or "us-east-1"
        self._model_ref = model
        super().__init__(
            profile_name(model),
            base_url=base_url or f"https://bedrock-runtime.{self._region}.amazonaws.com/openai/v1",
            api_key=api_key or os.environ.get("AWS_BEARER_TOKEN_BEDROCK", ""),
            provider=self._provider_id,
            **kwargs,
        )

    def _kwargs(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str | None,
        temperature: float,
    ) -> dict[str, Any]:
        kwargs = super()._kwargs(messages, tools, system, temperature)
        kwargs["model"] = self._model_ref
        return kwargs

    def _meter(
        self,
        raw_usage: Any,
        service_tier: str | None = None,
        reported_model: str | None = None,
        service_tier_observed: bool | None = None,
    ) -> dict[str, Any]:
        payload = super()._meter(raw_usage, service_tier, reported_model, service_tier_observed)
        return managed_unpriced(payload, provider=self._provider_id, region=self._region)
