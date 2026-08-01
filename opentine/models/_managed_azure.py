"""Azure OpenAI: the Chat Completions wire, under a different billing identity.

Azure resells OpenAI's models from a customer-owned resource, under enterprise
agreement pricing (plus PTU reservations, regional multipliers, and commitment
discounts) that no public snapshot can state truthfully. This adapter is
therefore the same preset shape as ``BedrockCompatible``: it reuses the
OpenAI-compatible transport wholesale and changes exactly two things —
``_provider_id`` (so no rate card can price the call; ``RateCard.matches``
compares provider first) and a ``managed_unpriced`` pass after metering (so the
silence is explicit rather than a ``0`` that reads like a bill).

**The mispricing this class exists to prevent.** Azure reports the *same* model
strings the direct OpenAI API reports — a response says ``gpt-5.6`` on both
surfaces, and the bundled catalog holds a real card for the direct one. Nothing
in the payload distinguishes an Azure call. ``_provider_id`` is a class
attribute, never a constructor argument, and the catalog carries no
``azure-openai`` card, so the engine takes its no-card path and
``managed_unpriced`` records why.

**The credential rule (the non-forwarding doctrine).** ``AZURE_OPENAI_API_KEY``
is read; ``OPENAI_API_KEY`` is *never* consulted. This is the same rule
``OpenAICompatible`` applies to gateways and ``GLM`` applies to its China
endpoint: a key minted for one host must not ride out to another host because
the wire format happens to match. A developer with ``OPENAI_API_KEY`` exported
would otherwise ship their direct-OpenAI secret to ``*.openai.azure.com`` — a
different company's endpoint — on the first call, silently. Microsoft Entra ID
is supported by passing an already-minted bearer token as ``api_key=``; token
acquisition and refresh belong to the caller's identity library, not here.

**Streaming usage.** ``include_usage=True`` is set at the *adapter* level rather
than by widening ``ChatCompletions._stream_usage_providers``, whose documented
bar for membership is positive evidence that a provider accepts the field. The
failure this prevents is the silent one: without ``stream_options``, an Azure
stream ends with no usage chunk at all, so a streamed call records zero tokens
and prices as "unknown" for the wrong reason — indistinguishable, in the
artifact, from the managed-cloud silence this module is deliberately recording.

NON-GOAL, recorded so 0.7.0 does not relitigate it: the legacy Azure surface —
``/openai/deployments/{deployment}/chat/completions?api-version=...``. It is not
a base URL an OpenAI-compatible client can be pointed at: the deployment name
sits in the *path* (not the ``model`` field) and a dated ``api-version`` query
parameter is mandatory on every request. Supporting it means depending on
``openai.AsyncAzureOpenAI`` and threading a version through request building —
a real adapter with its own surface area, not a preset. The ``/openai/v1``
endpoint, which Azure documents as the forward path, is a plain OpenAI-
compatible base URL and needs none of it. A legacy URL passed to ``base_url=``
is rejected rather than half-supported.
"""

from __future__ import annotations

import os
from typing import Any

from opentine.models._compat_local import OpenAICompatible, _exact_url, _versioned_url
from opentine.models._managed_billing import managed_unpriced

#: The path Azure serves the version-less, OpenAI-compatible API from.
AZURE_V1_PREFIX = "/openai/v1"

#: Markers of the legacy, ``api-version``-scoped surface. See the module NON-GOAL.
_LEGACY_MARKERS = ("api-version=", "/deployments/")


def _reject_legacy_surface(url: str) -> None:
    lowered = url.lower()
    for marker in _LEGACY_MARKERS:
        if marker in lowered:
            raise ValueError(
                "AzureOpenAI speaks the version-less /openai/v1 endpoint; the legacy "
                f"{marker!r} surface needs AsyncAzureOpenAI and is not supported. Pass "
                "resource= (or AZURE_OPENAI_ENDPOINT) and name the deployment as the model."
            )


def azure_base_url(resource: str | None, base_url: str | None) -> str:
    """Resolve the endpoint from an exact URL, a resource name, or the environment.

    Precedence is explicit-over-ambient, and the two explicit forms are mutually
    exclusive so a caller cannot half-configure the endpoint and be left
    guessing which half won:

    * ``base_url=`` — used exactly, like every other ``OpenAICompatible``. No
      ``/openai/v1`` is appended, because a private-endpoint or gateway URL is
      whatever the operator says it is.
    * ``resource="acme"`` — ``https://acme.openai.azure.com/openai/v1``.
    * ``AZURE_OPENAI_ENDPOINT`` — the resource URL Azure's portal shows
      (``https://acme.openai.azure.com/``), given the ``/openai/v1`` suffix once;
      an endpoint that already carries the suffix is left alone. A bare resource
      *name* in that variable is accepted too, since the portal shows both.
    """
    if resource and base_url:
        raise ValueError("pass resource= or an exact base_url=, not both")
    if base_url is not None:
        _reject_legacy_surface(base_url)
        return _exact_url(base_url)
    name = resource or os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    if not name:
        raise ValueError(
            "AzureOpenAI needs resource='my-resource', an exact base_url=, or AZURE_OPENAI_ENDPOINT"
        )
    _reject_legacy_surface(name)
    host = name if "://" in name else f"https://{name.strip('/')}.openai.azure.com"
    return _versioned_url(host, AZURE_V1_PREFIX)


class AzureOpenAI(OpenAICompatible):
    """Azure OpenAI's ``/openai/v1`` endpoint: usage recorded, cost unknown.

    ``model`` is the **deployment name**, which is what this endpoint resolves;
    it is often but not always the underlying model id.

        AzureOpenAI("gpt-5.6", resource="acme-prod")
        AzureOpenAI("gpt-5.6", base_url="https://acme.openai.azure.com/openai/v1")
        AzureOpenAI("gpt-5.6", resource="acme-prod", api_key=entra_token)

    ``region=`` (or ``AZURE_OPENAI_REGION``) is recorded on the billing
    calculation when supplied. It is not inferred: the endpoint hostname does not
    name a region, and a guessed region in an artifact is worse than none.
    """

    _provider_id = "azure-openai"

    def __init__(
        self,
        model: str,
        *,
        resource: str | None = None,
        base_url: str | None = None,
        api_key: str = "",
        region: str | None = None,
        **kwargs: Any,
    ):
        self._resource = resource
        self._region = region or os.environ.get("AZURE_OPENAI_REGION") or None
        # Adapter-level, not a _stream_usage_providers entry: see the module docstring.
        kwargs.setdefault("include_usage", True)
        super().__init__(
            model,
            base_url=azure_base_url(resource, base_url),
            # AZURE_OPENAI_API_KEY only. A direct-OpenAI key must never ride out
            # on an Azure adapter, so there is no OPENAI_API_KEY fallback here.
            api_key=api_key or os.environ.get("AZURE_OPENAI_API_KEY", ""),
            provider=self._provider_id,
            **kwargs,
        )

    def _meter(
        self,
        raw_usage: Any,
        service_tier: str | None = None,
        reported_model: str | None = None,
        service_tier_observed: bool | None = None,
    ) -> dict[str, Any]:
        payload = super()._meter(raw_usage, service_tier, reported_model, service_tier_observed)
        return managed_unpriced(payload, provider=self._provider_id, region=self._region)
