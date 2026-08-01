"""Vertex AI adapters: the same wire, a different billing identity.

The mispricing this module exists to prevent, stated once: Vertex reports a bare
``gemini-3.5-flash`` — the *same string* the direct Gemini API reports, for which
the bundled catalog holds a real card. Nothing about the model id distinguishes a
Vertex call from a direct one, so any scheme that matched cards by model name
would price every Vertex call at Google's list rates and hand the operator a
number their invoice will not contain.

It is structurally impossible here: ``RateCard.matches`` compares the provider
first, and these classes fix ``_provider_id`` to ``"vertex"`` as a *class*
attribute (never a constructor argument a caller could set back to ``"google"``).
The catalog has no ``vertex`` card, so the engine takes its no-card path and
``managed_unpriced`` records why. See ``tests/test_managed_cloud.py`` for the
regression.
"""

from __future__ import annotations

import os
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._managed_billing import managed_unpriced, reject_unsupported_controls
from opentine.models.anthropic import Anthropic
from opentine.models.google import Google


def _project(project: str | None) -> str:
    return project or os.environ.get("GOOGLE_CLOUD_PROJECT", "")


def _location(location: str | None) -> str:
    return location or os.environ.get("GOOGLE_CLOUD_LOCATION") or "global"


class Vertex(Google):
    """Gemini on Vertex AI: the google-genai wire, priced as unknown.

    Usage extraction needs no new code — Vertex returns the same
    ``usageMetadata`` block, and the normalizer already reads both the snake_case
    and camelCase spellings of every field.
    """

    _provider_id = "vertex"

    def __init__(
        self,
        model: str = "gemini-3.5-flash",
        *,
        project: str | None = None,
        location: str | None = None,
        rates: dict[str, Any] | None = None,
        catalog: PricingCatalog | None = None,
        service_tier: str | None = None,
    ):
        self._project = _project(project)
        self._location = _location(location)
        super().__init__(model, api_key="", rates=rates, catalog=catalog, service_tier=service_tier)
        # Vertex authenticates with Application Default Credentials; a direct-API
        # key on a managed adapter would put the credential and the billing
        # identity in disagreement.
        self._api_key = ""

    def _get_client(self):
        try:
            from google import genai
        except ImportError:
            raise ImportError("pip install opentine[vertex]") from None
        return genai.Client(vertexai=True, project=self._project or None, location=self._location)

    def _meter(
        self,
        raw_usage: Any,
        reported_model: str | None = None,
        response_tier: str | None = None,
    ) -> dict[str, Any]:
        return managed_unpriced(
            super()._meter(raw_usage, reported_model, response_tier),
            provider=self._provider_id,
            region=self._location,
        )


class VertexAnthropic(Anthropic):
    """Anthropic models on Vertex AI: the Messages wire, priced as unknown."""

    _provider_id = "vertex"

    def __init__(
        self,
        model: str = "claude-sonnet-5@20260101",
        *,
        project: str | None = None,
        region: str | None = None,
        rates: dict[str, Any] | None = None,
        catalog: PricingCatalog | None = None,
        service_tier: str | None = None,
        inference_geo: str | None = None,
    ):
        reject_unsupported_controls(
            "Vertex Messages", service_tier=service_tier, inference_geo=inference_geo
        )
        self._project = project or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "")
        self._region = region or os.environ.get("CLOUD_ML_REGION") or _location(None)
        super().__init__(model, api_key="", rates=rates, catalog=catalog)
        self._api_key = ""

    def _get_client(self):
        try:
            from anthropic import AsyncAnthropicVertex
        except ImportError:
            raise ImportError("pip install opentine[vertex]") from None
        return AsyncAnthropicVertex(
            project_id=self._project or None, region=self._region, max_retries=0
        )

    def _meter(self, response: Any, *, early_refusal: bool = False) -> dict[str, Any]:
        return managed_unpriced(
            super()._meter(response, early_refusal=early_refusal),
            provider=self._provider_id,
            region=self._region,
        )
