"""Building the Anthropic SDK client and the Messages request.

Two SDK facts shape this module. Anthropic's Python SDK 1.0 (2026-08-20) removed
``temperature``/``top_p``/``top_k`` from ``messages.create`` -- a keyword the
method no longer declares raises ``TypeError`` before any request -- while the
Messages API itself still accepts ``temperature`` for the models that take it. So
sampling travels in ``extra_body`` on SDK >= 1 and as a keyword before it.

And credentials are resolved here, once, the way the SDK would resolve them
(``ANTHROPIC_API_KEY`` then ``ANTHROPIC_AUTH_TOKEN``), so the key checked against
the transport rule is exactly the key that is sent -- except for an explicit
``base_url`` naming a host other than Anthropic's. A compatible server (Ollama,
LM Studio, llama.cpp, vLLM, a gateway) never receives the ambient first-party
credentials: it gets an explicit ``api_key`` or ``ANTHROPIC_COMPAT_API_KEY``, and
the SDK is told both headers explicitly so it cannot read them from the
environment either, and every header ``ANTHROPIC_CUSTOM_HEADERS`` would add is
cancelled. ``ANTHROPIC_BASE_URL`` set in the environment is the operator's own
pairing of endpoint and key and keeps the SDK's behaviour, its custom headers held
to the same cleartext rule as a key.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

from opentine.models._endpoint_security import require_key_transport
from opentine.models._sdk_headers import ANTHROPIC, cancelled, require_transport


@lru_cache(maxsize=1)
def sdk_major() -> int:
    try:
        from importlib.metadata import version

        return int(version("anthropic").split(".", 1)[0])
    except Exception:  # noqa: BLE001 - absent or odd metadata: assume the old keyword API
        return 0


def sampling_kwargs(temperature: float) -> dict[str, Any]:
    if sdk_major() >= 1:
        return {"extra_body": {"temperature": temperature}}
    return {"temperature": temperature}


#: Sent to a compatible server that needs no key (an SDK refuses no credential).
PLACEHOLDER_KEY = "anthropic-compatible"


def third_party(base_url: str | None) -> bool:
    """Whether an explicit *base_url* names a host other than Anthropic's own."""
    if not base_url:
        return False
    host = (urlsplit(base_url.strip()).hostname or "").lower().rstrip(".")
    return not (host == "anthropic.com" or host.endswith(".anthropic.com"))


def credentials(api_key: str | None, base_url: str | None = None) -> tuple[str, str]:
    """``(api_key, auth_token)`` exactly as the SDK would send them.

    The SDK reads ``ANTHROPIC_AUTH_TOKEN`` even beside an explicit key and sends it
    as a bearer header, so it is resolved (and transport-checked) here too. A
    third-party *base_url* gets only an explicit key or ``ANTHROPIC_COMPAT_API_KEY``.
    """
    if third_party(base_url):
        return api_key or os.environ.get("ANTHROPIC_COMPAT_API_KEY", ""), ""
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    return key, os.environ.get("ANTHROPIC_AUTH_TOKEN", "")


def make_client(api_key: str, auth_token: str, base_url: str | None):
    try:
        import anthropic
    except ImportError:
        raise ImportError("pip install opentine[anthropic]") from None
    url = base_url or os.environ.get("ANTHROPIC_BASE_URL")
    require_key_transport(url, api_key)
    require_key_transport(url, auth_token)
    foreign = third_party(base_url)
    options: dict[str, Any] = {
        # Explicit values: an SDK given none reads the first-party variables.
        "api_key": (api_key or PLACEHOLDER_KEY) if foreign else (api_key or None),
        "auth_token": auth_token or None,
        "max_retries": 0,
        # httpx strips only ``Authorization`` on a cross-origin redirect, so a
        # followed redirect would hand ``x-api-key`` to the redirect target.
        "http_client": anthropic.DefaultAsyncHttpxClient(follow_redirects=False),
    }
    if base_url:
        options["base_url"] = base_url
    headers: dict[str, Any] = {}
    if foreign:
        # ANTHROPIC_CUSTOM_HEADERS carries gateway credentials for Anthropic or
        # the operator's ANTHROPIC_BASE_URL, never for a compatible server.
        headers.update(cancelled(ANTHROPIC, anthropic.Omit()))
    else:
        require_transport(ANTHROPIC, url)
    if foreign and not auth_token:
        # Older SDKs read ANTHROPIC_AUTH_TOKEN whenever auth_token is None.
        headers["Authorization"] = anthropic.Omit()
    if headers:
        options["default_headers"] = headers
    return anthropic.AsyncAnthropic(**options)


__all__ = ["credentials", "make_client", "sampling_kwargs", "sdk_major", "third_party"]
